// agent/main.go — Phase 2: Near-RT RRM Agent
//
// This binary owns the full BPF lifecycle:
//   1. Loads kern/rrm_xdp.o (compiled BPF object)
//   2. Writes configurable thresholds into ap_thresholds map
//   3. Attaches XDP program to the target interface
//   4. Reads classified events from the ring buffer (fast-loop goroutine)
//   5. Polls ap_state map every 500ms (slow-loop goroutine)
//   6. Prints classified events with latency measurements
//
// This is the "Near-RT RIC analog" from the P4+RRM article:
//   - Ring buffer goroutine = Near-RT RIC (100ms–1s reaction window)
//   - State poller goroutine = slow loop (periodic controller cycle analog)
//
// Run from the project root:
//   cd ~/ebpf-rrm-engine
//   go build -o rrm-agent ./agent/
//   sudo ./rrm-agent --iface veth0
//
// Requires: kernel 5.8+ (BPF_MAP_TYPE_RINGBUF)
//           Linux capabilities: CAP_BPF, CAP_NET_ADMIN (or run as root)

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ── Wire types ────────────────────────────────────────────────────────────────
// These structs must match the C definitions in kern/rrm_maps.h exactly.
// binary.Read uses the struct field order and sizes directly — no tags needed
// for NativeEndian on a homogeneous struct. We use LittleEndian explicitly
// since x86_64 and arm64 (Apple Silicon VMs) are both little-endian.

// RRMEvent matches struct rrm_event in kern/rrm_maps.h.
// Wire layout (16 bytes, little-endian):
//
//	Offset  Size  Field
//	0       8     TimestampNs
//	8       4     ApID
//	12      1     EventType
//	13      1     Channel
//	14      1     UtilSnapshot
//	15      1     NoiseSnapshot
type RRMEvent struct {
	TimestampNs   uint64
	ApID          uint32
	EventType     uint8
	Channel       uint8
	UtilSnapshot  uint8
	NoiseSnapshot int8
}

// APInfo matches struct ap_info in kern/rrm_maps.h.
// Wire layout (8 bytes):
//
//	Offset  Size  Field
//	0       1     Channel
//	1       1     ChannelUtil
//	2       1     NoiseFloorDbm (signed)
//	3       1     ClientCount
//	4       1     EventFlags
//	5       1     UtilEwmaQ8
//	6       1     NoisePrevDbm (signed)
//	7       1     ConsecHigh
type APInfo struct {
	Channel       uint8
	ChannelUtil   uint8
	NoiseFloorDbm int8
	ClientCount   uint8
	EventFlags    uint8
	UtilEwmaQ8    uint8
	NoisePrevDbm  int8
	ConsecHigh    uint8
}

// Thresholds matches struct thresholds in kern/rrm_maps.h.
// Wire layout (4 bytes):
type Thresholds struct {
	UtilHigh   uint8
	UtilConsec uint8
	NoiseDelta uint8
	Pad        uint8
}

// ── Event type constants (must match RRM_EVENT_* in kern/rrm_maps.h) ────────
const (
	EventDFS         = 0
	EventLoadAnomaly = 1
	EventNoiseSpike  = 2
)

var eventTypeNames = map[uint8]string{
	EventDFS:         "DFS      ",
	EventLoadAnomaly: "LOAD_ANOMALY",
	EventNoiseSpike:  "NOISE_SPIKE ",
}

// ── CLI flags ─────────────────────────────────────────────────────────────────
var (
	flagIface      = flag.String("iface", "veth0", "Interface to attach XDP program to")
	flagBPFObj     = flag.String("bpf-obj", "kern/rrm_xdp.o", "Path to compiled BPF object")
	flagUtilHigh   = flag.Uint("util-high", 85, "Channel utilisation threshold (%)")
	flagUtilConsec = flag.Uint("util-consec", 3, "Consecutive high-util intervals before event")
	flagNoiseDelta = flag.Uint("noise-delta", 10, "Noise floor delta (dBm) to trigger spike event")
	flagPollMs     = flag.Uint("poll-ms", 500, "ap_state poll interval (milliseconds)")
)

// ── Event log (shared between goroutines) ─────────────────────────────────────
type EventRecord struct {
	ReceivedAt time.Time
	KernelNs   uint64
	LatencyNs  int64 // time from kernel timestamp to userspace receipt
	Event      RRMEvent
}

var (
	eventLog   []EventRecord
	eventLogMu sync.Mutex
)

func recordEvent(evt RRMEvent, receivedAt time.Time, bootTimeNs uint64) {
	// Compute latency: difference between kernel timestamp and receipt.
	// bpf_ktime_get_ns() returns ns since boot. We record our own
	// boot-relative timestamp at agent start and use it for comparison.
	latency := int64(receivedAt.UnixNano()) - int64(bootTimeNs+evt.TimestampNs)

	rec := EventRecord{
		ReceivedAt: receivedAt,
		KernelNs:   evt.TimestampNs,
		LatencyNs:  latency,
		Event:      evt,
	}
	eventLogMu.Lock()
	eventLog = append(eventLog, rec)
	eventLogMu.Unlock()
}

// ── Fast-loop: ring buffer consumer ──────────────────────────────────────────
//
// Reads RRMEvent records from the BPF ring buffer as they are produced
// by the XDP program. Prints classified events with latency measurement.
//
// This goroutine is the Near-RT RIC analog:
//   - Reaction time: time from XDP event write to this print statement
//   - Target: sub-100ms (demonstrated in Phase 2 milestone check)
//   - Not gated by any polling cycle — woken by kernel immediately on data

func runRingBufferConsumer(rd *ringbuf.Reader, bootTimeNs uint64, done chan struct{}) {
	defer close(done)

	fmt.Println("[fast-loop] Ring buffer consumer started")
	fmt.Println("[fast-loop] Waiting for events from XDP program...\n")

	// Header for event output
	fmt.Printf("%-26s %-5s %-12s %-5s %-6s %-10s %s\n",
		"TIME", "AP", "EVENT", "CH", "EWMA%", "NOISE", "LATENCY")
	fmt.Printf("%-26s %-5s %-12s %-5s %-6s %-10s %s\n",
		"──────────────────────────", "─────", "────────────",
		"─────", "──────", "──────────", "───────────")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// rd.Close() was called — clean shutdown
				fmt.Println("\n[fast-loop] Ring buffer closed, stopping.")
				return
			}
			// Other errors: log and continue
			log.Printf("[fast-loop] Read error: %v", err)
			continue
		}

		receivedAt := time.Now()

		// Deserialise the raw bytes into RRMEvent.
		// binary.Read + LittleEndian matches the C struct layout on x86/arm64.
		// The struct has no padding (all fields naturally aligned), so this
		// is equivalent to a direct memcpy.
		var evt RRMEvent
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&evt,
		); err != nil {
			log.Printf("[fast-loop] Deserialise error: %v", err)
			continue
		}

		// Record event and compute latency
		recordEvent(evt, receivedAt, bootTimeNs)

		// Compute display latency (kernel timestamp → userspace receipt)
		// bootTimeNs is the system boot time in Unix nanoseconds.
		// evt.TimestampNs is nanoseconds since boot (from bpf_ktime_get_ns).
		kernelUnixNs := int64(bootTimeNs) + int64(evt.TimestampNs)
		latencyNs := receivedAt.UnixNano() - kernelUnixNs
		latencyUs := float64(latencyNs) / 1000.0

		typeName := eventTypeNames[evt.EventType]
		if typeName == "" {
			typeName = fmt.Sprintf("UNKNOWN(%d)", evt.EventType)
		}

		// ANSI colour codes for event type visibility
		colour := "\033[0m"
		switch evt.EventType {
		case EventDFS:
			colour = "\033[1;31m" // bold red
		case EventLoadAnomaly:
			colour = "\033[1;33m" // bold yellow
		case EventNoiseSpike:
			colour = "\033[1;36m" // bold cyan
		}
		reset := "\033[0m"

		fmt.Printf("%s%-26s %-5d %s%-12s%s %-5d %-6d %-10d %.1fµs%s\n",
			colour,
			receivedAt.Format("15:04:05.000000000"),
			evt.ApID,
			colour, typeName, reset,
			evt.Channel,
			evt.UtilSnapshot,
			evt.NoiseSnapshot,
			latencyUs,
			reset,
		)
	}
}

// ── Slow-loop: ap_state map poller ───────────────────────────────────────────
//
// Reads the full ap_state hash map every poll interval and prints a summary.
// This is the "slow loop" analog — the periodic controller polling cycle.
// Runs alongside the fast-loop consumer, demonstrating both loops coexisting.

func runStatePoller(apStateMap *ebpf.Map, interval time.Duration, stop chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fmt.Printf("\n[slow-loop] State poller started (interval: %v)\n", interval)

	for {
		select {
		case <-stop:
			fmt.Println("[slow-loop] Stopping.")
			return
		case <-ticker.C:
			printAPState(apStateMap)
		}
	}
}

func printAPState(apStateMap *ebpf.Map) {
	type apEntry struct {
		id   uint32
		info APInfo
	}

	var entries []apEntry

	// Iterate over all ap_state map entries
	var key uint32
	var info APInfo
	iter := apStateMap.Iterate()
	for iter.Next(&key, &info) {
		entries = append(entries, apEntry{key, info})
	}
	if err := iter.Err(); err != nil {
		log.Printf("[slow-loop] Map iterate error: %v", err)
		return
	}

	if len(entries) == 0 {
		fmt.Println("[slow-loop] ap_state: empty (no traffic received yet)")
		return
	}

	// Sort by AP ID for stable output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].id < entries[j].id
	})

	eventLogMu.Lock()
	totalEvents := len(eventLog)
	eventLogMu.Unlock()

	fmt.Printf("\n[slow-loop] %s | APs: %d | events logged: %d\n",
		time.Now().Format("15:04:05"), len(entries), totalEvents)
	fmt.Printf("  %-5s %-4s %-6s %-8s %-8s %-8s %-6s\n",
		"AP", "CH", "RAW%", "EWMA%", "NOISE", "CLIENTS", "CONSEC")
	fmt.Printf("  %-5s %-4s %-6s %-8s %-8s %-8s %-6s\n",
		"─────", "────", "──────", "────────", "────────", "───────", "──────")

	for _, e := range entries {
		fmt.Printf("  %-5d %-4d %-6d %-8d %-8d %-8d %-6d\n",
			e.id,
			e.info.Channel,
			e.info.ChannelUtil,
			e.info.UtilEwmaQ8,
			e.info.NoiseFloorDbm,
			e.info.ClientCount,
			e.info.ConsecHigh,
		)
	}
}

// ── Boot time helper ──────────────────────────────────────────────────────────
//
// bpf_ktime_get_ns() returns nanoseconds since system boot.
// To convert to Unix wall-clock time, we need the boot time in Unix ns.
// We get it from /proc/stat (btime field) converted to nanoseconds.

func getBootTimeNs() (uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, fmt.Errorf("read /proc/stat: %w", err)
	}
	var btime uint64
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("btime ")) {
			if _, err := fmt.Sscanf(string(line), "btime %d", &btime); err == nil {
				return btime * uint64(time.Second), nil
			}
		}
	}
	return 0, fmt.Errorf("btime not found in /proc/stat")
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║       ebpf-rrm-engine — Near-RT RRM Agent v0.2          ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Printf("[*] Interface:   %s\n", *flagIface)
	fmt.Printf("[*] BPF object:  %s\n", *flagBPFObj)
	fmt.Printf("[*] Thresholds:  util_high=%d%% consec=%d noise_delta=%ddBm\n",
		*flagUtilHigh, *flagUtilConsec, *flagNoiseDelta)
	fmt.Printf("[*] Poll interval: %dms\n\n", *flagPollMs)

	// ── Step 1: Remove RLIMIT_MEMLOCK ──────────────────────────────────────
	// Required on kernels < 5.11 to allow BPF map allocation.
	// On 5.11+ it's a no-op (memlock rlimit no longer applies to BPF).
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("[!] RemoveMemlock: %v", err)
	}

	// ── Step 2: Load BPF object ────────────────────────────────────────────
	// LoadCollectionSpec parses the .o file and returns a spec describing
	// all programs and maps without loading them into the kernel yet.
	spec, err := ebpf.LoadCollectionSpec(*flagBPFObj)
	if err != nil {
		log.Fatalf("[!] LoadCollectionSpec(%q): %v\n"+
			"    Make sure you ran 'make' first to compile kern/rrm_xdp.c",
			*flagBPFObj, err)
	}

	// NewCollection loads all programs and maps into the kernel.
	// The BPF verifier runs at this step — if it rejects the program,
	// the error message will tell you which instruction failed verification.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("[!] NewCollection: %v\n"+
			"    If this is a verifier error, check kern/rrm_xdp.c for\n"+
			"    unvalidated pointer dereferences or uninitialised stack values.",
			err)
	}
	defer coll.Close()
	fmt.Printf("[+] BPF collection loaded (%d programs, %d maps)\n",
		len(coll.Programs), len(coll.Maps))

	// ── Step 3: Write thresholds into ap_thresholds map ───────────────────
	// This is the "P4Runtime analogy": control plane writing config into
	// the data plane without recompiling the XDP program.
	thresh := Thresholds{
		UtilHigh:   uint8(*flagUtilHigh),
		UtilConsec: uint8(*flagUtilConsec),
		NoiseDelta: uint8(*flagNoiseDelta),
		Pad:        0,
	}
	threshMap, ok := coll.Maps["ap_thresholds"]
	if !ok {
		log.Fatal("[!] ap_thresholds map not found in BPF collection")
	}
	threshKey := uint32(0)
	if err := threshMap.Put(threshKey, thresh); err != nil {
		log.Fatalf("[!] threshMap.Put: %v", err)
	}
	fmt.Printf("[+] Thresholds written: util_high=%d util_consec=%d noise_delta=%d\n",
		thresh.UtilHigh, thresh.UtilConsec, thresh.NoiseDelta)

	// ── Step 4: Attach XDP program ─────────────────────────────────────────
	// link.AttachXDP creates a kernel "link" object that persists until
	// l.Close() is called or the process exits (link is tied to the fd).
	// XDPGenericMode works in all VM environments regardless of NIC driver.
	iface, err := net.InterfaceByName(*flagIface)
	if err != nil {
		log.Fatalf("[!] InterfaceByName(%q): %v\n"+
			"    Check that the interface exists: ip link show %s",
			*flagIface, err, *flagIface)
	}

	prog, ok := coll.Programs["rrm_xdp_parser"]
	if !ok {
		log.Fatal("[!] rrm_xdp_parser program not found in BPF collection")
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("[!] AttachXDP: %v\n"+
			"    If 'device or resource busy': another XDP program may be attached.\n"+
			"    Remove it: sudo ip link set dev %s xdpgeneric off",
			err, *flagIface)
	}
	defer l.Close()
	fmt.Printf("[+] XDP program attached to %s (generic mode)\n", *flagIface)

	// ── Step 5: Open ring buffer reader ───────────────────────────────────
	eventsMap, ok := coll.Maps["rrm_events"]
	if !ok {
		log.Fatal("[!] rrm_events map not found in BPF collection")
	}
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("[!] ringbuf.NewReader: %v\n"+
			"    Requires kernel 5.8+ for BPF_MAP_TYPE_RINGBUF.", err)
	}
	defer rd.Close()
	fmt.Printf("[+] Ring buffer reader opened\n")

	// ── Step 6: Get boot time for latency calculation ──────────────────────
	bootTimeNs, err := getBootTimeNs()
	if err != nil {
		log.Printf("[!] Could not read boot time: %v (latency display will be approximate)", err)
		bootTimeNs = 0
	}

	// ── Step 7: Start goroutines ───────────────────────────────────────────
	stopPoller := make(chan struct{})
	rbDone := make(chan struct{})

	// Fast-loop: ring buffer consumer
	go runRingBufferConsumer(rd, bootTimeNs, rbDone)

	// Slow-loop: ap_state map poller
	apStateMap, ok := coll.Maps["ap_state"]
	if !ok {
		log.Fatal("[!] ap_state map not found in BPF collection")
	}
	go runStatePoller(apStateMap, time.Duration(*flagPollMs)*time.Millisecond, stopPoller)

	fmt.Printf("\n[*] Agent running. Start traffic generator:\n")
	fmt.Printf("[*]   sudo python3 gen/capwap_gen.py --mode normal\n")
	fmt.Printf("[*]   sudo python3 gen/capwap_gen.py --mode dfs --target-ap 1\n")
	fmt.Printf("[*]   sudo python3 gen/capwap_gen.py --mode spike --target-ap 2\n")
	fmt.Printf("[*] Ctrl+C to stop\n\n")

	// ── Step 8: Wait for signal ────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n[*] Shutting down...")

	// Stop the ring buffer reader (unblocks runRingBufferConsumer)
	rd.Close()
	<-rbDone

	// Stop the state poller
	close(stopPoller)

	// Print final event summary
	eventLogMu.Lock()
	total := len(eventLog)
	eventLogMu.Unlock()

	fmt.Printf("\n── Final Summary ─────────────────────────────────────────────\n")
	fmt.Printf("   Total events logged: %d\n", total)

	if total > 0 {
		eventLogMu.Lock()
		var dfsCount, loadCount, noiseCount int
		var totalLatencyNs int64
		for _, rec := range eventLog {
			switch rec.Event.EventType {
			case EventDFS:
				dfsCount++
			case EventLoadAnomaly:
				loadCount++
			case EventNoiseSpike:
				noiseCount++
			}
			if rec.LatencyNs > 0 {
				totalLatencyNs += rec.LatencyNs
			}
		}
		eventLogMu.Unlock()

		avgLatencyUs := float64(totalLatencyNs) / float64(total) / 1000.0
		fmt.Printf("   DFS events:          %d\n", dfsCount)
		fmt.Printf("   Load anomaly events: %d\n", loadCount)
		fmt.Printf("   Noise spike events:  %d\n", noiseCount)
		fmt.Printf("   Avg kernel→agent latency: %.1fµs\n", avgLatencyUs)
	}

	fmt.Println("[*] Done. XDP program detached.")
}
