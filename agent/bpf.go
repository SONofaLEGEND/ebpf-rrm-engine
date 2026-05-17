// agent/bpf.go
//
// BPF lifecycle: types, loading, map access, XDP attach/detach.
// All other agent files import types from here.
// Separating BPF concerns from application logic keeps both testable.

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ── Wire types ────────────────────────────────────────────────────────────────
// Must match C structs in kern/rrm_maps.h exactly.
// All fields are sized to match the C layout; no struct tags needed for
// binary.Read with LittleEndian on x86_64 / arm64.

// RRMEvent matches struct rrm_event (16 bytes, no padding).
type RRMEvent struct {
	TimestampNs   uint64 // bpf_ktime_get_ns() — ns since boot
	ApID          uint32
	EventType     uint8
	Channel       uint8
	UtilSnapshot  uint8 // util_ewma_q8 at event time
	NoiseSnapshot int8  // noise_floor_dbm at event time (signed)
}

// APInfo matches struct ap_info (8 bytes, no padding).
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

// Thresholds matches struct thresholds (4 bytes).
type Thresholds struct {
	UtilHigh   uint8
	UtilConsec uint8
	NoiseDelta uint8
	Pad        uint8
}

// Event type constants — must match RRM_EVENT_* in kern/rrm_maps.h.
const (
	EventDFS         uint8 = 0
	EventLoadAnomaly uint8 = 1
	EventNoiseSpike  uint8 = 2
)

// EventTypeName returns a fixed-width display name for an event type.
func EventTypeName(t uint8) string {
	switch t {
	case EventDFS:
		return "DFS"
	case EventLoadAnomaly:
		return "LOAD_ANOMALY"
	case EventNoiseSpike:
		return "NOISE_SPIKE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// EventTypeColour returns an ANSI colour code for terminal output.
func EventTypeColour(t uint8) string {
	switch t {
	case EventDFS:
		return "\033[1;31m" // bold red
	case EventLoadAnomaly:
		return "\033[1;33m" // bold yellow
	case EventNoiseSpike:
		return "\033[1;36m" // bold cyan
	default:
		return "\033[0m"
	}
}

// ── BPFHandle — owns all kernel-side BPF resources ───────────────────────────

// BPFHandle holds the loaded BPF collection, XDP link, and ring buffer reader.
// Call Close() to cleanly detach XDP and release all kernel resources.
type BPFHandle struct {
	Collection *ebpf.Collection
	XDPLink    link.Link
	RingReader *ringbuf.Reader

	// Direct map references (convenience wrappers around Collection.Maps)
	PktCountMap *ebpf.Map
	APStateMap  *ebpf.Map
	ThreshMap   *ebpf.Map
	EventsMap   *ebpf.Map
}

// Close releases all kernel BPF resources in the correct order:
// 1. Ring buffer reader (stops the consumer goroutine's rd.Read() call)
// 2. XDP link (detaches the program from the interface)
// 3. Collection (releases programs and maps)
func (h *BPFHandle) Close() {
	if h.RingReader != nil {
		h.RingReader.Close()
	}
	if h.XDPLink != nil {
		h.XDPLink.Close()
	}
	if h.Collection != nil {
		h.Collection.Close()
	}
}

// LoadBPF loads the BPF object, writes thresholds, attaches XDP,
// and opens the ring buffer reader. Returns a BPFHandle on success.
//
// This is the "control plane setup" step — analogous to programming
// a P4 switch before forwarding begins.
func LoadBPF(cfg *Config) (*BPFHandle, error) {
	// Remove RLIMIT_MEMLOCK restriction (required on kernels < 5.11).
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("RemoveMemlock: %w", err)
	}

	// Parse the BPF object file (does not load into kernel yet).
	spec, err := ebpf.LoadCollectionSpec(cfg.BPFObj)
	if err != nil {
		return nil, fmt.Errorf("LoadCollectionSpec(%q): %w\n"+
			"  Run 'make' to compile kern/rrm_xdp.c first", cfg.BPFObj, err)
	}

	// Load all programs and maps into the kernel.
	// The BPF verifier runs at this point.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("NewCollection: %w\n"+
			"  Verifier rejection — check kern/rrm_xdp.c for unvalidated pointers", err)
	}

	h := &BPFHandle{Collection: coll}

	// Resolve named maps.
	mapNames := map[string]**ebpf.Map{
		"ap_pkt_count":  &h.PktCountMap,
		"ap_state":      &h.APStateMap,
		"ap_thresholds": &h.ThreshMap,
		"rrm_events":    &h.EventsMap,
	}
	for name, ptr := range mapNames {
		m, ok := coll.Maps[name]
		if !ok {
			h.Close()
			return nil, fmt.Errorf("map %q not found in BPF collection", name)
		}
		*ptr = m
	}

	// Write thresholds — P4Runtime analogy.
	// The XDP program reads key=0 from ap_thresholds on every packet.
	thresh := Thresholds{
		UtilHigh:   cfg.UtilHigh,
		UtilConsec: cfg.UtilConsec,
		NoiseDelta: cfg.NoiseDelta,
		Pad:        0,
	}
	threshKey := uint32(0)
	if err := h.ThreshMap.Put(threshKey, thresh); err != nil {
		h.Close()
		return nil, fmt.Errorf("write thresholds: %w", err)
	}

	// Resolve the interface.
	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("InterfaceByName(%q): %w", cfg.Iface, err)
	}

	// Attach XDP in generic mode (works in all VM environments).
	prog, ok := coll.Programs["rrm_xdp_parser"]
	if !ok {
		h.Close()
		return nil, fmt.Errorf("program rrm_xdp_parser not found in BPF collection")
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("AttachXDP on %s: %w\n"+
			"  If 'device or resource busy': sudo ip link set dev %s xdpgeneric off",
			cfg.Iface, err, cfg.Iface)
	}
	h.XDPLink = l

	// Open ring buffer reader.
	rd, err := ringbuf.NewReader(h.EventsMap)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("ringbuf.NewReader: %w\n"+
			"  Requires kernel 5.8+ for BPF_MAP_TYPE_RINGBUF", err)
	}
	h.RingReader = rd

	return h, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// GetBootTimeNs reads the system boot time from /proc/stat as Unix nanoseconds.
// Used to convert bpf_ktime_get_ns() (ns since boot) to wall-clock time.
func GetBootTimeNs() (uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, fmt.Errorf("read /proc/stat: %w", err)
	}
	var btime uint64
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("btime ")) {
			if _, err := fmt.Sscanf(string(line), "btime %d", &btime); err == nil {
				return btime * 1e9, nil
			}
		}
	}
	return 0, fmt.Errorf("btime field not found in /proc/stat")
}

// WriteThresholds updates the ap_thresholds map at runtime.
// Called by the control CLI to push new thresholds without restarting.
func WriteThresholds(m *ebpf.Map, t Thresholds) error {
	key := uint32(0)
	return m.Put(key, t)
}

// ReadThresholds reads the current threshold configuration from the map.
func ReadThresholds(m *ebpf.Map) (Thresholds, error) {
	var t Thresholds
	key := uint32(0)
	if err := m.Lookup(key, &t); err != nil {
		return t, fmt.Errorf("lookup ap_thresholds: %w", err)
	}
	return t, nil
}
