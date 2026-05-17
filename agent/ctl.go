// agent/ctl.go
//
// Control CLI — the "P4Runtime analog" for the RRM engine.
//
// Subcommands:
//
//   rrm-agent ctl get-state              print all AP states from ap_state map
//   rrm-agent ctl get-thresholds         print current threshold config
//   rrm-agent ctl set-threshold          write new thresholds to ap_thresholds map
//     --util-high N   (default: 85)
//     --util-consec N (default: 3)
//     --noise-delta N (default: 10)
//   rrm-agent ctl inject-event           write a synthetic event to the event log
//     --ap-id N       (required)
//     --type [dfs|load|noise]
//
// The CLI operates by directly reading and writing BPF maps — the same maps
// the XDP data plane reads on every packet. Threshold changes take effect
// on the next packet processed by the XDP program (no restart required).
//
// This demonstrates the bidirectional control-plane / data-plane interface:
// the XDP program (data plane) reads thresholds; the CLI (control plane) writes
// them. Exactly the relationship the P4 article described.
//
// Note: the CLI shares the BPF map file descriptors with the running agent
// via BPFHandle. In a production deployment, these would be accessed via
// pinned maps in /sys/fs/bpf — Phase 4 would add that.

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
)

// runCTL dispatches CLI subcommands.
// Called when the first argument is "ctl".
func runCTL(h *BPFHandle, args []string) {
	if len(args) == 0 {
		printCTLHelp()
		os.Exit(1)
	}

	subcommand := args[0]
	rest := args[1:]

	switch subcommand {
	case "get-state":
		runGetState(h, rest)
	case "get-thresholds":
		runGetThresholds(h, rest)
	case "set-threshold":
		runSetThreshold(h, rest)
	case "inject-event":
		// inject-event is only meaningful when the full agent is running
		// (it prints to stdout for standalone CLI use)
		runInjectEvent(h, rest)
	case "help", "--help", "-h":
		printCTLHelp()
	default:
		fmt.Fprintf(os.Stderr, "[!] Unknown subcommand: %q\n\n", subcommand)
		printCTLHelp()
		os.Exit(1)
	}
}

// ── get-state ─────────────────────────────────────────────────────────────────

func runGetState(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("get-state", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: rrm-agent ctl get-state\n")
		fmt.Fprintf(os.Stderr, "  Prints current RF state for all APs from the ap_state BPF map.\n")
	}
	fs.Parse(args)

	// Collect all entries
	type entry struct {
		id   uint32
		info APInfo
	}
	var entries []entry

	var id uint32
	var info APInfo
	iter := h.APStateMap.Iterate()
	for iter.Next(&id, &info) {
		entries = append(entries, entry{id, info})
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Map iterate error: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("(ap_state map is empty — start traffic generator first)")
		return
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })

	fmt.Printf("%-6s %-4s %-6s %-8s %-10s %-8s %-8s\n",
		"AP_ID", "CH", "RAW%", "EWMA%", "NOISE_DBM", "CLIENTS", "CONSEC")
	fmt.Printf("%-6s %-4s %-6s %-8s %-10s %-8s %-8s\n",
		"──────", "────", "──────", "────────", "──────────", "────────", "────────")

	for _, e := range entries {
		fmt.Printf("%-6d %-4d %-6d %-8d %-10d %-8d %-8d\n",
			e.id,
			e.info.Channel,
			e.info.ChannelUtil,
			e.info.UtilEwmaQ8,
			e.info.NoiseFloorDbm,
			e.info.ClientCount,
			e.info.ConsecHigh,
		)
	}
	fmt.Printf("\n%d AP(s) in ap_state map\n", len(entries))
}

// ── get-thresholds ─────────────────────────────────────────────────────────────

func runGetThresholds(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("get-thresholds", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: rrm-agent ctl get-thresholds\n")
	}
	fs.Parse(args)

	thresh, err := ReadThresholds(h.ThreshMap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Current ap_thresholds map contents:")
	fmt.Printf("  util_high:   %d%%   (EWMA >= this → channel considered 'high')\n", thresh.UtilHigh)
	fmt.Printf("  util_consec: %d     (consecutive high intervals before LOAD_ANOMALY event)\n", thresh.UtilConsec)
	fmt.Printf("  noise_delta: %d dBm (single-interval noise floor rise → NOISE_SPIKE event)\n", thresh.NoiseDelta)

	if thresh.UtilHigh == 0 && thresh.UtilConsec == 0 && thresh.NoiseDelta == 0 {
		fmt.Println("\n  (all zeros — XDP program is using built-in defaults)")
		fmt.Println("  Start the agent with 'make run' to write thresholds.")
	}
}

// ── set-threshold ─────────────────────────────────────────────────────────────

func runSetThreshold(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("set-threshold", flag.ExitOnError)
	utilHigh := fs.Uint("util-high", 85, "EWMA threshold %")
	utilConsec := fs.Uint("util-consec", 3, "Consecutive high intervals")
	noiseDelta := fs.Uint("noise-delta", 10, "Noise floor delta dBm")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: rrm-agent ctl set-threshold [flags]\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	// Validate ranges
	if *utilHigh > 100 {
		fmt.Fprintln(os.Stderr, "[!] --util-high must be 0–100")
		os.Exit(1)
	}
	if *utilConsec == 0 || *utilConsec > 20 {
		fmt.Fprintln(os.Stderr, "[!] --util-consec must be 1–20")
		os.Exit(1)
	}
	if *noiseDelta > 50 {
		fmt.Fprintln(os.Stderr, "[!] --noise-delta must be 0–50")
		os.Exit(1)
	}

	thresh := Thresholds{
		UtilHigh:   uint8(*utilHigh),
		UtilConsec: uint8(*utilConsec),
		NoiseDelta: uint8(*noiseDelta),
		Pad:        0,
	}

	if err := WriteThresholds(h.ThreshMap, thresh); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Write failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Thresholds updated in ap_thresholds map:\n")
	fmt.Printf("    util_high=%d%% util_consec=%d noise_delta=%ddBm\n",
		thresh.UtilHigh, thresh.UtilConsec, thresh.NoiseDelta)
	fmt.Println("[*] Change takes effect on the next packet processed by XDP.")
	fmt.Println("[*] No restart required — this is the control-plane / data-plane boundary.")
}

// ── inject-event ───────────────────────────────────────────────────────────────

func runInjectEvent(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("inject-event", flag.ExitOnError)
	apID := fs.Uint("ap-id", 1, "Target AP identifier")
	eventType := fs.String("type", "dfs", "Event type: dfs | load | noise")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: rrm-agent ctl inject-event --ap-id N --type [dfs|load|noise]\n\n")
		fmt.Fprintf(os.Stderr, "  Injects a synthetic event into the agent's event log.\n")
		fmt.Fprintf(os.Stderr, "  Useful for testing the dashboard and metrics without real traffic.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	var evtType uint8
	switch *eventType {
	case "dfs":
		evtType = EventDFS
	case "load", "load_anomaly":
		evtType = EventLoadAnomaly
	case "noise", "noise_spike":
		evtType = EventNoiseSpike
	default:
		fmt.Fprintf(os.Stderr, "[!] Unknown event type: %q. Use: dfs | load | noise\n", *eventType)
		os.Exit(1)
	}

	// Look up the current AP state to get a realistic channel/util snapshot
	var info APInfo
	apID32 := uint32(*apID)
	if err := h.APStateMap.Lookup(apID32, &info); err != nil {
		// AP not seen yet — use placeholder values
		fmt.Printf("[!] AP%d not found in ap_state map. Using placeholder values.\n", *apID)
		if evtType == EventDFS {
			info.Channel = 52
		} else {
			info.Channel = 6
		}
		info.UtilEwmaQ8 = 50
		info.NoiseFloorDbm = -80
	}

	evt := RRMEvent{
		TimestampNs:   0, // synthetic — no kernel timestamp
		ApID:          apID32,
		EventType:     evtType,
		Channel:       info.Channel,
		UtilSnapshot:  info.UtilEwmaQ8,
		NoiseSnapshot: info.NoiseFloorDbm,
	}

	rec := EventRecord{
		ReceivedAt: time.Now(),
		KernelNs:   0,
		LatencyNs:  0,
		Synthetic:  true,
		Event:      evt,
	}

	// Print what would be injected (in standalone CLI mode, the agent store
	// is not accessible — print to stdout for verification)
	fmt.Printf("[+] Synthetic event prepared:\n")
	fmt.Printf("    AP:        %d\n", rec.Event.ApID)
	fmt.Printf("    Type:      %s\n", EventTypeName(rec.Event.EventType))
	fmt.Printf("    Channel:   %d\n", rec.Event.Channel)
	fmt.Printf("    EWMA%%:    %d\n", rec.Event.UtilSnapshot)
	fmt.Printf("    Noise:     %d dBm\n", rec.Event.NoiseSnapshot)
	fmt.Printf("    Synthetic: true\n")
	fmt.Println()
	fmt.Println("[*] Note: inject-event in standalone mode prints the event for inspection.")
	fmt.Println("[*] When running inside the full agent (future phase), it feeds the Store directly.")
	_ = rec // suppress unused warning in standalone mode
}

// printCTLHelp prints usage for the ctl subcommand.
func printCTLHelp() {
	fmt.Println(`Usage: rrm-agent ctl <subcommand> [flags]

Control plane interface for the RRM telemetry engine.
Reads and writes BPF maps directly — no agent restart required.

Subcommands:
  get-state              Print RF state for all APs from ap_state map
  get-thresholds         Print current threshold configuration
  set-threshold          Write new thresholds to ap_thresholds map
    --util-high   N      EWMA channel util threshold % (default 85)
    --util-consec N      Consecutive high intervals before event (default 3)
    --noise-delta N      Noise floor spike threshold dBm (default 10)
  inject-event           Prepare a synthetic event (test mode)
    --ap-id N            Target AP ID
    --type [dfs|load|noise]

Examples:
  sudo ./rrm-agent ctl get-state
  sudo ./rrm-agent ctl get-thresholds
  sudo ./rrm-agent ctl set-threshold --util-high 75 --util-consec 2
  sudo ./rrm-agent ctl inject-event --ap-id 3 --type dfs`)
}
