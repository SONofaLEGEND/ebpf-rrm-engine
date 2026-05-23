// Package main implements the Go Agent.
//
// ctl.go implements the CLI client for interacting with pinned BPF maps.

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
)

func runCTL(args []string) {
	if len(args) == 0 {
		printCTLHelp()
		os.Exit(1)
	}

	// Open maps from BPF filesystem — no BPF object load needed
	h, err := OpenPinnedMaps()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	// Note: h.Close() closes the map file descriptors but does NOT unpin them.
	// Pinned maps persist until UnpinMaps() is called or the system reboots.
	defer h.Close()

	switch args[0] {
	case "get-state":
		cmdGetState(h, args[1:])
	case "get-thresholds":
		cmdGetThresholds(h, args[1:])
	case "set-threshold":
		cmdSetThreshold(h, args[1:])
	case "get-stats":
		cmdGetStats(h, args[1:])
	case "inject-event":
		cmdInjectEvent(h, args[1:])
	case "help", "--help", "-h":
		printCTLHelp()
	default:
		fmt.Fprintf(os.Stderr, "[!] Unknown subcommand: %q\n\n", args[0])
		printCTLHelp()
		os.Exit(1)
	}
}

func cmdGetState(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("get-state", flag.ExitOnError)
	fs.Parse(args)

	type entry struct {
		id   uint32
		info APInfo
		pkts uint64
	}
	var entries []entry

	var id uint32
	var info APInfo
	iter := h.APStateMap.Iterate()
	for iter.Next(&id, &info) {
		var pkts uint64
		_ = h.PktCountMap.Lookup(id, &pkts)
		entries = append(entries, entry{id, info, pkts})
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Iterate error: %v\n", err)
		os.Exit(1)
	}
	if len(entries) == 0 {
		fmt.Println("(ap_state is empty — start the traffic generator)")
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })

	fmt.Printf("%-6s %-4s %-6s %-8s %-10s %-8s %-6s %-8s\n",
		"AP", "CH", "RAW%", "EWMA%", "NOISE_DBM", "CLIENTS", "CONSEC", "PKTS")
	fmt.Printf("%-6s %-4s %-6s %-8s %-10s %-8s %-6s %-8s\n",
		"──────", "────", "──────", "────────", "──────────", "────────", "──────", "────────")
	for _, e := range entries {
		fmt.Printf("%-6d %-4d %-6d %-8d %-10d %-8d %-6d %-8d\n",
			e.id, e.info.Channel, e.info.ChannelUtil,
			e.info.UtilEwmaQ8, e.info.NoiseFloorDbm,
			e.info.ClientCount, e.info.ConsecHigh, e.pkts)
	}
	fmt.Printf("\n%d AP(s)\n", len(entries))
}

func cmdGetThresholds(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("get-thresholds", flag.ExitOnError)
	fs.Parse(args)

	t, err := ReadThresholds(h.ThreshMap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("util_high:   %d%%\n", t.UtilHigh)
	fmt.Printf("util_consec: %d intervals\n", t.UtilConsec)
	fmt.Printf("noise_delta: %d dBm\n", t.NoiseDelta)
	if t.UtilHigh == 0 {
		fmt.Println("\n(all zeros — XDP program using built-in defaults)")
	}
}

func cmdSetThreshold(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("set-threshold", flag.ExitOnError)
	utilHigh := fs.Uint("util-high", 85, "Util EWMA threshold %")
	utilConsec := fs.Uint("util-consec", 3, "Consecutive high intervals")
	noiseDelta := fs.Uint("noise-delta", 10, "Noise floor delta dBm")
	fs.Parse(args)

	if *utilHigh > 100 {
		fmt.Fprintln(os.Stderr, "[!] --util-high must be 0–100")
		os.Exit(1)
	}
	t := Thresholds{
		UtilHigh:   uint8(*utilHigh),
		UtilConsec: uint8(*utilConsec),
		NoiseDelta: uint8(*noiseDelta),
	}
	if err := WriteThresholds(h.ThreshMap, t); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Thresholds updated: util_high=%d%% util_consec=%d noise_delta=%ddBm\n",
		t.UtilHigh, t.UtilConsec, t.NoiseDelta)
	fmt.Println("[*] Effective on next XDP packet — no restart required.")
}

func cmdGetStats(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("get-stats", flag.ExitOnError)
	fs.Parse(args)

	drops, err := ReadDropCount(h.StatsMap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] read stats: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ring_buffer_drops: %d\n", drops)
	if drops > 0 {
		fmt.Println("[!] WARNING: events were dropped — ring buffer full.")
		fmt.Println("[!] Increase rrm_events max_entries in kern/rrm_maps.h")
		fmt.Println("[!] or reduce the event rate.")
	} else {
		fmt.Println("[+] No ring buffer drops — fast-loop consumer keeping up.")
	}
}

func cmdInjectEvent(h *BPFHandle, args []string) {
	fs := flag.NewFlagSet("inject-event", flag.ExitOnError)
	apID := fs.Uint("ap-id", 1, "Target AP ID")
	eventType := fs.String("type", "dfs", "Event type: dfs|load|noise")
	fs.Parse(args)

	var evtType uint8
	switch *eventType {
	case "dfs":
		evtType = EventDFS
	case "load":
		evtType = EventLoadAnomaly
	case "noise":
		evtType = EventNoiseSpike
	default:
		fmt.Fprintf(os.Stderr, "[!] Unknown type %q — use: dfs|load|noise\n", *eventType)
		os.Exit(1)
	}

	var info APInfo
	if err := h.APStateMap.Lookup(uint32(*apID), &info); err != nil {
		fmt.Printf("[!] AP%d not in ap_state map — using placeholder values\n", *apID)
		if evtType == EventDFS {
			info.Channel = 52
		} else {
			info.Channel = 6
		}
		info.UtilEwmaQ8 = 50
		info.NoiseFloorDbm = -80
	}

	fmt.Printf("[+] Synthetic event:\n")
	fmt.Printf("    AP:%d  type:%s  ch:%d  util:%d%%  noise:%ddBm\n",
		*apID, EventTypeName(evtType), info.Channel, info.UtilEwmaQ8, info.NoiseFloorDbm)
	fmt.Println("[*] Note: inject-event writes metadata only — actual ring buffer")
	fmt.Println("[*] injection requires running the DFS/spike generator modes.")
}

func printCTLHelp() {
	fmt.Print(`Usage: sudo ./rrm-agent ctl <subcommand> [flags]

Reads/writes BPF maps via /sys/fs/bpf/rrm/ (agent must be running).

Subcommands:
  get-state              Print all AP RF states
  get-thresholds         Print current threshold config
  set-threshold          Update thresholds live (no restart)
    --util-high N        EWMA util threshold % (default 85)
    --util-consec N      Consecutive high intervals (default 3)
    --noise-delta N      Noise floor spike dBm (default 10)
  get-stats              Print ring buffer drop counter
  inject-event           Show synthetic event details
    --ap-id N            Target AP
    --type [dfs|load|noise]

Examples:
  sudo ./rrm-agent ctl get-state
  sudo ./rrm-agent ctl set-threshold --util-high 70 --util-consec 2
  sudo ./rrm-agent ctl get-stats
`)
}
