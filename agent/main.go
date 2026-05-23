// Package main implements the Near-RT RRM Go Agent.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Config struct {
	Iface       string
	BPFObj      string
	UtilHigh    uint8
	UtilConsec  uint8
	NoiseDelta  uint8
	PollMs      uint
	MetricsAddr string
	NoDashboard bool
	MaxEvents   int
}

func main() {
	// ── CLI dispatch ──────────────────────────────────────────────────────
	if len(os.Args) > 1 && os.Args[1] == "ctl" {
		runCTL(os.Args[2:])
		return
	}

	// ── Flags ─────────────────────────────────────────────────────────────
	utilHigh := flag.Uint("util-high", 85, "EWMA util threshold %")
	utilConsec := flag.Uint("util-consec", 3, "Consecutive high intervals before event")
	noiseDelta := flag.Uint("noise-delta", 10, "Noise floor delta dBm for spike")
	iface := flag.String("iface", "veth0", "Interface for XDP attach")
	bpfObj := flag.String("bpf-obj", "kern/rrm_xdp.o", "Compiled BPF object")
	pollMs := flag.Uint("poll-ms", 500, "ap_state poll interval ms")
	metricsAddr := flag.String("metrics", ":9090", "Prometheus listen addr")
	noDashboard := flag.Bool("no-dashboard", false, "Headless mode (no TUI)")
	maxEvents := flag.Int("max-events", 200, "Max events kept in memory")
	flag.Parse()

	cfg := &Config{
		Iface:       *iface,
		BPFObj:      *bpfObj,
		UtilHigh:    uint8(*utilHigh),
		UtilConsec:  uint8(*utilConsec),
		NoiseDelta:  uint8(*noiseDelta),
		PollMs:      *pollMs,
		MetricsAddr: *metricsAddr,
		NoDashboard: *noDashboard,
		MaxEvents:   *maxEvents,
	}

	if cfg.NoDashboard {
		printBanner(cfg)
	}

	// ── BPF setup ─────────────────────────────────────────────────────────
	log.Println("[*] Loading BPF + attaching XDP...")
	h, err := LoadBPF(cfg)
	if err != nil {
		log.Fatalf("[!] %v", err)
	}
	defer func() {
		h.Close()
		UnpinMaps()
		log.Println("[*] Maps unpinned. XDP detached.")
	}()
	log.Printf("[+] XDP attached to %s | thresholds util_high=%d consec=%d noise=%d",
		cfg.Iface, cfg.UtilHigh, cfg.UtilConsec, cfg.NoiseDelta)
	log.Printf("[+] Maps pinned to %s/", BPFPinDir)

	// ── Shared state ──────────────────────────────────────────────────────
	store := NewStore(cfg.MaxEvents)

	// ── Prometheus ────────────────────────────────────────────────────────
	metrics := NewMetrics()
	metrics.StartMetricsServer(cfg.MetricsAddr)
	log.Printf("[+] Metrics: http://localhost%s/metrics", cfg.MetricsAddr)

	// ── Boot time ─────────────────────────────────────────────────────────
	bootTimeNs, err := GetBootTimeNs()
	if err != nil {
		log.Printf("[!] boot time unavailable (%v) — latency display will be 0", err)
	}

	// Fast loop: ring buffer consumer
	fastDone := make(chan struct{})
	go RunFastLoop(h.RingReader, store, metrics, bootTimeNs, fastDone)
	log.Println("[+] Fast-loop started")

	// Slow loop: map polling and stats synchronization
	slowStop := make(chan struct{})
	go RunSlowLoop(h.APStateMap, h.PktCountMap, h.StatsMap, store, metrics,
		time.Duration(cfg.PollMs)*time.Millisecond, slowStop)
	log.Printf("[+] Slow-loop started (%dms interval)", cfg.PollMs)

	// ── Signal ────────────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── UI ────────────────────────────────────────────────────────────────
	if !cfg.NoDashboard {
		dash := NewDashboard(store)
		go func() { <-sigCh; dash.Stop() }()
		log.Println("[+] TUI dashboard starting (press 'q' to quit)")
		if err := dash.Run(); err != nil {
			log.Printf("[!] Dashboard error: %v", err)
		}
	} else {
		log.Println("[*] Headless — Ctrl+C to stop")
		log.Printf("[*]   sudo python3 gen/capwap_gen.py --mode normal")
		log.Printf("[*]   sudo python3 gen/capwap_gen.py --mode dfs --target-ap 1")
		log.Printf("[*]   sudo python3 gen/capwap_gen.py --mode spike --target-ap 2")
		<-sigCh
	}

	// ── Shutdown ──────────────────────────────────────────────────────────
	log.Println("[*] Shutting down...")
	close(slowStop)
	h.RingReader.Close()
	<-fastDone

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics.StopMetricsServer(ctx)

	printSummary(store, h)
}

func printBanner(cfg *Config) {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║              ebpf-rrm-engine — RRM Agent                 ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Printf("[*] Interface:    %s\n", cfg.Iface)
	fmt.Printf("[*] BPF object:   %s\n", cfg.BPFObj)
	fmt.Printf("[*] Thresholds:   util_high=%d%% consec=%d noise_delta=%ddBm\n",
		cfg.UtilHigh, cfg.UtilConsec, cfg.NoiseDelta)
	fmt.Printf("[*] Metrics:      http://localhost%s/metrics\n", cfg.MetricsAddr)
	fmt.Printf("[*] BPF pin dir:  %s/\n\n", BPFPinDir)
}

func printSummary(store *Store, h *BPFHandle) {
	counts := store.EventCounts()
	total := store.TotalEvents()
	avgUs := store.AvgLatencyUs()

	drops, _ := ReadDropCount(h.StatsMap)
	invalid, _ := ReadInvalidRFCount(h.StatsMap)

	fmt.Println("\n── Final Summary ────────────────────────────────────────────")
	fmt.Printf("   APs observed:            %d\n", store.APCount())
	fmt.Printf("   Total events logged:     %d\n", total)
	fmt.Printf("   DFS events:              %d\n", counts[EventDFS])
	fmt.Printf("   Load anomaly events:     %d\n", counts[EventLoadAnomaly])
	fmt.Printf("   Noise spike events:      %d\n", counts[EventNoiseSpike])
	fmt.Printf("   Regulatory violation evts: %d\n", counts[EventRegViolation])
	fmt.Printf("   Ring buffer drops:       %d\n", drops)
	fmt.Printf("   Invalid RF packets:      %d\n", invalid)
	if total > 0 && avgUs > 0 {
		fmt.Printf("   Avg fast-loop latency:   %.1fµs\n", avgUs)
	}
}
