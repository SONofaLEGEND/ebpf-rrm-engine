// agent/main.go — Phase 3: full agent entry point
//
// Goroutine architecture:
//
//   main()
//     ├── LoadBPF() — loads XDP program, writes thresholds, attaches to interface
//     ├── Metrics.StartMetricsServer() — Prometheus HTTP on :9090
//     ├── go RunFastLoop()   — ring buffer consumer (fast-loop)
//     ├── go RunSlowLoop()   — ap_state map poller (slow-loop)
//     ├── Dashboard.Run()    — tview TUI (blocks main goroutine)
//     └── cleanup on signal (SIGINT/SIGTERM) or 'q' keypress
//
// The dashboard is the primary user interface in Phase 3.
// For headless use (CI, SSH sessions without a TTY), run with --no-dashboard.
// The fast-loop still prints to stdout in headless mode.
//
// Control CLI mode: if first arg is "ctl", runs CLI subcommands instead.
//   sudo ./rrm-agent ctl get-state
//   sudo ./rrm-agent ctl set-threshold --util-high 75

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

// Config holds all agent configuration from CLI flags.
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
	// ── CLI dispatch: ctl subcommand ──────────────────────────────────────
	// Check for "ctl" before flag parsing so ctl flags don't conflict.
	if len(os.Args) > 1 && os.Args[1] == "ctl" {
		// Load BPF object to get map access, but don't attach XDP.
		// This allows the CLI to operate while the full agent is running.
		cfg := defaultConfig()
		h, err := LoadBPF(cfg)
		if err != nil {
			// If the agent isn't running (XDP not attached), still allow
			// get-thresholds / get-state by loading without attaching.
			// For simplicity in Phase 3, exit with a clear message.
			fmt.Fprintf(os.Stderr, "[!] Failed to access BPF maps: %v\n", err)
			fmt.Fprintf(os.Stderr, "[!] The full agent must be running first.\n")
			fmt.Fprintf(os.Stderr, "[!] Start it with: sudo make run\n")
			os.Exit(1)
		}
		defer h.Close()
		runCTL(h, os.Args[2:])
		return
	}

	// ── Flag parsing ──────────────────────────────────────────────────────
	utilHigh := flag.Uint("util-high", 85, "EWMA util threshold %")
	utilConsec := flag.Uint("util-consec", 3, "Consecutive high intervals before event")
	noiseDelta := flag.Uint("noise-delta", 10, "Noise floor delta dBm for spike")
	iface := flag.String("iface", "veth0", "Interface to attach XDP program")
	bpfObj := flag.String("bpf-obj", "kern/rrm_xdp.o", "Compiled BPF object path")
	pollMs := flag.Uint("poll-ms", 500, "ap_state poll interval ms")
	metricsAddr := flag.String("metrics", ":9090", "Prometheus metrics address")
	noDashboard := flag.Bool("no-dashboard", false, "Disable TUI (headless mode)")
	maxEvents := flag.Int("max-events", 200, "Max events to keep in memory")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "ebpf-rrm-engine — Near-RT RRM Agent v0.3")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage: sudo ./rrm-agent [flags]")
		fmt.Fprintln(os.Stderr, "       sudo ./rrm-agent ctl <subcommand>  (control CLI)")
		fmt.Fprintln(os.Stderr, "")
		flag.PrintDefaults()
	}
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

	// ── Banner ────────────────────────────────────────────────────────────
	if cfg.NoDashboard {
		printBanner(cfg)
	}

	// ── BPF setup ─────────────────────────────────────────────────────────
	log.Println("[*] Loading BPF collection and attaching XDP...")
	h, err := LoadBPF(cfg)
	if err != nil {
		log.Fatalf("[!] BPF setup failed: %v", err)
	}
	defer h.Close()
	log.Printf("[+] XDP attached to %s | thresholds: util_high=%d util_consec=%d noise_delta=%d",
		cfg.Iface, cfg.UtilHigh, cfg.UtilConsec, cfg.NoiseDelta)

	// ── Shared state store ────────────────────────────────────────────────
	store := NewStore(cfg.MaxEvents)

	// ── Prometheus metrics ─────────────────────────────────────────────────
	metrics := NewMetrics()
	metrics.StartMetricsServer(cfg.MetricsAddr)
	log.Printf("[+] Metrics: http://localhost%s/metrics", cfg.MetricsAddr)

	// ── Boot time for latency calculation ─────────────────────────────────
	bootTimeNs, err := GetBootTimeNs()
	if err != nil {
		log.Printf("[!] Could not read boot time (%v) — latency display will be 0", err)
		bootTimeNs = 0
	}

	// ── Fast-loop goroutine ────────────────────────────────────────────────
	fastLoopDone := make(chan struct{})
	go RunFastLoop(h.RingReader, store, metrics, bootTimeNs, fastLoopDone)
	log.Println("[+] Fast-loop goroutine started (ring buffer consumer)")

	// ── Slow-loop goroutine ────────────────────────────────────────────────
	slowLoopStop := make(chan struct{})
	go RunSlowLoop(
		h.APStateMap,
		h.PktCountMap,
		store,
		metrics,
		time.Duration(cfg.PollMs)*time.Millisecond,
		slowLoopStop,
	)
	log.Printf("[+] Slow-loop goroutine started (poll interval: %dms)", cfg.PollMs)

	// ── Signal handler ────────────────────────────────────────────────────
	// Runs in a goroutine alongside either the dashboard or the headless loop.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── Dashboard or headless ─────────────────────────────────────────────
	if !cfg.NoDashboard {
		// Dashboard mode: tview blocks the main goroutine.
		// Signal handler closes the dashboard from a separate goroutine.
		dash := NewDashboard(store)

		go func() {
			<-sigCh
			dash.Stop()
		}()

		log.Println("[+] Starting TUI dashboard (press 'q' to quit)...")
		if err := dash.Run(); err != nil {
			log.Printf("[!] Dashboard error: %v", err)
		}
	} else {
		// Headless mode: print events to stdout, wait for signal.
		log.Println("[*] Headless mode. Generator commands:")
		log.Println("[*]   sudo python3 gen/capwap_gen.py --mode normal")
		log.Println("[*]   sudo python3 gen/capwap_gen.py --mode dfs --target-ap 1")
		log.Println("[*]   sudo python3 gen/capwap_gen.py --mode spike --target-ap 2")
		log.Println("[*] Ctrl+C to stop")

		<-sigCh
	}

	// ── Cleanup ───────────────────────────────────────────────────────────
	log.Println("[*] Shutting down...")

	// Stop slow-loop goroutine
	close(slowLoopStop)

	// Stop fast-loop goroutine (by closing the ring buffer reader)
	// h.Close() calls rd.Close() which unblocks ringbuf.Reader.Read()
	h.Close()
	<-fastLoopDone

	// Shutdown Prometheus server
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	metrics.StopMetricsServer(ctx)

	// Print final summary
	printSummary(store)
}

// defaultConfig returns configuration with defaults (used by ctl subcommand).
func defaultConfig() *Config {
	return &Config{
		Iface:       "veth0",
		BPFObj:      "kern/rrm_xdp.o",
		UtilHigh:    85,
		UtilConsec:  3,
		NoiseDelta:  10,
		PollMs:      500,
		MetricsAddr: ":9090",
		MaxEvents:   200,
	}
}

func printBanner(cfg *Config) {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║     ebpf-rrm-engine — Near-RT RRM Agent v0.3            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Printf("[*] Interface:    %s\n", cfg.Iface)
	fmt.Printf("[*] BPF object:   %s\n", cfg.BPFObj)
	fmt.Printf("[*] Thresholds:   util_high=%d%% consec=%d noise_delta=%ddBm\n",
		cfg.UtilHigh, cfg.UtilConsec, cfg.NoiseDelta)
	fmt.Printf("[*] Metrics:      http://localhost%s/metrics\n", cfg.MetricsAddr)
	fmt.Printf("[*] Poll interval: %dms\n\n", cfg.PollMs)
}

func printSummary(store *Store) {
	counts := store.EventCounts()
	total := store.TotalEvents()
	avgUs := store.AvgLatencyUs()

	fmt.Println("\n── Final Summary ────────────────────────────────────────────")
	fmt.Printf("   APs observed:         %d\n", store.APCount())
	fmt.Printf("   Total events logged:  %d\n", total)
	fmt.Printf("   DFS events:           %d\n", counts[EventDFS])
	fmt.Printf("   Load anomaly events:  %d\n", counts[EventLoadAnomaly])
	fmt.Printf("   Noise spike events:   %d\n", counts[EventNoiseSpike])
	if total > 0 {
		fmt.Printf("   Avg kernel→agent latency: %.1fµs\n", avgUs)
		fmt.Printf("   Slow-loop comparison:     500,000µs (500ms poll)\n")
		fmt.Printf("   Speed advantage:          %.0fx faster\n", 500000.0/avgUs)
	}
	fmt.Println("[*] XDP program detached. Done.")
}
