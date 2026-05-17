// agent/slowloop.go
//
// Slow-loop goroutine: polls the ap_state and ap_pkt_count BPF maps
// on a configurable interval and updates the Store's AP snapshots.
//
// This is the "controller polling cycle" analog — demonstrating the
// deliberate architectural difference from the fast-loop:
//   Fast-loop: event-driven, sub-millisecond reaction via ring buffer
//   Slow-loop: periodic, poll-based, interval-bounded visibility
//
// The contrast between these two loops is the central argument of the
// P4+RRM article. Both are observable in the TUI dashboard simultaneously.

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
)

// RunSlowLoop polls BPF maps and updates the Store at the given interval.
//
// Parameters:
//
//	apStateMap   — ap_state HASH map (key: ap_id, value: APInfo)
//	pktCountMap  — ap_pkt_count HASH map (key: ap_id, value: uint64)
//	store        — shared state store
//	metrics      — Prometheus metrics (nil disables metric export)
//	interval     — poll interval (default: 500ms)
//	stop         — close to stop the goroutine
func RunSlowLoop(
	apStateMap *ebpf.Map,
	pktCountMap *ebpf.Map,
	store *Store,
	metrics *Metrics,
	interval time.Duration,
	stop <-chan struct{},
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			pollMaps(apStateMap, pktCountMap, store, metrics)
		}
	}
}

// pollMaps performs one iteration: reads all ap_state and ap_pkt_count
// entries and updates the Store with fresh snapshots.
func pollMaps(
	apStateMap *ebpf.Map,
	pktCountMap *ebpf.Map,
	store *Store,
	metrics *Metrics,
) {
	now := time.Now()

	// Iterate over all ap_state entries.
	// ebpf.Map.Iterate() returns an iterator that calls the kernel
	// bpf_map_get_next_key + bpf_map_lookup_elem pair internally.
	var apID uint32
	var info APInfo

	iter := apStateMap.Iterate()
	for iter.Next(&apID, &info) {
		// Look up the packet count for this AP.
		var pktCount uint64
		if err := pktCountMap.Lookup(apID, &pktCount); err != nil {
			// AP may not yet have a packet count entry (race with init).
			pktCount = 0
		}

		snap := APSnapshot{
			APID:      apID,
			Info:      info,
			PktCount:  pktCount,
			UpdatedAt: now,
		}
		store.UpdateAPSnapshot(snap)

		// Push per-AP gauge metrics to Prometheus.
		if metrics != nil {
			metrics.UpdateAPGauges(snap)
		}
	}

	if err := iter.Err(); err != nil {
		log.Printf("[slow-loop] ap_state iterate error: %v", err)
	}
}
