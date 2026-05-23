// Package main implements the Go Agent.
//
// agent/slowloop.go runs the goroutine that periodically polls the eBPF maps
// to snapshot AP telemetry and check for regulatory compliance.

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
//	statsMap     — global stats ARRAY map
//	store        — shared state store
//	metrics      — Prometheus metrics (nil disables metric export)
//	interval     — poll interval
//	stop         — close to stop the goroutine
func RunSlowLoop(
	apStateMap *ebpf.Map,
	pktCountMap *ebpf.Map,
	statsMap *ebpf.Map,
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
			pollMaps(apStateMap, pktCountMap, statsMap, store, metrics)
		}
	}
}

// pollMaps performs one iteration: reads all ap_state and ap_pkt_count
// entries and updates the Store with fresh snapshots.
func pollMaps(
	apStateMap *ebpf.Map,
	pktCountMap *ebpf.Map,
	statsMap *ebpf.Map,
	store *Store,
	metrics *Metrics,
) {
	now := time.Now()

	// Iterate over all ap_state entries.
	var apID uint32
	var info APInfo

	iter := apStateMap.Iterate()
	for iter.Next(&apID, &info) {
		// Look up the packet count for this AP.
		var pktCount uint64
		if err := pktCountMap.Lookup(apID, &pktCount); err != nil {
			pktCount = 0
		}

		snap := APSnapshot{
			APID:      apID,
			Info:      info,
			PktCount:  pktCount,
			UpdatedAt: now,
		}
		store.UpdateAPSnapshot(snap)

		// Check for DFS regulatory compliance violations
		if store.IsChannelInNOP(info.Channel) {
			store.IncrementViolations()
			log.Printf("[slow-loop] [REGULATORY VIOLATION] AP %d is active on DFS channel %d during active NOP!", apID, info.Channel)
			if metrics != nil {
				metrics.IncRegulatoryViolations()
			}
		}

		// Push per-AP gauge metrics to Prometheus.
		if metrics != nil {
			metrics.UpdateAPGauges(snap)
		}
	}

	if err := iter.Err(); err != nil {
		log.Printf("[slow-loop] ap_state iterate error: %v", err)
	}

	if metrics != nil && statsMap != nil {
		metrics.UpdateGlobalStats(statsMap)
	}
}
