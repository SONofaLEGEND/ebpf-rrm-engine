// Package main implements the Go Agent.
//
// agent/fastloop.go runs the goroutine that consumes events from the eBPF ring buffer
// and stores them in the state store.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// RunFastLoop is the ring buffer consumer goroutine.
//
// Parameters:
//
//	rd         — ring buffer reader (closed by main() on shutdown)
//	store      — shared state store (AddEvent is thread-safe)
//	metrics    — Prometheus metrics (ObserveEvent is thread-safe)
//	bootTimeNs — system boot time in Unix ns for latency calculation
//	done       — closed when the goroutine exits (signals main())
func RunFastLoop(
	rd *ringbuf.Reader,
	store *Store,
	metrics *Metrics,
	bootTimeNs uint64,
	done chan<- struct{},
) {
	defer close(done)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// rd.Close() called — clean shutdown path
				return
			}
			// Transient error — log and continue
			log.Printf("[fast-loop] Read error: %v", err)
			continue
		}

		receivedAt := time.Now()

		// Deserialise the 16-byte ring buffer record into RRMEvent.
		// binary.Read + LittleEndian matches the C struct layout on both
		// x86_64 and arm64 (both little-endian).
		// struct rrm_event has no internal padding — direct cast is safe.
		var evt RRMEvent
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&evt,
		); err != nil {
			log.Printf("[fast-loop] Deserialise error (got %d bytes, want 16): %v",
				len(record.RawSample), err)
			continue
		}

		// Compute kernel → userspace latency using CLOCK_MONOTONIC to avoid
		// coarse btime (procfs) drift/integer seconds errors.
		latencyNs := int64(GetMonotonicTimeNs()) - int64(evt.TimestampNs)
		if latencyNs < 0 {
			latencyNs = 0 // Safeguard against tiny timing anomalies
		}

		rec := EventRecord{
			ReceivedAt: receivedAt,
			KernelNs:   evt.TimestampNs,
			LatencyNs:  latencyNs,
			Synthetic:  false,
			Event:      evt,
		}

		// Update shared state (thread-safe)
		store.AddEvent(rec)

		// Record Non-Occupancy Period (NOP) if radar was detected on a DFS channel
		if evt.EventType == EventDFS {
			store.AddNOPChannel(evt.Channel)
		}

		// Update Prometheus metrics (thread-safe)
		if metrics != nil {
			metrics.ObserveEvent(rec)
		}
	}
}

func GetMonotonicTimeNs() uint64 {
	var tv unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &tv)
	return uint64(tv.Sec)*1e9 + uint64(tv.Nsec)
}
