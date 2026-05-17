// agent/fastloop.go
//
// Fast-loop goroutine: reads classified events from the BPF ring buffer
// and feeds them into the Store.
//
// This is the Near-RT RIC analog from the P4+RRM article:
//   - Woken by the kernel immediately when the XDP program writes an event
//   - No polling — ringbuf.Reader.Read() blocks until data is available
//   - Target reaction time: sub-millisecond from kernel write to Store update
//
// The goroutine signals completion via the done channel so main() can
// wait for clean shutdown after rd.Close() is called.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"time"

	"github.com/cilium/ebpf/ringbuf"
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

		// Compute kernel → userspace latency.
		// evt.TimestampNs = bpf_ktime_get_ns() = ns since boot.
		// bootTimeNs = boot time as Unix ns.
		// kernelUnixNs = boot + offset = absolute Unix timestamp of the event.
		kernelUnixNs := int64(bootTimeNs) + int64(evt.TimestampNs)
		latencyNs := receivedAt.UnixNano() - kernelUnixNs

		rec := EventRecord{
			ReceivedAt: receivedAt,
			KernelNs:   evt.TimestampNs,
			LatencyNs:  latencyNs,
			Synthetic:  false,
			Event:      evt,
		}

		// Update shared state (thread-safe)
		store.AddEvent(rec)

		// Update Prometheus metrics (thread-safe)
		if metrics != nil {
			metrics.ObserveEvent(rec)
		}
	}
}
