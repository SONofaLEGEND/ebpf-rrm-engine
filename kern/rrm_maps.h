/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kern/rrm_maps.h — Phase 2
 *
 * BPF map definitions for the RRM telemetry engine.
 *
 * Phase 2 additions over Phase 1:
 *   ap_info        → extended with EWMA state fields
 *   ap_thresholds  → configurable detection thresholds (ARRAY, single entry)
 *   rrm_events     → fast-path event ring buffer (RINGBUF)
 *   RRM_EVENT_*    → event type constants shared with Go agent
 *
 * Struct layouts are designed with explicit padding so Go's binary.Read
 * (using native little-endian) produces the same byte offsets as C.
 * Every struct is annotated with its exact byte layout.
 */

#ifndef RRM_MAPS_H
#define RRM_MAPS_H

/* ── Event type constants ────────────────────────────────────────────────────
 *
 * Used in rrm_event.event_type and matched in the Go agent.
 * Defined as macros (not enum) to be usable in BPF and in Python generator.
 */
#define RRM_EVENT_DFS           0   /* DFS radar detected — immediate */
#define RRM_EVENT_LOAD_ANOMALY  1   /* channel_util EWMA above threshold N times */
#define RRM_EVENT_NOISE_SPIKE   2   /* noise floor rose by > delta dBm */

/* ── ap_info ─────────────────────────────────────────────────────────────────
 *
 * Per-AP state stored in the ap_state hash map.
 * Updated on every CAPWAP-lite packet from that AP.
 *
 * Phase 2 additions (vs Phase 1):
 *   util_ewma_q8    — fixed-point Q8 EWMA of channel_util (see rrm_xdp.c)
 *   noise_prev_dbm  — previous noise floor, used to compute per-interval delta
 *   consec_high     — consecutive intervals where util_ewma >= util_high
 *
 * Wire layout (8 bytes, no implicit padding):
 *   Offset  Size  Field             Description
 *   ──────  ────  ────────────────  ───────────────────────────────────────
 *   0       1     channel           current 802.11 channel
 *   1       1     channel_util      raw utilisation from last packet (0–100)
 *   2       1     noise_floor_dbm   raw noise floor, signed dBm (-100 to 0)
 *   3       1     client_count      associated clients
 *   4       1     event_flags       CAPWAP_EVENT_* from last packet
 *   5       1     util_ewma_q8      Q8 EWMA of channel_util (see note below)
 *   6       1     noise_prev_dbm    noise floor from previous packet (signed)
 *   7       1     consec_high       consecutive high-utilisation intervals
 *
 * Q8 EWMA note:
 *   util_ewma_q8 is a fixed-point value in Q8 format (multiply by 256).
 *   To read the actual percentage: util_ewma_q8 (stored as __u8 0–255)
 *   represents util_ewma_q8 / 256 * 100 ≈ util_ewma_q8 * 100 / 256.
 *   However, since channel_util is 0–100 (fits in __u8), the EWMA is also
 *   0–100 and fits directly in __u8 without loss of significant information.
 *   The Q8 arithmetic is done at full precision internally; the final result
 *   is truncated back to __u8 before storage.
 */
struct ap_info {
    __u8  channel;
    __u8  channel_util;
    __s8  noise_floor_dbm;
    __u8  client_count;
    __u8  event_flags;
    __u8  util_ewma_q8;
    __s8  noise_prev_dbm;
    __u8  consec_high;
};

/* ── thresholds ──────────────────────────────────────────────────────────────
 *
 * Configurable detection thresholds written by the Go agent via P4Runtime
 * analogy (BPF map update from userspace using cilium/ebpf).
 *
 * Wire layout (4 bytes):
 *   Offset  Size  Field        Default  Description
 *   ──────  ────  ───────────  ───────  ───────────────────────────────────
 *   0       1     util_high    85       EWMA % above which util is "high"
 *   1       1     util_consec  3        consecutive high intervals → event
 *   2       1     noise_delta  10       dBm rise per interval → noise spike
 *   3       1     pad          0        padding to 4-byte alignment
 */
struct thresholds {
    __u8  util_high;
    __u8  util_consec;
    __u8  noise_delta;
    __u8  pad;
};

/* ── rrm_event ────────────────────────────────────────────────────────────────
 *
 * Fast-path event emitted to the ring buffer on anomaly detection.
 * Read by the Go agent's ring buffer consumer goroutine.
 *
 * Wire layout (16 bytes, packed):
 *   Offset  Size  Go type   Field           Description
 *   ──────  ────  ────────  ─────────────   ──────────────────────────────
 *   0       8     uint64    timestamp_ns    bpf_ktime_get_ns() at detection
 *   8       4     uint32    ap_id           AP identifier
 *   12      1     uint8     event_type      RRM_EVENT_* constant
 *   13      1     uint8     channel         channel at time of event
 *   14      1     uint8     util_snapshot   util_ewma_q8 at time of event
 *   15      1     int8      noise_snapshot  noise_floor_dbm at time of event
 *
 * Total: 16 bytes. No internal padding (natural alignment).
 * The Go struct RRMEvent in agent/main.go must match this layout exactly.
 */
struct rrm_event {
    __u64 timestamp_ns;
    __u32 ap_id;
    __u8  event_type;
    __u8  channel;
    __u8  util_snapshot;
    __s8  noise_snapshot;
};

/* ── BPF map definitions ─────────────────────────────────────────────────── */

/*
 * ap_pkt_count — packet counter per AP (unchanged from Phase 1)
 * Key: ap_id (__u32), Value: count (__u64)
 */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,         __u32);
    __type(value,       __u64);
} ap_pkt_count SEC(".maps");

/*
 * ap_state — per-AP RF telemetry snapshot (extended in Phase 2)
 * Key: ap_id (__u32), Value: struct ap_info (8 bytes)
 */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,         __u32);
    __type(value,       struct ap_info);
} ap_state SEC(".maps");

/*
 * ap_thresholds — configurable detection thresholds
 * Key: __u32 (always 0, single entry), Value: struct thresholds (4 bytes)
 *
 * Written by the Go agent at startup via BPF map update.
 * Read by the XDP program on every packet (ARRAY lookup is O(1) in BPF).
 *
 * BPF_MAP_TYPE_ARRAY: always pre-allocated, lookup never fails for key < max.
 * The XDP program reads key=0 and uses defaults if the map entry is zeroed.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct thresholds);
} ap_thresholds SEC(".maps");

/*
 * rrm_events — fast-path event ring buffer
 * Produced by: XDP program (bpf_ringbuf_reserve + bpf_ringbuf_submit)
 * Consumed by: Go agent ringbuf.Reader goroutine
 *
 * max_entries: ring buffer size in bytes. Must be:
 *   - Power of 2
 *   - Multiple of PAGE_SIZE (4096 on x86/arm64)
 *
 * 256 * 1024 = 262144 bytes = 64 pages.
 * At 16 bytes per event, this holds 16384 unconsumed events before
 * the XDP program starts dropping (bpf_ringbuf_reserve returns NULL).
 * For a 5-AP deployment at 1 event/sec, this is effectively unlimited.
 *
 * Requires kernel 5.8+. Ubuntu 22.04 (kernel 5.15) is fine.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rrm_events SEC(".maps");

#endif /* RRM_MAPS_H */