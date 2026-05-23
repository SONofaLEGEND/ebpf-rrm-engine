/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kern/rrm_maps.h
 *
 * BPF map definitions for the RRM telemetry engine.
 *
 * Pinned map paths (written by agent on startup):
 *   /sys/fs/bpf/rrm/ap_pkt_count
 *   /sys/fs/bpf/rrm/ap_state
 *   /sys/fs/bpf/rrm/ap_thresholds
 *   /sys/fs/bpf/rrm/rrm_events
 *   /sys/fs/bpf/rrm/rrm_stats
 *
 * Pinning allows the CLI to access maps without the agent process holding
 * the file descriptors — maps persist in the BPF filesystem until explicitly
 * unpinned or the system reboots.
 */

#ifndef RRM_MAPS_H
#define RRM_MAPS_H

/* Event type constants */
#define RRM_EVENT_DFS           0
#define RRM_EVENT_LOAD_ANOMALY  1
#define RRM_EVENT_NOISE_SPIKE   2

/* Global stats index constants */
#define RRM_STAT_RINGBUF_DROPS    0
#define RRM_STAT_INVALID_RF_PKTS  1

/*
 * ap_info — per-AP state (8 bytes, no padding)
 *   Offset  Size  Field
 *   0       1     channel
 *   1       1     channel_util
 *   2       1     noise_floor_dbm  (signed)
 *   3       1     client_count
 *   4       1     event_flags
 *   5       1     util_ewma_q8
 *   6       1     noise_prev_dbm   (signed)
 *   7       1     consec_high
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

/*
 * thresholds — configurable detection thresholds (4 bytes)
 *   Offset  Size  Field        Default
 *   0       1     util_high    85
 *   1       1     util_consec  3
 *   2       1     noise_delta  10
 *   3       1     pad          0
 */
struct thresholds {
    __u8  util_high;
    __u8  util_consec;
    __u8  noise_delta;
    __u8  pad;
};

/*
 * rrm_event — fast-path ring buffer record (16 bytes, no padding)
 *   Offset  Size  Field
 *   0       8     timestamp_ns
 *   8       4     ap_id
 *   12      1     event_type
 *   13      1     channel
 *   14      1     util_snapshot
 *   15      1     noise_snapshot  (signed)
 */
struct rrm_event {
    __u64 timestamp_ns;
    __u32 ap_id;
    __u8  event_type;
    __u8  channel;
    __u8  util_snapshot;
    __s8  noise_snapshot;
};

/* ── Map definitions ──────────────────────────────────────────────────────── */

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,         __u32);
    __type(value,       __u64);
} ap_pkt_count SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,         __u32);
    __type(value,       struct ap_info);
} ap_state SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct thresholds);
} ap_thresholds SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rrm_events SEC(".maps");

/*
 * rrm_stats — global counters.
 * Index RRM_STAT_RINGBUF_DROPS: Ring buffer drops
 * Index RRM_STAT_INVALID_RF_PKTS: Packets dropped due to invalid RF parameters
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key,         __u32);
    __type(value,       __u64);
} rrm_stats SEC(".maps");

#endif /* RRM_MAPS_H */