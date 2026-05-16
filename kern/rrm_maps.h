/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kern/rrm_maps.h
 *
 * BPF map definitions for the RRM telemetry engine.
 *
 * Phase 1 maps:
 *   ap_pkt_count   — packet counter per AP (HASH, u32 key → u64 value)
 *   ap_state       — RF state snapshot per AP (HASH, u32 key → ap_info)
 *
 * Phase 2 will add:
 *   ap_thresholds  — configurable detection thresholds (ARRAY)
 *   rrm_events     — fast-path event ring buffer (RINGBUF)
 *
 * Map definitions use the BTF-annotated syntax (SEC(".maps") + struct
 * initialiser). This is the libbpf-preferred style and required for
 * CO-RE skeleton generation in Phase 3.
 */

#ifndef RRM_MAPS_H
#define RRM_MAPS_H

/*
 * ap_info — per-AP state stored in ap_state map.
 *
 * All fields are 1 byte; total struct is 8 bytes with no implicit padding.
 * The Go agent reads this struct via cilium/ebpf map iteration in Phase 3.
 *
 * Layout:
 *   Offset  Size  Field
 *   ──────  ────  ──────────────────────────────────────
 *   0       1     channel          current channel
 *   1       1     channel_util     channel utilisation %
 *   2       1     noise_floor_dbm  signed noise floor dBm
 *   3       1     client_count     associated client count
 *   4       1     event_flags      last seen event flags
 *   5       3     pad              padding
 */
struct ap_info {
    __u8  channel;
    __u8  channel_util;
    __s8  noise_floor_dbm;
    __u8  client_count;
    __u8  event_flags;
    __u8  pad[3];
};

/*
 * ap_pkt_count — counts CAPWAP-lite packets received per AP.
 *
 * Key:   ap_id (__u32)
 * Value: packet count (__u64), updated atomically with __sync_fetch_and_add
 *
 * max_entries=512: supports up to 512 distinct APs per switch.
 * In production, size to the AP count of the deployment.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,         __u32);
    __type(value,       __u64);
} ap_pkt_count SEC(".maps");

/*
 * ap_state — stores the most recent RF telemetry snapshot per AP.
 *
 * Key:   ap_id (__u32)
 * Value: struct ap_info (8 bytes)
 *
 * Updated on every CAPWAP-lite packet. Not atomic (last-write wins).
 * For Phase 1 validation on a single-CPU veth pair this is acceptable.
 * Phase 2 introduces per-CPU maps for multi-core correctness.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,         __u32);
    __type(value,       struct ap_info);
} ap_state SEC(".maps");

#endif /* RRM_MAPS_H */