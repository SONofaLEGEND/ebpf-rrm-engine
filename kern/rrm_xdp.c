// SPDX-License-Identifier: GPL-2.0
/*
 * kern/rrm_xdp.c
 *
 * Fast-path packet parsing and RF telemetry classification using eBPF/XDP.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "rrm_maps.h"
#include "../proto/capwap_lite.h"

#define RRM_ETH_P_IP     0x0800
#define RRM_IPPROTO_UDP  17

#define EWMA_ALPHA_Q8    64
#define EWMA_BETA_Q8    192

#define DEFAULT_UTIL_HIGH    85
#define DEFAULT_UTIL_CONSEC   3
#define DEFAULT_NOISE_DELTA  10

static __always_inline bool is_valid_channel(__u8 channel)
{
    if (channel >= 1 && channel <= 14)
        return true;
    if (channel >= 36 && channel <= 64 && (channel % 4 == 0))
        return true;
    if (channel >= 100 && channel <= 144 && (channel % 4 == 0))
        return true;
    if (channel >= 149 && channel <= 161 && (channel % 4 == 0))
        return true;
    if (channel == 165)
        return true;
    return false;
}

static __always_inline bool is_dfs_channel(__u8 channel)
{
    if (channel >= 52 && channel <= 64 && (channel % 4 == 0))
        return true;
    if (channel >= 100 && channel <= 144 && (channel % 4 == 0))
        return true;
    return false;
}

static __always_inline __u8 ewma_update(__u8 old_ewma, __u8 new_val)
{
    __u16 result = ((__u16)EWMA_ALPHA_Q8 * (__u16)new_val +
                    (__u16)EWMA_BETA_Q8  * (__u16)old_ewma) >> 8;
    return (__u8)result;
}


SEC("xdp")
int rrm_xdp_parser(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != RRM_ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != RRM_IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr) || ip_hlen > 60)
        return XDP_PASS;
    if ((void *)ip + ip_hlen > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(udp->dest) != CAPWAP_LITE_PORT)
        return XDP_PASS;

    struct capwap_lite_hdr *cap = (void *)(udp + 1);
    if ((void *)(cap + 1) > data_end)
        return XDP_PASS;

    /* Validate RF parameters for compliance and 802.11 specs */
    if (!is_valid_channel(cap->channel) ||
        cap->channel_util > 100 ||
        cap->noise_floor_dbm < -120 ||
        cap->noise_floor_dbm > 0) {
        __u32 err_key = RRM_STAT_INVALID_RF_PKTS;
        __u64 *err_cnt = bpf_map_lookup_elem(&rrm_stats, &err_key);
        if (err_cnt) {
            __sync_fetch_and_add(err_cnt, 1);
        }
        return XDP_PASS;
    }

    __u32 ap_id = bpf_ntohl(cap->ap_id);

    __u64 *pkt_cnt = bpf_map_lookup_elem(&ap_pkt_count, &ap_id);
    if (pkt_cnt) {
        __sync_fetch_and_add(pkt_cnt, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&ap_pkt_count, &ap_id, &init, BPF_ANY);
    }

    __u32 thresh_key = 0;
    struct thresholds *thresh = bpf_map_lookup_elem(&ap_thresholds, &thresh_key);

    __u8 util_high   = DEFAULT_UTIL_HIGH;
    __u8 util_consec = DEFAULT_UTIL_CONSEC;
    __u8 noise_delta = DEFAULT_NOISE_DELTA;
    if (thresh) {
        if (thresh->util_high   > 0) util_high   = thresh->util_high;
        if (thresh->util_consec > 0) util_consec = thresh->util_consec;
        if (thresh->noise_delta > 0) noise_delta = thresh->noise_delta;
    }

    struct ap_info *state = bpf_map_lookup_elem(&ap_state, &ap_id);
    if (!state) {
        struct ap_info init_state;
        __builtin_memset(&init_state, 0, sizeof(init_state));
        init_state.channel         = cap->channel;
        init_state.channel_util    = cap->channel_util;
        init_state.noise_floor_dbm = cap->noise_floor_dbm;
        init_state.client_count    = cap->client_count;
        init_state.event_flags     = cap->event_flags;
        init_state.util_ewma_q8    = cap->channel_util;
        init_state.noise_prev_dbm  = cap->noise_floor_dbm;
        init_state.consec_high     = 0;
        bpf_map_update_elem(&ap_state, &ap_id, &init_state, BPF_ANY);
        return XDP_PASS;
    }

    __u8  new_ewma      = ewma_update(state->util_ewma_q8, cap->channel_util);
    __s16 noise_delta_val = (__s16)cap->noise_floor_dbm -
                            (__s16)state->noise_prev_dbm;

    __u8 emit_event = 0;
    __u8 event_type = 0;
    __u8 new_consec = 0;

    if ((cap->event_flags & CAPWAP_EVENT_RADAR) && is_dfs_channel(cap->channel)) {
        emit_event = 1;
        event_type = RRM_EVENT_DFS;
        new_consec = 0;
    } else if (new_ewma >= util_high) {
        new_consec = state->consec_high + 1;
        if (new_consec >= util_consec) {
            emit_event = 1;
            event_type = RRM_EVENT_LOAD_ANOMALY;
            new_consec = util_consec;
        }
    } else if (noise_delta_val > (__s16)noise_delta) {
        emit_event = 1;
        event_type = RRM_EVENT_NOISE_SPIKE;
        new_consec = 0;
    }

    struct ap_info updated;
    __builtin_memset(&updated, 0, sizeof(updated));
    updated.channel         = cap->channel;
    updated.channel_util    = cap->channel_util;
    updated.noise_floor_dbm = cap->noise_floor_dbm;
    updated.client_count    = cap->client_count;
    updated.event_flags     = cap->event_flags;
    updated.util_ewma_q8    = new_ewma;
    updated.noise_prev_dbm  = cap->noise_floor_dbm;
    updated.consec_high     = new_consec;
    bpf_map_update_elem(&ap_state, &ap_id, &updated, BPF_ANY);

    if (emit_event) {
        struct rrm_event *evt = bpf_ringbuf_reserve(
            &rrm_events, sizeof(struct rrm_event), 0);
        if (evt) {
            evt->timestamp_ns   = bpf_ktime_get_ns();
            evt->ap_id          = ap_id;
            evt->event_type     = event_type;
            evt->channel        = cap->channel;
            evt->util_snapshot  = new_ewma;
            evt->noise_snapshot = cap->noise_floor_dbm;
            bpf_ringbuf_submit(evt, 0);
        } else {
            __u32 drop_key = RRM_STAT_RINGBUF_DROPS;
            __u64 *drops = bpf_map_lookup_elem(&rrm_stats, &drop_key);
            if (drops)
                __sync_fetch_and_add(drops, 1);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";