// SPDX-License-Identifier: GPL-2.0
/*
 * kern/rrm_xdp.c — Phase 2: EWMA + Threshold Detection + Ring Buffer
 *
 * Extends the Phase 1 parser with:
 *
 *   1. Fixed-point Q8 EWMA for channel utilisation smoothing.
 *      No floating point — eBPF kernel programs do not support FPU.
 *      Uses integer multiply + bitshift to approximate alpha=0.25 weighting.
 *
 *   2. Configurable threshold detection for three event classes:
 *      - DFS radar:     immediate on CAPWAP_EVENT_RADAR flag
 *      - Load anomaly:  EWMA >= util_high for util_consec consecutive packets
 *      - Noise spike:   noise floor rose > noise_delta dBm vs last packet
 *
 *   3. Fast-path ring buffer output via bpf_ringbuf_reserve/submit.
 *      The reserve/submit API writes directly into the ring buffer without
 *      a copy (vs bpf_ringbuf_output which copies from a stack buffer).
 *
 * Processing pipeline per packet:
 *
 *   Ethernet → IPv4 → UDP/9000 → capwap_lite_hdr
 *          ↓
 *   ap_id extraction
 *          ↓
 *   ap_pkt_count update (atomic)
 *          ↓
 *   ap_thresholds lookup (key=0, ARRAY → always succeeds)
 *          ↓
 *   ap_state lookup
 *   ├── not found → initialise state, XDP_PASS (no event on first packet)
 *   └── found →
 *          EWMA update
 *          noise delta calculation
 *          DFS / load / noise threshold check
 *          ap_state update
 *          ring buffer write (if event detected)
 *          XDP_PASS
 *
 * All non-CAPWAP-lite packets pass through without any processing.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "rrm_maps.h"
#include "../proto/capwap_lite.h"

/* Protocol constants (not provided by vmlinux.h as #defines) */
#define RRM_ETH_P_IP    0x0800
#define RRM_IPPROTO_UDP 17

/* ── EWMA parameters ─────────────────────────────────────────────────────────
 *
 * Q8 fixed-point arithmetic: all values are scaled by 2^8 = 256.
 *
 * alpha = 0.25 → EWMA_ALPHA_Q8 = 64   (0.25 * 256)
 * beta  = 0.75 → EWMA_BETA_Q8  = 192  (0.75 * 256 = 256 - 64)
 *
 * Update formula:
 *   new_ewma_q8 = (ALPHA * new_val + BETA * old_ewma) >> 8
 *
 * Why alpha=0.25:
 *   - Higher alpha (e.g. 0.5) reacts faster but is noisier
 *   - Lower alpha (e.g. 0.125) is smoother but slower to react
 *   - 0.25 gives reasonable responsiveness to sustained load changes
 *     while filtering single-packet measurement noise
 *
 * Input range: channel_util is 0–100 (fits in __u8).
 * Output range: ewma result is also 0–100, fits in __u8.
 * Intermediate: (64 * 100 + 192 * 100) = 25600, fits in __u16. Safe.
 */
#define EWMA_ALPHA_Q8   64
#define EWMA_BETA_Q8    192

/*
 * ewma_update — compute one EWMA step without floating point.
 *
 * @old_ewma: previous EWMA value (0–100, same unit as channel_util)
 * @new_val:  new channel_util measurement (0–100)
 * Returns:   updated EWMA value (0–100)
 *
 * The function is marked __always_inline: BPF does not support function
 * calls in older kernels (pre-4.16). Even on modern kernels, inlining
 * avoids the BPF-to-BPF call overhead for this hot path.
 */
static __always_inline __u8 ewma_update(__u8 old_ewma, __u8 new_val)
{
    /*
     * Use __u16 for the intermediate multiply to avoid __u8 overflow.
     * Maximum intermediate value: 192 * 100 = 19200, fits in __u16.
     * After >> 8: 19200 / 256 = 75, fits in __u8.
     */
    __u16 result = ((__u16)EWMA_ALPHA_Q8 * (__u16)new_val +
                    (__u16)EWMA_BETA_Q8  * (__u16)old_ewma) >> 8;

    /* result is guaranteed 0–100, safe to truncate to __u8 */
    return (__u8)result;
}

/* ── Default threshold values ─────────────────────────────────────────────
 *
 * Used when the Go agent has not yet written thresholds (map entry is zero).
 * Matching the defaults in agent/main.go.
 */
#define DEFAULT_UTIL_HIGH    85
#define DEFAULT_UTIL_CONSEC   3
#define DEFAULT_NOISE_DELTA  10

/* ── XDP entry point ─────────────────────────────────────────────────────── */

SEC("xdp")
int rrm_xdp_parser(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* ── L2: Ethernet ──────────────────────────────────────────────────── */

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != RRM_ETH_P_IP)
        return XDP_PASS;

    /* ── L3: IPv4 ──────────────────────────────────────────────────────── */

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != RRM_IPPROTO_UDP)
        return XDP_PASS;

    /* ── L4: UDP ───────────────────────────────────────────────────────── */

    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(udp->dest) != CAPWAP_LITE_PORT)
        return XDP_PASS;

    /* ── CAPWAP-lite header ────────────────────────────────────────────── */

    struct capwap_lite_hdr *cap = (void *)(udp + 1);
    if ((void *)(cap + 1) > data_end)
        return XDP_PASS;

    __u32 ap_id = bpf_ntohl(cap->ap_id);

    /* ── Packet counter (always updated) ──────────────────────────────── */

    __u64 *pkt_cnt = bpf_map_lookup_elem(&ap_pkt_count, &ap_id);
    if (pkt_cnt) {
        __sync_fetch_and_add(pkt_cnt, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&ap_pkt_count, &ap_id, &init, BPF_ANY);
    }

    /* ── Threshold lookup ──────────────────────────────────────────────
     *
     * ARRAY map lookup with key=0 always succeeds (array is pre-allocated).
     * If the Go agent has not yet written thresholds, all fields are 0.
     * We use default values when the stored value is 0.
     *
     * This is the "P4Runtime analogy": thresholds are pushed from the
     * control plane (Go agent) into the data plane (XDP) without recompiling.
     */
    __u32 thresh_key = 0;
    struct thresholds *thresh = bpf_map_lookup_elem(&ap_thresholds, &thresh_key);

    __u8 util_high    = DEFAULT_UTIL_HIGH;
    __u8 util_consec  = DEFAULT_UTIL_CONSEC;
    __u8 noise_delta  = DEFAULT_NOISE_DELTA;

    if (thresh) {
        /* Use stored values if non-zero; keep defaults otherwise */
        if (thresh->util_high   > 0) util_high   = thresh->util_high;
        if (thresh->util_consec > 0) util_consec = thresh->util_consec;
        if (thresh->noise_delta > 0) noise_delta = thresh->noise_delta;
    }

    /* ── AP state lookup ───────────────────────────────────────────────
     *
     * First packet from this AP: initialise state and return.
     * No EWMA update or event detection on the first packet —
     * we have no previous state to compare against.
     */
    struct ap_info *state = bpf_map_lookup_elem(&ap_state, &ap_id);

    if (!state) {
        struct ap_info init_state = {
            .channel         = cap->channel,
            .channel_util    = cap->channel_util,
            .noise_floor_dbm = cap->noise_floor_dbm,
            .client_count    = cap->client_count,
            .event_flags     = cap->event_flags,
            /*
             * Initialise EWMA to the first observed value (not 0).
             * Using 0 would cause the EWMA to ramp up slowly from zero
             * instead of starting at the actual baseline.
             */
            .util_ewma_q8    = cap->channel_util,
            .noise_prev_dbm  = cap->noise_floor_dbm,
            .consec_high     = 0,
        };
        bpf_map_update_elem(&ap_state, &ap_id, &init_state, BPF_ANY);
        return XDP_PASS;
    }

    /* ── EWMA update ───────────────────────────────────────────────────
     *
     * Compute updated EWMA from previous EWMA and new raw measurement.
     * The EWMA smooths out single-packet measurement noise.
     */
    __u8 new_ewma = ewma_update(state->util_ewma_q8, cap->channel_util);

    /* ── Noise delta calculation ────────────────────────────────────────
     *
     * noise_floor_dbm is signed: -100 to 0 dBm.
     * A noise spike means the noise floor INCREASED (became less negative).
     * Example: previous=-90, current=-75 → delta = -75 - (-90) = +15
     *
     * We compute using __s16 to avoid signed overflow:
     *   __s8 - __s8 can overflow for large differences,
     *   e.g. (-100) - (0) = -100 in __s8 but only -100 in __s16.
     *   Safe range: -100 to 0, delta range: -100 to +100. Fits in __s16.
     */
    __s16 noise_delta_val = (__s16)cap->noise_floor_dbm -
                            (__s16)state->noise_prev_dbm;

    /* ── Event classification ───────────────────────────────────────────
     *
     * Priority: DFS > Load Anomaly > Noise Spike.
     * Only one event is emitted per packet.
     *
     * DFS: immediate on flag, no consecutive requirement.
     *      Regulatory requirement: must respond within 10 seconds.
     *      Even one missed detection cycle is unacceptable.
     *
     * Load anomaly: EWMA must exceed threshold for util_consec consecutive
     *      packets. Prevents false positives from transient bursts.
     *      consec_high is reset to 0 when EWMA drops below threshold.
     *
     * Noise spike: single-packet delta check (no consecutive requirement).
     *      A sudden jump in noise floor (e.g. microwave oven turning on)
     *      warrants immediate notification regardless of prior state.
     */
    __u8 emit_event  = 0;
    __u8 event_type  = 0;
    __u8 new_consec  = 0;   /* consecutive high-util counter for updated state */

    if (cap->event_flags & CAPWAP_EVENT_RADAR) {
        /* DFS: flag-driven, no consecutive requirement */
        emit_event = 1;
        event_type = RRM_EVENT_DFS;
        new_consec  = 0;   /* reset load counter on channel event */

    } else if (new_ewma >= util_high) {
        /*
         * Load anomaly path: increment consecutive counter.
         * Cap at util_consec to prevent __u8 overflow on persistent load.
         * Emit event when counter reaches threshold.
         */
        new_consec = state->consec_high + 1;
        if (new_consec >= util_consec) {
            emit_event = 1;
            event_type = RRM_EVENT_LOAD_ANOMALY;
            new_consec = util_consec;   /* saturate, don't wrap */
        }

    } else if (noise_delta_val > (__s16)noise_delta) {
        /* Noise spike: single-packet delta exceeds threshold */
        emit_event = 1;
        event_type = RRM_EVENT_NOISE_SPIKE;
        new_consec  = 0;   /* below util threshold, reset counter */

    }
    /* else: normal packet, no event, new_consec stays 0 (reset load counter) */

    /* ── ap_state update ───────────────────────────────────────────────
     *
     * Write a fully initialised struct. The BPF verifier requires that
     * all bytes of a value passed to bpf_map_update_elem be initialised.
     * A compound literal with named fields satisfies this requirement.
     */
    struct ap_info updated = {
        .channel         = cap->channel,
        .channel_util    = cap->channel_util,
        .noise_floor_dbm = cap->noise_floor_dbm,
        .client_count    = cap->client_count,
        .event_flags     = cap->event_flags,
        .util_ewma_q8    = new_ewma,
        .noise_prev_dbm  = cap->noise_floor_dbm,  /* current becomes "prev" */
        .consec_high     = new_consec,
    };
    bpf_map_update_elem(&ap_state, &ap_id, &updated, BPF_ANY);

    /* ── Ring buffer event emission ─────────────────────────────────────
     *
     * bpf_ringbuf_reserve: reserves sizeof(struct rrm_event) bytes in the
     * ring buffer and returns a pointer to the reserved slot. Returns NULL
     * if the ring buffer is full (consumer is too slow).
     *
     * We write directly into the reserved slot — no intermediate stack copy.
     * This is more efficient than bpf_ringbuf_output.
     *
     * bpf_ringbuf_submit: makes the slot visible to the consumer. After
     * submit, the pointer must not be used again.
     *
     * bpf_ringbuf_discard: called instead of submit on the error path
     * (though here we only reserve after deciding to emit, so discard
     * is not needed).
     */
    if (emit_event) {
        struct rrm_event *evt = bpf_ringbuf_reserve(
            &rrm_events, sizeof(struct rrm_event), 0);

        if (evt) {
            /*
             * bpf_ktime_get_ns() returns nanoseconds since system boot.
             * The Go agent subtracts its own startup timestamp to get
             * relative event times, or compares two events to get latency.
             */
            evt->timestamp_ns  = bpf_ktime_get_ns();
            evt->ap_id         = ap_id;
            evt->event_type    = event_type;
            evt->channel       = cap->channel;
            evt->util_snapshot = new_ewma;
            evt->noise_snapshot = cap->noise_floor_dbm;

            bpf_ringbuf_submit(evt, 0);

            /* Trace log — remove in Phase 4 production build */
            bpf_printk("RRM EVENT: ap=%u type=%u ch=%u ewma=%u%%\n",
                       ap_id, event_type, cap->channel, new_ewma);
        } else {
            /* Ring buffer full — consumer may be too slow */
            bpf_printk("RRM WARN: ring buffer full, dropped event ap=%u\n",
                       ap_id);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";