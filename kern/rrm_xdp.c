// SPDX-License-Identifier: GPL-2.0
/*
 * kern/rrm_xdp.c — Phase 1: CAPWAP-lite parser
 *
 * XDP program that inspects all ingress packets on the attached interface,
 * identifies CAPWAP-lite frames (UDP/9000), parses the RF telemetry header,
 * and updates per-AP state in BPF hash maps.
 *
 * All non-CAPWAP-lite traffic is passed through unmodified (XDP_PASS).
 * This program is purely observational — it never drops or modifies packets.
 *
 * Packet path parsed:
 *   Ethernet → IPv4 → UDP (dport=9000) → capwap_lite_hdr
 *
 * Compile with:
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_{arm64|x86} \
 *         -I./kern -I./proto -I/usr/include/<arch>-linux-gnu \
 *         -c kern/rrm_xdp.c -o kern/rrm_xdp.o
 *
 * Or simply: make
 */

/*
 * vmlinux.h provides all kernel struct/type definitions generated from the
 * running kernel's BTF data. Including this (instead of linux/*.h headers)
 * is the CO-RE approach: the compiled program works on any kernel that
 * exports compatible BTF, without recompilation.
 *
 * DO NOT include any linux/*.h or asm/*.h headers alongside vmlinux.h —
 * type conflicts will cause compilation errors.
 */
#include "vmlinux.h"

/*
 * bpf_helpers.h   — BPF helper function declarations (bpf_map_lookup_elem,
 *                   bpf_map_update_elem, bpf_printk, SEC macro, etc.)
 * bpf_endian.h    — byte-order conversion macros (bpf_ntohs, bpf_ntohl)
 *                   These are safe to include alongside vmlinux.h.
 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "rrm_maps.h"
#include "../proto/capwap_lite.h"

/*
 * Protocol constants.
 * vmlinux.h provides type definitions, not #define macros.
 * Define our own with an RRM_ prefix to avoid any future collisions.
 */
#define RRM_ETH_P_IP     0x0800   /* IPv4 EtherType */
#define RRM_IPPROTO_UDP  17       /* IP protocol number for UDP */

/*
 * rrm_xdp_parser — main XDP entry point.
 *
 * Called by the kernel for every ingress packet on the attached interface.
 * ctx->data and ctx->data_end define the packet bounds. Every pointer
 * dereference must be validated against data_end before access — this is
 * enforced at load time by the BPF verifier. Any unchecked access causes
 * the verifier to reject the program.
 *
 * Return values:
 *   XDP_PASS — forward packet normally (used for all packets here)
 *   XDP_DROP — drop packet (not used in Phase 1)
 */
SEC("xdp")
int rrm_xdp_parser(struct xdp_md *ctx)
{
    /*
     * data and data_end are the packet buffer boundaries.
     * The cast through (long) is required — ctx fields are __u32,
     * but pointer arithmetic needs void*.
     */
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* ── Layer 2: Ethernet header ────────────────────────────────────────── */

    struct ethhdr *eth = data;

    /*
     * Bounds check pattern used throughout this program:
     * Verify that the entire struct fits within the packet buffer.
     * If (ptr_to_struct + 1) > data_end, the struct would extend beyond
     * the buffer — reject by passing through without processing.
     * The verifier requires this check before every dereference.
     */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 frames. Skip ARP, IPv6, etc. */
    if (bpf_ntohs(eth->h_proto) != RRM_ETH_P_IP)
        return XDP_PASS;

    /* ── Layer 3: IPv4 header ────────────────────────────────────────────── */

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process UDP. Skip TCP, ICMP, etc. */
    if (ip->protocol != RRM_IPPROTO_UDP)
        return XDP_PASS;

    /*
     * Locate the UDP header.
     *
     * We use sizeof(*ip) = 20 bytes rather than ip->ihl*4 because:
     *   1. Our generator (Scapy) never sets IP options, so ihl is always 5.
     *   2. sizeof() avoids a bitfield read, keeping the verifier analysis
     *      straightforward. The verifier tracks ihl*4 as a bounded value
     *      (5*4=20 to 15*4=60), but the simpler sizeof() is cleaner here.
     *   3. If a packet with IP options arrives, the CAPWAP-lite bounds check
     *      below will reject it correctly anyway.
     */
    struct udphdr *udp = (void *)ip + sizeof(*ip);

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* ── Layer 4: UDP — filter on destination port ───────────────────────── */

    if (bpf_ntohs(udp->dest) != CAPWAP_LITE_PORT)
        return XDP_PASS;

    /* ── CAPWAP-lite header ─────────────────────────────────────────────── */

    struct capwap_lite_hdr *cap = (void *)(udp + 1);

    if ((void *)(cap + 1) > data_end)
        return XDP_PASS;

    /*
     * Extract AP identifier.
     * ap_id is in network byte order (big-endian) in the packet.
     * Convert to host byte order for use as a map key.
     */
    __u32 ap_id = bpf_ntohl(cap->ap_id);

    /* ── Update per-AP packet counter ───────────────────────────────────── */

    __u64 *pkt_cnt = bpf_map_lookup_elem(&ap_pkt_count, &ap_id);
    if (pkt_cnt) {
        /*
         * Atomic increment. Required for correctness on multi-CPU systems
         * where multiple cores may process packets for the same AP_ID.
         * __sync_fetch_and_add is the BPF-safe atomic add.
         */
        __sync_fetch_and_add(pkt_cnt, 1);
    } else {
        /*
         * First packet from this AP — create the map entry.
         * BPF_ANY: create if not exists, update if exists.
         * Race condition on first packet is benign: the count may
         * start at 1 or 2 depending on concurrent insertions. Phase 2
         * will use per-CPU maps to eliminate this.
         */
        __u64 init = 1;
        bpf_map_update_elem(&ap_pkt_count, &ap_id, &init, BPF_ANY);
    }

    /* ── Update per-AP state snapshot ───────────────────────────────────── */

    /*
     * Compound literal initialisation of ap_info.
     * The verifier requires that the entire value be initialised before
     * passing its address to bpf_map_update_elem — partial initialisation
     * can leave stack bytes undefined, which the verifier rejects.
     * Explicit .pad = {0,0,0} ensures all bytes are initialised.
     */
    struct ap_info info = {
        .channel         = cap->channel,
        .channel_util    = cap->channel_util,
        .noise_floor_dbm = cap->noise_floor_dbm,
        .client_count    = cap->client_count,
        .event_flags     = cap->event_flags,
        .pad             = {0, 0, 0},
    };

    bpf_map_update_elem(&ap_state, &ap_id, &info, BPF_ANY);

    /* ── Debug trace ─────────────────────────────────────────────────────── */

    /*
     * bpf_printk writes to /sys/kernel/debug/tracing/trace_pipe.
     * Read with: sudo cat /sys/kernel/debug/tracing/trace_pipe
     *
     * IMPORTANT: bpf_printk supports a maximum of 3 format arguments
     * on kernels before 5.13 (where bpf_trace_vprintk was added).
     * We split into two calls to ensure compatibility with kernel 5.15
     * using older libbpf headers (Ubuntu 22.04 ships libbpf 0.5).
     *
     * Remove these calls in Phase 4 (production build) — bpf_printk
     * adds per-packet overhead and is for development only.
     */
    bpf_printk("RRM rx: ap_id=%u ch=%u util=%u%%\n",
               ap_id, cap->channel, cap->channel_util);

    bpf_printk("RRM rx: noise=%d clients=%u flags=0x%x\n",
               (int)cap->noise_floor_dbm,
               cap->client_count,
               cap->event_flags);

    /* Pass packet through — this program never drops traffic */
    return XDP_PASS;
}

/*
 * License declaration — required by the BPF verifier.
 * GPL is needed to access GPL-only kernel helpers.
 */
char LICENSE[] SEC("license") = "GPL";