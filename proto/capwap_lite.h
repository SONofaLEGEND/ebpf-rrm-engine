/* SPDX-License-Identifier: GPL-2.0 */
/*
 * proto/capwap_lite.h
 *
 * Synthetic CAPWAP-lite protocol definition.
 *
 * This is NOT the real CAPWAP protocol (RFC 5415). It is a minimal,
 * purpose-built header that carries the RF telemetry fields we need
 * for the RRM fast-loop engine. Carried over UDP/9000.
 *
 * Used by:
 *   kern/rrm_xdp.c     — XDP parser (kernel, C)
 *   gen/capwap_gen.py  — traffic generator (userspace, Python)
 *
 * Wire layout (12 bytes, network byte order, packed):
 *   Offset  Size  Field
 *   ──────  ────  ─────────────────────────────────────────────────
 *   0       4     ap_id            AP identifier (unique per AP)
 *   4       1     channel          802.11 channel number (1–165)
 *   5       1     channel_util     Channel utilisation 0–100 (percent)
 *   6       1     noise_floor_dbm  Noise floor in dBm (-100 to 0, signed)
 *   7       1     client_count     Number of associated clients (0–255)
 *   8       1     event_flags      Bit field (see EVENT_* defines below)
 *   9       3     pad              Reserved, must be zero
 *
 * Types (__u8, __u32 etc.) are provided by vmlinux.h in kernel context.
 * The Python generator uses struct.pack("!IBBbBB3s", ...) to match this
 * layout exactly.
 */

#ifndef CAPWAP_LITE_H
#define CAPWAP_LITE_H

/* UDP destination port for CAPWAP-lite traffic */
#define CAPWAP_LITE_PORT   9000

/* event_flags bit definitions */
#define CAPWAP_EVENT_RADAR     (1 << 0)   /* DFS radar detected on channel */
#define CAPWAP_EVENT_RESERVED  (1 << 1)   /* reserved for Phase 2 */

/*
 * capwap_lite_hdr — on-wire header structure.
 *
 * __attribute__((packed)) ensures no compiler padding is inserted.
 * struct size: 4+1+1+1+1+1+3 = 12 bytes exactly.
 */
struct capwap_lite_hdr {
    __u32 ap_id;              /* unique AP identifier, network byte order */
    __u8  channel;            /* 802.11 operating channel */
    __u8  channel_util;       /* channel utilisation, 0–100 percent */
    __s8  noise_floor_dbm;    /* noise floor, signed dBm (-100 to 0) */
    __u8  client_count;       /* number of associated clients */
    __u8  event_flags;        /* CAPWAP_EVENT_* bit flags */
    __u8  pad[3];             /* padding to 12-byte total, must be zero */
} __attribute__((packed));

#endif /* CAPWAP_LITE_H */