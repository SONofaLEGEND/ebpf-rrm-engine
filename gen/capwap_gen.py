#!/usr/bin/env python3
"""
gen/capwap_gen.py — Synthetic CAPWAP-lite traffic generator

Requires root (raw socket access for Scapy sendp).
Run as: sudo python3 gen/capwap_gen.py [--mode normal] [--num-aps 5] [--interval 1.0]

Packet structure (on the wire):
    Ethernet / IPv4 / UDP(dport=9000) / capwap_lite_hdr (12 bytes)

Sends on veth1 (10.0.0.2 → 10.0.0.1), XDP reads on veth0.
"""

import sys
import os
import struct
import time
import random
import argparse

# ── Root check ───────────────────────────────────────────────────────────────
if os.geteuid() != 0:
    print("[!] Requires root for raw socket access.", file=sys.stderr)
    print("[!] Run: sudo python3 gen/capwap_gen.py", file=sys.stderr)
    sys.exit(1)

# Import Scapy after root check (avoids spurious warning output)
from scapy.all import (
    Ether, IP, UDP, Raw,
    sendp, get_if_hwaddr,
)

# ── Wire constants ────────────────────────────────────────────────────────────
CAPWAP_LITE_PORT = 9000    # UDP destination port (matches kern/rrm_maps.h)

# Interface names (must match the veth pair created in Step 0)
SRC_IFACE = "veth1"        # Send FROM here
DST_IFACE = "veth0"        # XDP is attached here

SRC_IP = "10.0.0.2"       # veth1 address
DST_IP = "10.0.0.1"       # veth0 address (where packets arrive)

# ── Channel sets ─────────────────────────────────────────────────────────────
CHANNELS_2G = [1, 6, 11]
CHANNELS_5G = [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161]

# ── Struct packing ────────────────────────────────────────────────────────────
#
# Matches struct capwap_lite_hdr in proto/capwap_lite.h exactly.
# Format string breakdown (! = network/big-endian byte order):
#   I  = unsigned int  (4 bytes) → ap_id
#   B  = unsigned char (1 byte)  → channel
#   B  = unsigned char (1 byte)  → channel_util
#   b  = signed char   (1 byte)  → noise_floor_dbm  ← signed!
#   B  = unsigned char (1 byte)  → client_count
#   B  = unsigned char (1 byte)  → event_flags
#   3s = 3-byte string           → pad[3]
# Total: 4+1+1+1+1+1+3 = 12 bytes
#
CAPWAP_FMT = "!IBBbBB3s"
CAPWAP_SIZE = struct.calcsize(CAPWAP_FMT)  # should be 12
assert CAPWAP_SIZE == 12, f"Struct size mismatch: {CAPWAP_SIZE} != 12"


def build_capwap_payload(
    ap_id: int,
    channel: int,
    channel_util: int,
    noise_floor_dbm: int,
    client_count: int,
    event_flags: int = 0,
) -> bytes:
    """
    Pack a capwap_lite_hdr payload.

    Args:
        ap_id:           AP identifier (uint32, 1–65535)
        channel:         802.11 channel (uint8, 1–165)
        channel_util:    utilisation percent (uint8, 0–100)
        noise_floor_dbm: noise floor dBm (int8, -100 to 0)
        client_count:    associated clients (uint8, 0–255)
        event_flags:     CAPWAP_EVENT_* flags (uint8)

    Returns:
        12-byte packed bytes ready to use as UDP payload.
    """
    return struct.pack(
        CAPWAP_FMT,
        ap_id,
        channel,
        channel_util,
        noise_floor_dbm,   # signed — struct 'b' handles this correctly
        client_count,
        event_flags,
        b'\x00\x00\x00',  # pad[3]
    )


# ── Simulated AP ──────────────────────────────────────────────────────────────

class SimulatedAP:
    """
    Models one AP producing periodic RF telemetry.

    RF parameters drift by small random amounts each tick to simulate
    a real environment — clients join/leave, interference appears/clears,
    etc. All values are bounded to realistic ranges.
    """

    def __init__(self, ap_id: int, channel: int):
        self.ap_id           = ap_id
        self.channel         = channel
        self.channel_util    = random.randint(20, 55)    # percent
        self.noise_floor_dbm = random.randint(-92, -72)  # dBm, signed
        self.client_count    = random.randint(5, 20)
        self.event_flags     = 0x00

    def tick(self) -> None:
        """Drift RF parameters by small random amounts."""
        # Channel utilisation: drift ±5%, clamp to [5, 90]
        self.channel_util = max(5, min(90,
            self.channel_util + random.randint(-5, 5)))

        # Noise floor: drift ±2 dBm, clamp to [-100, -60] dBm
        self.noise_floor_dbm = max(-100, min(-60,
            self.noise_floor_dbm + random.randint(-2, 2)))

        # Client count: drift ±2, clamp to [1, 30]
        self.client_count = max(1, min(30,
            self.client_count + random.randint(-2, 2)))

    def payload(self) -> bytes:
        """Build wire-format CAPWAP-lite payload for this AP's current state."""
        return build_capwap_payload(
            ap_id           = self.ap_id,
            channel         = self.channel,
            channel_util    = self.channel_util,
            noise_floor_dbm = self.noise_floor_dbm,
            client_count    = self.client_count,
            event_flags     = self.event_flags,
        )

    def status_line(self) -> str:
        return (
            f"AP{self.ap_id:03d}: "
            f"ch={self.channel:3d} "
            f"util={self.channel_util:3d}% "
            f"noise={self.noise_floor_dbm:4d}dBm "
            f"clients={self.client_count:2d} "
            f"flags={self.event_flags:#04x}"
        )


# ── Packet builder ─────────────────────────────────────────────────────────────

def build_frame(src_mac: str, dst_mac: str, sport: int, payload: bytes) -> Ether:
    """
    Build a complete L2 Ethernet frame carrying a CAPWAP-lite payload.

    Uses sendp() (L2 send) instead of send() (L3 send) for explicit
    control over the Ethernet header. On a directly-connected veth pair,
    the destination MAC is known without ARP.
    """
    return (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=SRC_IP, dst=DST_IP, ttl=64) /
        UDP(sport=sport, dport=CAPWAP_LITE_PORT) /
        Raw(load=payload)
    )


# ── Normal mode ────────────────────────────────────────────────────────────────

def run_normal(num_aps: int, interval: float) -> None:
    """
    Steady-state mode: send one telemetry packet per AP per interval.

    Simulates the periodic CAPWAP RF measurement reports that real APs
    send to their WLC. RF parameters drift each tick to exercise the
    EWMA state tracking in the XDP program (Phase 2).

    Runs indefinitely until Ctrl+C.
    """
    print(f"[*] Mode: normal | APs: {num_aps} | interval: {interval}s")
    print(f"[*] {SRC_IFACE} ({SRC_IP}) → {DST_IFACE} ({DST_IP}:{CAPWAP_LITE_PORT})")

    # Resolve MAC addresses for veth pair.
    # get_if_hwaddr reads from /sys/class/net/<iface>/address.
    try:
        src_mac = get_if_hwaddr(SRC_IFACE)
        dst_mac = get_if_hwaddr(DST_IFACE)
    except Exception as exc:
        print(f"[!] Failed to get MAC addresses: {exc}", file=sys.stderr)
        print(f"[!] Check that {SRC_IFACE} and {DST_IFACE} are UP:", file=sys.stderr)
        print(f"[!]   ip link show {SRC_IFACE}", file=sys.stderr)
        print(f"[!]   ip link show {DST_IFACE}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] src MAC ({SRC_IFACE}): {src_mac}")
    print(f"[*] dst MAC ({DST_IFACE}): {dst_mac}")

    # Assign channels to APs, cycling through 2.4GHz and 5GHz.
    # Real deployments interleave bands; we mirror that here.
    all_channels = CHANNELS_2G + CHANNELS_5G
    aps = [
        SimulatedAP(
            ap_id   = i + 1,
            channel = all_channels[i % len(all_channels)]
        )
        for i in range(num_aps)
    ]

    print("\n[*] Initial AP configuration:")
    for ap in aps:
        print(f"    {ap.status_line()}")
    print(f"\n[*] Sending... Ctrl+C to stop\n")

    tick       = 0
    total_pkts = 0

    try:
        while True:
            tick      += 1
            tick_pkts  = 0

            for ap in aps:
                ap.tick()

                sport = random.randint(1024, 65535)
                frame = build_frame(src_mac, dst_mac, sport, ap.payload())
                sendp(frame, iface=SRC_IFACE, verbose=False)
                tick_pkts += 1

            total_pkts += tick_pkts

            # Print status every 5 ticks so the terminal stays readable
            if tick % 5 == 0:
                print(f"── tick {tick:04d} | sent {total_pkts} pkts total ─────────────")
                for ap in aps:
                    print(f"  {ap.status_line()}")

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Total: {tick} ticks, {total_pkts} packets sent.")
        print(f"[*] Run 'make maps' to inspect BPF map state.")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CAPWAP-lite synthetic traffic generator — ebpf-rrm-engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "dfs", "spike"],
        default="normal",
        help="Traffic mode: normal=steady telemetry, dfs=radar event (Phase 2), spike=load anomaly (Phase 2)",
    )
    parser.add_argument(
        "--num-aps",
        type=int,
        default=5,
        metavar="N",
        help="Number of simulated APs",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        metavar="SEC",
        help="Seconds between telemetry rounds",
    )
    args = parser.parse_args()

    if args.num_aps < 1 or args.num_aps > 512:
        print("[!] --num-aps must be between 1 and 512", file=sys.stderr)
        sys.exit(1)

    if args.interval < 0.1:
        print("[!] --interval must be >= 0.1 seconds", file=sys.stderr)
        sys.exit(1)

    if args.mode == "normal":
        run_normal(num_aps=args.num_aps, interval=args.interval)
    else:
        print(f"[!] Mode '{args.mode}' is implemented in Phase 2.", file=sys.stderr)
        print(f"[!] Available now: --mode normal", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()