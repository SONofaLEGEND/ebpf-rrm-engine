#!/usr/bin/env python3
"""
gen/capwap_gen.py — Phase 2: all three traffic modes

Modes:
  --mode normal   steady-state telemetry (Phase 1, unchanged)
  --mode dfs      injects a radar detection event on one AP after a delay
  --mode spike    ramps channel_util of one AP to trigger load anomaly detection

Run as: sudo python3 gen/capwap_gen.py --mode [normal|dfs|spike] [options]

Phase 2 milestone tests:
  DFS:   sudo python3 gen/capwap_gen.py --mode dfs --target-ap 2 --delay 5
         → After 5s: AP2 emits one packet with CAPWAP_EVENT_RADAR set.
         → Go agent should print a DFS event within 1 packet interval.

  Spike: sudo python3 gen/capwap_gen.py --mode spike --target-ap 3 --spike-util 92
         → AP3 util ramps from baseline to 92% over 10 packets.
         → Go agent should print a LOAD_ANOMALY event after 3 consecutive
           packets above the 85% threshold.
"""

import sys
import os
import struct
import time
import random
import argparse

if os.geteuid() != 0:
    print("[!] Requires root. Run: sudo python3 gen/capwap_gen.py", file=sys.stderr)
    sys.exit(1)

from scapy.all import Ether, IP, UDP, Raw, sendp, get_if_hwaddr

# ── Wire constants ────────────────────────────────────────────────────────────

CAPWAP_LITE_PORT = 9000
SRC_IFACE        = "veth1"
DST_IFACE        = "veth0"
SRC_IP           = "10.0.0.2"
DST_IP           = "10.0.0.1"

# event_flags bit definitions (must match proto/capwap_lite.h)
CAPWAP_EVENT_NONE  = 0x00
CAPWAP_EVENT_RADAR = 0x01

# Channel sets
CHANNELS_2G = [1, 6, 11]
CHANNELS_5G = [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161]

# Struct format: matches struct capwap_lite_hdr exactly
# ! = big-endian (network byte order)
# I  = uint32  ap_id
# B  = uint8   channel
# B  = uint8   channel_util
# b  = int8    noise_floor_dbm  (SIGNED)
# B  = uint8   client_count
# B  = uint8   event_flags
# 3s = 3 bytes pad[3]
CAPWAP_FMT  = "!IBBbBB3s"
CAPWAP_SIZE = struct.calcsize(CAPWAP_FMT)
assert CAPWAP_SIZE == 12, f"Struct size mismatch: {CAPWAP_SIZE}"


def build_payload(ap_id, channel, channel_util, noise_floor_dbm,
                  client_count, event_flags=0):
    return struct.pack(
        CAPWAP_FMT,
        ap_id,
        channel,
        channel_util,
        noise_floor_dbm,
        client_count,
        event_flags,
        b'\x00\x00\x00',
    )


def get_macs():
    """Resolve MAC addresses for the veth pair. Exits on failure."""
    try:
        src_mac = get_if_hwaddr(SRC_IFACE)
        dst_mac = get_if_hwaddr(DST_IFACE)
        return src_mac, dst_mac
    except Exception as exc:
        print(f"[!] MAC lookup failed: {exc}", file=sys.stderr)
        print(f"[!] Ensure veth pair is up:", file=sys.stderr)
        print(f"[!]   sudo ip link set {SRC_IFACE} up", file=sys.stderr)
        print(f"[!]   sudo ip link set {DST_IFACE} up", file=sys.stderr)
        sys.exit(1)


def build_frame(src_mac, dst_mac, payload):
    sport = random.randint(1024, 65535)
    return (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=SRC_IP, dst=DST_IP, ttl=64) /
        UDP(sport=sport, dport=CAPWAP_LITE_PORT) /
        Raw(load=payload)
    )


# ── SimulatedAP ────────────────────────────────────────────────────────────────

class SimulatedAP:
    """Models one AP producing periodic RF telemetry with realistic drift."""

    def __init__(self, ap_id, channel):
        self.ap_id           = ap_id
        self.channel         = channel
        self.channel_util    = random.randint(20, 55)
        self.noise_floor_dbm = random.randint(-92, -72)
        self.client_count    = random.randint(5, 20)
        self.event_flags     = CAPWAP_EVENT_NONE

    def tick(self):
        self.channel_util    = max(5,    min(90,  self.channel_util + random.randint(-5, 5)))
        self.noise_floor_dbm = max(-100, min(-60, self.noise_floor_dbm + random.randint(-2, 2)))
        self.client_count    = max(1,    min(30,  self.client_count + random.randint(-2, 2)))
        self.event_flags     = CAPWAP_EVENT_NONE   # cleared each tick unless overridden

    def payload(self):
        return build_payload(
            self.ap_id, self.channel, self.channel_util,
            self.noise_floor_dbm, self.client_count, self.event_flags,
        )

    def status(self):
        flags = f"RADAR" if self.event_flags & CAPWAP_EVENT_RADAR else "----"
        return (f"AP{self.ap_id:03d}: ch={self.channel:3d} "
                f"util={self.channel_util:3d}% "
                f"ewma≈{self.channel_util:3d}% "
                f"noise={self.noise_floor_dbm:4d}dBm "
                f"clients={self.client_count:2d} [{flags}]")


def make_aps(num_aps):
    all_channels = CHANNELS_2G + CHANNELS_5G
    return [SimulatedAP(i + 1, all_channels[i % len(all_channels)])
            for i in range(num_aps)]


# ── Mode: normal ───────────────────────────────────────────────────────────────

def run_normal(num_aps, interval):
    """Steady-state periodic telemetry for all APs. Unchanged from Phase 1."""
    print(f"[*] Mode: normal | APs: {num_aps} | interval: {interval}s")
    src_mac, dst_mac = get_macs()
    aps  = make_aps(num_aps)
    tick = 0

    print("\n[*] Initial state:")
    for ap in aps:
        print(f"    {ap.status()}")
    print("\n[*] Sending... Ctrl+C to stop\n")

    try:
        while True:
            tick += 1
            for ap in aps:
                ap.tick()
                sendp(build_frame(src_mac, dst_mac, ap.payload()),
                      iface=SRC_IFACE, verbose=False)
            if tick % 5 == 0:
                print(f"── tick {tick:04d} ───────────────────────────────────────")
                for ap in aps:
                    print(f"  {ap.status()}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped after {tick} ticks.")


# ── Mode: dfs ─────────────────────────────────────────────────────────────────

def run_dfs(num_aps, interval, target_ap_id, delay):
    """
    Normal traffic for `delay` seconds, then inject a radar detection event
    on target_ap_id. The event lasts exactly ONE packet (event_flags is
    cleared the next tick). This mirrors real AP behaviour: the AP sends a
    single CAPWAP radar notification, not a sustained flag.

    Expected Go agent output:
        [EVENT] DFS       AP:002 ch:6 util:43% noise:-82dBm
    """
    if target_ap_id < 1 or target_ap_id > num_aps:
        print(f"[!] --target-ap must be 1–{num_aps}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Mode: dfs | APs: {num_aps} | interval: {interval}s")
    print(f"[*] Radar event on AP{target_ap_id:03d} in {delay}s")
    src_mac, dst_mac = get_macs()
    aps       = make_aps(num_aps)
    tick      = 0
    radar_sent = False
    start_time = time.monotonic()

    print("\n[*] Sending normal traffic... radar injection incoming\n")

    try:
        while True:
            tick += 1
            elapsed = time.monotonic() - start_time

            for ap in aps:
                ap.tick()

                # Inject radar on target AP when delay expires (once only)
                if (ap.ap_id == target_ap_id and
                        elapsed >= delay and not radar_sent):
                    ap.event_flags = CAPWAP_EVENT_RADAR
                    print(f"\n[!] INJECTING RADAR on AP{target_ap_id:03d} "
                          f"(tick {tick}, t={elapsed:.1f}s)")
                    radar_sent = True

                sendp(build_frame(src_mac, dst_mac, ap.payload()),
                      iface=SRC_IFACE, verbose=False)

            if tick % 5 == 0 or (radar_sent and tick % 2 == 0):
                print(f"── tick {tick:04d} | t={elapsed:.1f}s ──────────────")
                for ap in aps:
                    print(f"  {ap.status()}")

            # Stop 5 ticks after radar injection so output is readable
            if radar_sent and tick > 5:
                extra_ticks = 0
                for _ in range(5):
                    extra_ticks += 1
                    tick += 1
                    for ap in aps:
                        ap.tick()
                        sendp(build_frame(src_mac, dst_mac, ap.payload()),
                              iface=SRC_IFACE, verbose=False)
                    time.sleep(interval)
                print(f"\n[*] DFS test complete. Check agent output for RRM_EVENT_DFS.")
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Stopped.")


# ── Mode: spike ────────────────────────────────────────────────────────────────

def run_spike(num_aps, interval, target_ap_id, spike_util):
    """
    Gradually ramps channel_util of target_ap_id from its baseline to
    spike_util over 10 packets, then holds it there for another 5 packets.

    With default thresholds (util_high=85, util_consec=3):
    - When spike_util >= 85, the EWMA will exceed 85 after a few packets.
    - The XDP EWMA (alpha=0.25) lags the raw value, so the consecutive
      threshold will be crossed approximately 3–5 packets after the raw
      util exceeds 85%.
    - Expected: LOAD_ANOMALY event emitted by the agent.

    Timeline example (baseline=40%, spike=92%, alpha=0.25):
      Packet  Raw   EWMA (approx)   consec_high
      1       40    40              0
      2       55    43              0
      3       70    47              0
      4       85    55              0
      5       92    63              0
      6       92    70              0
      7       92    76              0
      8       92    80              0
      9       92    84              0      ← approaching threshold
      10      92    86              1      ← first high
      11      92    87              2
      12      92    88              3      ← LOAD_ANOMALY EMITTED
    """
    if target_ap_id < 1 or target_ap_id > num_aps:
        print(f"[!] --target-ap must be 1–{num_aps}", file=sys.stderr)
        sys.exit(1)
    if spike_util < 85 or spike_util > 100:
        print("[!] --spike-util should be >= 85 to trigger the default threshold",
              file=sys.stderr)

    print(f"[*] Mode: spike | APs: {num_aps} | interval: {interval}s")
    print(f"[*] Ramping AP{target_ap_id:03d} util to {spike_util}% over 10 packets")
    print(f"[*] Expected: LOAD_ANOMALY after ~3 packets above EWMA threshold\n")

    src_mac, dst_mac = get_macs()
    aps  = make_aps(num_aps)
    tick = 0

    # Find target AP and record its baseline
    target = next(ap for ap in aps if ap.ap_id == target_ap_id)
    baseline_util = target.channel_util
    print(f"[*] AP{target_ap_id:03d} baseline util: {baseline_util}%")

    # Ramp schedule: 10 steps from baseline to spike_util
    ramp_steps = [
        int(baseline_util + (spike_util - baseline_util) * i / 9)
        for i in range(10)
    ]
    # Hold for 10 more packets at spike_util
    hold_steps = [spike_util] * 10
    schedule   = ramp_steps + hold_steps
    sched_idx  = 0
    ramping    = True

    print(f"[*] Ramp schedule: {ramp_steps}")
    print(f"[*] Sending... Ctrl+C to stop\n")

    try:
        while True:
            tick += 1

            for ap in aps:
                ap.tick()

                # Override target AP's util per schedule
                if ap.ap_id == target_ap_id and sched_idx < len(schedule):
                    ap.channel_util = schedule[sched_idx]

                sendp(build_frame(src_mac, dst_mac, ap.payload()),
                      iface=SRC_IFACE, verbose=False)

            # Advance schedule on target AP
            if sched_idx < len(schedule):
                sched_idx += 1
                if sched_idx == len(ramp_steps):
                    print(f"\n[*] Ramp complete. Holding at {spike_util}% "
                          f"for {len(hold_steps)} more packets.")
                    ramping = False

            # Print status every tick during ramp, every 3 during hold
            if ramping or tick % 3 == 0:
                print(f"── tick {tick:04d} ───────────────────────────────────")
                for ap in aps:
                    marker = " ←TARGET" if ap.ap_id == target_ap_id else ""
                    print(f"  {ap.status()}{marker}")

            # End after full schedule
            if sched_idx >= len(schedule):
                print(f"\n[*] Spike test complete. Check agent output for "
                      f"RRM_EVENT_LOAD_ANOMALY.")
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Stopped after {tick} ticks.")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CAPWAP-lite generator — ebpf-rrm-engine Phase 2",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", choices=["normal", "dfs", "spike"],
                        default="normal")
    parser.add_argument("--num-aps", type=int, default=5, metavar="N")
    parser.add_argument("--interval", type=float, default=1.0, metavar="SEC")
    parser.add_argument("--target-ap", type=int, default=1, metavar="AP_ID",
                        help="AP to target for dfs/spike modes")
    parser.add_argument("--delay", type=float, default=5.0, metavar="SEC",
                        help="Seconds before DFS injection (dfs mode)")
    parser.add_argument("--spike-util", type=int, default=92, metavar="PCT",
                        help="Target utilisation percent for spike mode (85–100)")

    args = parser.parse_args()

    if args.mode == "normal":
        run_normal(args.num_aps, args.interval)
    elif args.mode == "dfs":
        run_dfs(args.num_aps, args.interval, args.target_ap, args.delay)
    elif args.mode == "spike":
        run_spike(args.num_aps, args.interval, args.target_ap, args.spike_util)


if __name__ == "__main__":
    main()