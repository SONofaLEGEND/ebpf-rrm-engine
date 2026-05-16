#!/usr/bin/env bash
# scripts/read_maps.sh
#
# Pretty-prints the BPF map contents for ebpf-rrm-engine.
# Requires: bpftool, python3
# Run via: make maps   OR   sudo bash scripts/read_maps.sh

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run as root: sudo bash scripts/read_maps.sh" >&2
    exit 1
fi

# Check the XDP program is loaded (maps only exist when program is running)
if ! bpftool map show name ap_pkt_count &>/dev/null; then
    echo "[!] BPF maps not found. Load the XDP program first:"
    echo "[!]   make load"
    exit 1
fi

# Use a temporary file for map data to avoid stdin conflicts with python heredoc
MAP_DATA=$(mktemp)
trap 'rm -f "$MAP_DATA"' EXIT

echo ""
echo "━━━ ap_pkt_count (packet counter per AP) ━━━━━━━━━━━━━━━━━━━━━━━━━━━"

bpftool map dump name ap_pkt_count -j > "$MAP_DATA"
python3 - "$MAP_DATA" << 'PYEOF'
import json, sys

try:
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    print("  (no data)")
    sys.exit(0)

if not data:
    print("  (empty — send some traffic first)")
    sys.exit(0)

# If bpftool finds multiple maps with the same name, it returns a list of map objects,
# each containing an 'elements' list. If it finds one, it returns the elements list directly.
if isinstance(data, list) and len(data) > 0 and 'elements' in data[0]:
    all_elements = []
    for m in data:
        all_elements.extend(m['elements'])
else:
    all_elements = data

if not all_elements:
    print("  (empty — send some traffic first)")
    sys.exit(0)

entries = {} # Use dict to merge duplicates if multiple maps exist
for entry in all_elements:
    if "formatted" in entry:
        ap_id = entry["formatted"]["key"]
        count = entry["formatted"]["value"]
    else:
        ap_id = int.from_bytes([int(x, 16) for x in entry["key"]], byteorder="little")
        count = int.from_bytes([int(x, 16) for x in entry["value"]], byteorder="little")
    
    # If multiple maps exist, sum the counts (or just take the latest)
    # Here we take the max to handle stale maps from previous loads
    entries[ap_id] = max(entries.get(ap_id, 0), count)

print(f"  {'AP ID':>6} | {'Packets':>10}")
print(f"  {'-'*6}-+-{'-'*10}")
for ap_id in sorted(entries.keys()):
    print(f"  {ap_id:>6} | {entries[ap_id]:>10}")
PYEOF

echo ""
echo "━━━ ap_state (RF telemetry snapshot per AP) ━━━━━━━━━━━━━━━━━━━━━━━━"

bpftool map dump name ap_state -j > "$MAP_DATA"
python3 - "$MAP_DATA" << 'PYEOF'
import json, sys

try:
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    print("  (no data)")
    sys.exit(0)

if not data:
    print("  (empty — send some traffic first)")
    sys.exit(0)

if isinstance(data, list) and len(data) > 0 and 'elements' in data[0]:
    all_elements = []
    for m in data:
        all_elements.extend(m['elements'])
else:
    all_elements = data

if not all_elements:
    print("  (empty — send some traffic first)")
    sys.exit(0)

def signed_byte(b: int) -> int:
    return b if b < 128 else b - 256

entries = {}
for entry in all_elements:
    if "formatted" in entry:
        f = entry["formatted"]
        ap_id   = f["key"]
        v       = f["value"]
        channel = v["channel"]
        util    = v["channel_util"]
        noise   = v["noise_floor_dbm"]
        clients = v["client_count"]
        flags   = v["event_flags"]
    else:
        ap_id   = int.from_bytes([int(x, 16) for x in entry["key"]], byteorder="little")
        v       = [int(x, 16) for x in entry["value"]]
        channel = v[0]
        util    = v[1]
        noise   = signed_byte(v[2])
        clients = v[3]
        flags   = v[4]
    
    # Store latest state (overwrite if duplicates exist)
    entries[ap_id] = (channel, util, noise, clients, flags)

print(f"  {'AP':>4} | {'Ch':>4} | {'Util%':>6} | {'Noise dBm':>10} | {'Clients':>8} | {'Flags':>8}")
print(f"  {'-'*4}-+-{'-'*4}-+-{'-'*6}-+-{'-'*10}-+-{'-'*8}-+-{'-'*8}")
for ap_id in sorted(entries.keys()):
    ch, util, noise, clients, flags = entries[ap_id]
    flag_str = f"{flags:#010b}"
    print(f"  {ap_id:>4} | {ch:>4} | {util:>5}% | {noise:>8}dBm | {clients:>8} | {flag_str}")
PYEOF

echo ""
echo "━━━ BPF program info ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
bpftool prog show name rrm_xdp_parser 2>/dev/null || echo "  (no program named rrm_xdp_parser found)"
echo ""