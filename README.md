# ebpf-rrm-engine

**Near-Real-Time Radio Resource Management (RRM) Telemetry Engine using eBPF (XDP) and Go.**

This project demonstrates how **eBPF (Extended Berkeley Packet Filter)** can be used to accelerate Wi-Fi telemetry processing by moving critical event detection into the Linux kernel's fast path. By using XDP (eXpress Data Path) to parse packets at line rate, we can achieve sub-millisecond reaction times for regulatory events (like DFS radar detection) and load anomalies, completely bypassing the traditional slow control-plane polling cycle.

## Architecture

The system implements the control-plane/data-plane separation model using eBPF and Go:

1. **Data Plane (eBPF XDP):** 
   - A custom XDP program (`kern/rrm_xdp.c`) runs directly on the network interface card driver.
   - It parses incoming `CAPWAP-lite` UDP telemetry packets from APs.
   - It maintains per-AP RF state in eBPF Hash Maps.
   - It computes a fixed-point Q8 Exponentially Weighted Moving Average (EWMA) of channel utilisation to filter out noise without floating-point overhead.
   - It detects threshold violations and pushes them to a BPF Ring Buffer.

2. **Control Plane (Go Agent):**
   - The Go daemon (`agent/main.go`) acts as the SDN controller.
   - **Fast-Loop Goroutine:** Consumes events from the ring buffer in real-time (~1ms latency).
   - **Slow-Loop Goroutine:** Periodically polls the state maps for telemetry snapshots (e.g. 500ms).
   - **Dynamic Reconfiguration:** Writes thresholds directly into BPF maps without recompiling the XDP program.

## Key Metrics (Benchmark)

Running the automated benchmark suite (`make benchmark`) demonstrates the architectural advantage:

- **BPF Instruction Count:** 147 instructions (highly optimized).
- **Fast-Loop Latency:** ~1.2ms (kernel-to-userspace delivery).
- **Speed Advantage:** ~400x faster than a 500ms polling cycle, and ~600,000x faster than a traditional 10-minute WLC RRM cycle.

## Quick Start (Ubuntu 22.04+)

### 1. Install Dependencies
```bash
make install-deps
```

### 2. Generate BTF and Compile
```bash
make vmlinux
make
```

### 3. Run the Agent (TUI Mode)
```bash
sudo make run
```

### 4. Run Traffic Simulation
In a separate terminal, inject synthetic AP traffic:
```bash
# Normal steady-state traffic
sudo make gen-normal

# Inject a DFS Radar event on AP 2
sudo make gen-dfs

# Inject a Load Anomaly Spike on AP 3
sudo make gen-spike
```

### 5. Live Control CLI
You can inspect the BPF maps or modify thresholds dynamically while the agent is running:
```bash
sudo ./rrm-agent ctl get-state
sudo ./rrm-agent ctl get-thresholds
sudo ./rrm-agent ctl set-threshold --util-high 70 --util-consec 2
```

## Features

- **DFS Radar Detection:** Bypasses EWMA and consecutive checks, alerting userspace instantly when `CAPWAP_EVENT_RADAR` is flagged on DFS channels.
- **Load Anomaly Detection:** Utilises EWMA smoothing and consecutive-packet guards to prevent transient spikes from triggering false topology changes.
- **Noise Spike Detection:** Tracks delta changes between packets to identify sudden RF interference (e.g. microwaves).
- **Live Observability:** TUI Dashboard (`tview`) and Prometheus metrics endpoint at `:9090`.
- **Pinned Maps:** Map persistence in `/sys/fs/bpf/rrm/` allows external CLI access.

## Testing

Run the automated benchmark suite:
```bash
sudo make benchmark
```

