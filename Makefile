# ─────────────────────────────────────────────────────────────────────────────
# ebpf-rrm-engine/Makefile — Phase 3
#
# Changes from Phase 2:
#   make run           → launches full TUI dashboard
#   make run-headless  → no TUI, prints to stdout (useful over SSH)
#   make ctl-*         → control CLI shortcuts
#   make metrics       → curl the Prometheus endpoint
# ─────────────────────────────────────────────────────────────────────────────

ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    BPF_ARCH := arm64
else ifeq ($(ARCH),x86_64)
    BPF_ARCH := x86
else
    $(error [!] Unsupported architecture: $(ARCH))
endif

LINUX_INC := /usr/include/$(ARCH)-linux-gnu
CLANG     := clang
BPFTOOL   := bpftool
GO        := /usr/local/go/bin/go

KERN_SRC  := kern/rrm_xdp.c
KERN_OBJ  := kern/rrm_xdp.o
AGENT_BIN := rrm-agent
AGENT_DIR := ./agent

INCLUDES := -I./kern -I./proto -I$(LINUX_INC)

CFLAGS := \
    -O2 -g -Wall \
    -target bpf \
    -D__TARGET_ARCH_$(BPF_ARCH) \
    $(INCLUDES)

.PHONY: all vmlinux agent run run-headless load unload verify maps \
        gen-normal gen-dfs gen-spike \
        ctl-get-state ctl-get-thresholds ctl-set-threshold \
        metrics clean help

all: $(KERN_OBJ) agent

# ── BPF compilation ───────────────────────────────────────────────────────────

$(KERN_OBJ): $(KERN_SRC) kern/vmlinux.h kern/rrm_maps.h proto/capwap_lite.h
	@echo "[*] Compiling $(KERN_SRC) → $(KERN_OBJ) (arch=$(BPF_ARCH))"
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "[+] BPF object compiled"
	@readelf -S $@ | grep -E 'xdp|maps|license|BTF' || true

vmlinux:
	@test -f /sys/kernel/btf/vmlinux || \
	    (echo "[!] /sys/kernel/btf/vmlinux missing" && exit 1)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kern/vmlinux.h
	@echo "[+] Generated kern/vmlinux.h ($$(wc -l < kern/vmlinux.h) lines)"

# ── Go agent ──────────────────────────────────────────────────────────────────

agent:
	@echo "[*] Building Go agent..."
	cd $(AGENT_DIR) && $(GO) mod tidy && $(GO) build -o ../$(AGENT_BIN) .
	@echo "[+] Built ./$(AGENT_BIN)"

# Full TUI dashboard mode (default)
run: all
	@echo "[*] Starting agent with TUI dashboard (press 'q' to quit)..."
	sudo ./$(AGENT_BIN) --iface veth0

# Headless mode — useful over SSH or for scripted testing
run-headless: all
	@echo "[*] Starting agent in headless mode..."
	sudo ./$(AGENT_BIN) --iface veth0 --no-dashboard

# ── Standalone XDP load ───────────────────────────────────────────────────────
# For testing the XDP program without the Go agent

load: $(KERN_OBJ)
	sudo ip link set dev veth0 xdpgeneric obj $(KERN_OBJ) sec xdp
	@echo "[+] XDP loaded"

unload:
	-sudo ip link set dev veth0 xdpgeneric off
	@echo "[+] Detached"

# ── BPF inspection ────────────────────────────────────────────────────────────

verify:
	@sudo $(BPFTOOL) prog show
	@echo ""
	@sudo $(BPFTOOL) map show

maps:
	@sudo bash scripts/read_maps.sh

# ── Prometheus metrics ────────────────────────────────────────────────────────
# Run while agent is running in another terminal

metrics:
	@echo "[*] Fetching metrics from http://localhost:9090/metrics"
	@curl -s http://localhost:9090/metrics | grep -E '^rrm_' | head -40 || \
	    echo "[!] Agent not running or metrics not available"

# ── Traffic generator shortcuts ───────────────────────────────────────────────
# Run in a separate terminal while agent is running

gen-normal:
	sudo python3 gen/capwap_gen.py --mode normal --num-aps 5 --interval 1.0

gen-dfs:
	sudo python3 gen/capwap_gen.py --mode dfs --num-aps 5 --target-ap 3 --delay 5

gen-spike:
	sudo python3 gen/capwap_gen.py --mode spike --num-aps 5 --target-ap 3 --spike-util 92

# ── Control CLI shortcuts ─────────────────────────────────────────────────────
# Requires agent to be running (it must have loaded the BPF object)

ctl-get-state:
	sudo ./$(AGENT_BIN) ctl get-state

ctl-get-thresholds:
	sudo ./$(AGENT_BIN) ctl get-thresholds

# Usage: make ctl-set-threshold ARGS="--util-high 75 --util-consec 2"
ctl-set-threshold:
	sudo ./$(AGENT_BIN) ctl set-threshold $(ARGS)

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	@rm -f $(KERN_OBJ) $(AGENT_BIN)
	@echo "[+] Cleaned"

help:
	@echo "Phase 3 targets:"
	@echo "  make vmlinux          generate kern/vmlinux.h (once)"
	@echo "  make                  compile BPF + build Go agent"
	@echo "  make run              sudo: TUI dashboard mode"
	@echo "  make run-headless     sudo: headless / SSH mode"
	@echo "  make gen-normal       run traffic generator (normal)"
	@echo "  make gen-dfs          run traffic generator (DFS event)"
	@echo "  make gen-spike        run traffic generator (load spike)"
	@echo "  make metrics          curl Prometheus metrics endpoint"
	@echo "  make ctl-get-state    print AP state from BPF map"
	@echo "  make ctl-get-thresholds print threshold config"
	@echo "  make ctl-set-threshold ARGS='--util-high 75'  update thresholds live"
	@echo "  make verify           show loaded programs + maps"
	@echo "  make maps             pretty-print BPF map contents"
	@echo "  make clean            remove build artifacts"