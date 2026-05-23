# ─────────────────────────────────────────────────────────────────────────────
# ebpf-rrm-engine/Makefile
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

# Production CFLAGS: -O2 (required for eBPF), -g (BTF debug info for CO-RE)
# -DNDEBUG removes any remaining debug assertions
CFLAGS := \
    -O2 -g -Wall -DNDEBUG \
    -target bpf \
    -D__TARGET_ARCH_$(BPF_ARCH) \
    $(INCLUDES)

.PHONY: all vmlinux agent run run-headless load unload verify maps \
        gen-normal gen-dfs gen-spike \
        ctl-get-state ctl-get-thresholds ctl-set-threshold ctl-get-stats \
        metrics benchmark install-deps clean help

all: $(KERN_OBJ) agent

# ── BPF compilation ───────────────────────────────────────────────────────────

$(KERN_OBJ): $(KERN_SRC) kern/vmlinux.h kern/rrm_maps.h proto/capwap_lite.h
	@echo "[*] Compiling $(KERN_SRC) → $(KERN_OBJ) (arch=$(BPF_ARCH))"
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "[+] Compiled"
	@echo "[*] Checking BTF:"
	@readelf -S $@ | grep -q BTF && echo "[+] BTF present" || echo "[!] BTF missing"
	@echo "[*] Sections:"
	@readelf -S $@ | grep -E 'xdp|maps|license' | awk '{print "    " $$0}'

vmlinux:
	@test -f /sys/kernel/btf/vmlinux || \
	    (echo "[!] /sys/kernel/btf/vmlinux missing — BTF not enabled?" && exit 1)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kern/vmlinux.h
	@echo "[+] Generated kern/vmlinux.h ($$(wc -l < kern/vmlinux.h) lines)"

# ── Go agent ──────────────────────────────────────────────────────────────────

agent:
	@echo "[*] Building Go agent..."
	cd $(AGENT_DIR) && $(GO) mod tidy && $(GO) build -ldflags="-s -w" -o ../$(AGENT_BIN) .
	@echo "[+] Built ./$(AGENT_BIN) ($$(du -sh $(AGENT_BIN) | cut -f1))"

# -ldflags="-s -w": strip debug symbols from the binary (smaller, faster to start)

run: all
	sudo ./$(AGENT_BIN) --iface veth0

run-headless: all
	sudo ./$(AGENT_BIN) --iface veth0 --no-dashboard

# ── Standalone XDP ────────────────────────────────────────────────────────────

load: $(KERN_OBJ)
	sudo ip link set dev veth0 xdpgeneric obj $(KERN_OBJ) sec xdp
	@echo "[+] XDP loaded on veth0"

unload:
	-sudo ip link set dev veth0 xdpgeneric off
	@echo "[+] Detached"

# ── Inspection ────────────────────────────────────────────────────────────────

verify:
	@sudo $(BPFTOOL) prog show
	@echo ""
	@sudo $(BPFTOOL) map show

# Instruction count check — production target: < 200
insn-count:
	@echo "[*] Verifier instruction count for rrm_xdp_parser:"
	@sudo $(BPFTOOL) prog show name rrm_xdp_parser 2>/dev/null \
	    | grep insns_cnt || echo "(load the program first: make load)"

maps:
	@sudo bash scripts/read_maps.sh

# ── Traffic generator ─────────────────────────────────────────────────────────

gen-normal:
	sudo python3 gen/capwap_gen.py --mode normal --num-aps 5 --interval 1.0

gen-dfs:
	sudo python3 gen/capwap_gen.py --mode dfs --num-aps 5 --target-ap 3 --delay 5

gen-spike:
	sudo python3 gen/capwap_gen.py --mode spike --num-aps 5 --target-ap 3 --spike-util 92

# ── Control CLI ───────────────────────────────────────────────────────────────

ctl-get-state:
	sudo ./$(AGENT_BIN) ctl get-state

ctl-get-thresholds:
	sudo ./$(AGENT_BIN) ctl get-thresholds

# make ctl-set-threshold ARGS="--util-high 70 --util-consec 2"
ctl-set-threshold:
	sudo ./$(AGENT_BIN) ctl set-threshold $(ARGS)

ctl-get-stats:
	sudo ./$(AGENT_BIN) ctl get-stats

# ── Metrics ───────────────────────────────────────────────────────────────────

metrics:
	@curl -s http://localhost:9090/metrics | grep -E '^rrm_' | head -50 || \
	    echo "[!] Agent not running"

# ── Benchmark ─────────────────────────────────────────────────────────────────

benchmark: all
	@chmod +x scripts/benchmark.sh
	sudo bash scripts/benchmark.sh

# ── Cleaned ───────────────────────────────────────────────────────────────────

# ── Dependencies ──────────────────────────────────────────────────────────────

install-deps:
	@echo "[*] Installing system dependencies..."
	sudo apt update
	sudo apt install -y build-essential git curl wget pkg-config \
	    libbpf-dev libelf-dev zlib1g-dev \
	    linux-tools-common linux-tools-generic \
	    python3 python3-pip
	@echo "[*] Installing Scapy..."
	sudo pip3 install scapy
	@echo "[*] Installing clang-17 (if not present)..."
	@command -v clang-17 >/dev/null 2>&1 || \
	    (wget -q https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && \
	     sudo ./llvm.sh 17 && rm llvm.sh && \
	     sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100)
	@echo "[+] System dependencies installed"
	@echo "[*] Install Go manually: see official Go installation guide"

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	@rm -f $(KERN_OBJ) $(AGENT_BIN) benchmark_results.txt
	@echo "[+] Cleaned"

# Unpin BPF maps from filesystem (if agent crashed without cleanup)
unpin:
	-sudo rm -rf /sys/fs/bpf/rrm
	@echo "[+] BPF maps unpinned"

help:
	@echo ""
	@echo "ebpf-rrm-engine — Makefile"
	@echo ""
	@echo "Setup:"
	@echo "  make install-deps     Install system dependencies (Ubuntu)"
	@echo "  make vmlinux          Generate kern/vmlinux.h (run once)"
	@echo ""
	@echo "Build:"
	@echo "  make                  Compile BPF + build Go agent"
	@echo ""
	@echo "Run:"
	@echo "  make run              sudo: TUI dashboard"
	@echo "  make run-headless     sudo: headless mode"
	@echo ""
	@echo "Traffic:"
	@echo "  make gen-normal       Normal steady-state telemetry"
	@echo "  make gen-dfs          DFS radar injection (fires after 5s)"
	@echo "  make gen-spike        Load anomaly ramp"
	@echo ""
	@echo "Control CLI (agent must be running):"
	@echo "  make ctl-get-state             Print AP state"
	@echo "  make ctl-get-thresholds        Print thresholds"
	@echo "  make ctl-set-threshold ARGS='' Update thresholds live"
	@echo "  make ctl-get-stats             Print drop counter"
	@echo ""
	@echo "Metrics:"
	@echo "  make metrics          curl /metrics"
	@echo ""
	@echo "Testing:"
	@echo "  make benchmark        Run automated benchmark suite"
	@echo "  make insn-count       Check XDP instruction count"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean            Remove build artifacts"
	@echo "  make unpin            Remove /sys/fs/bpf/rrm/ (after crash)"