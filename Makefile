# ─────────────────────────────────────────────────────────────────────────────
# ebpf-rrm-engine/Makefile — Phase 2
#
# Changes from Phase 1:
#   - `make agent`  builds the Go agent binary
#   - `make run`    builds + runs the agent (owns XDP lifecycle)
#   - `make load` / `make unload` kept for standalone XDP testing
#   - `make gen-*`  convenience targets for the traffic generator
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

.PHONY: all vmlinux agent run load unload verify maps \
        gen-normal gen-dfs gen-spike clean help

# Default: compile BPF object + build Go agent
all: $(KERN_OBJ) agent

# ── BPF compilation ───────────────────────────────────────────────────────────

$(KERN_OBJ): $(KERN_SRC) kern/vmlinux.h kern/rrm_maps.h proto/capwap_lite.h
	@echo "[*] Compiling $(KERN_SRC) → $(KERN_OBJ) (arch=$(BPF_ARCH))"
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "[+] BPF object compiled"
	@echo "[*] Sections:"
	@readelf -S $@ | grep -E 'xdp|maps|license' || true
	@echo "[*] Verifying BTF debug info embedded:"
	@readelf -S $@ | grep -q BTF && echo "[+] BTF present" || echo "[!] BTF missing (add -g to CFLAGS)"

vmlinux:
	@echo "[*] Generating kern/vmlinux.h ..."
	@test -f /sys/kernel/btf/vmlinux || \
	    (echo "[!] /sys/kernel/btf/vmlinux missing. CONFIG_DEBUG_INFO_BTF not set?" && exit 1)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kern/vmlinux.h
	@echo "[+] Generated ($$(wc -l < kern/vmlinux.h) lines)"

# ── Go agent ──────────────────────────────────────────────────────────────────

agent: $(KERN_OBJ)
	@echo "[*] Building Go agent..."
	cd $(AGENT_DIR) && $(GO) mod tidy && $(GO) build -o ../$(AGENT_BIN) .
	@echo "[+] Built: ./$(AGENT_BIN)"

# Run the agent (requires root — XDP attach + BPF map access)
# Reads BPF object from kern/rrm_xdp.o relative to project root.
run: agent
	@echo "[*] Starting agent on veth0 (Ctrl+C to stop)..."
	sudo ./$(AGENT_BIN) --iface veth0

# ── Standalone XDP load/unload (for testing without the Go agent) ─────────────

load: $(KERN_OBJ)
	@echo "[*] Attaching XDP program to veth0 (xdpgeneric)..."
	sudo ip link set dev veth0 xdpgeneric obj $(KERN_OBJ) sec xdp
	@echo "[+] Loaded"
	@ip link show veth0 | grep -o 'xdp[^ ]*' || true

unload:
	-sudo ip link set dev veth0 xdpgeneric off
	@echo "[+] Detached"

# ── Inspection ────────────────────────────────────────────────────────────────

verify:
	@echo "── BPF programs ──────────────────────────────────────────────"
	@sudo $(BPFTOOL) prog show
	@echo ""
	@echo "── BPF maps ──────────────────────────────────────────────────"
	@sudo $(BPFTOOL) map show

maps:
	@sudo bash scripts/read_maps.sh

# ── Traffic generator shortcuts ───────────────────────────────────────────────
# Run these in a SEPARATE terminal while the agent is running.

gen-normal:
	sudo python3 gen/capwap_gen.py --mode normal --num-aps 5 --interval 1.0

gen-dfs:
	sudo python3 gen/capwap_gen.py --mode dfs --num-aps 5 --target-ap 2 --delay 5

gen-spike:
	sudo python3 gen/capwap_gen.py --mode spike --num-aps 5 --target-ap 3 --spike-util 92

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	@rm -f $(KERN_OBJ) $(AGENT_BIN)
	@echo "[+] Cleaned"

help:
	@echo "Phase 2 targets:"
	@echo "  make vmlinux      generate kern/vmlinux.h (once)"
	@echo "  make              compile BPF + build Go agent"
	@echo "  make run          sudo: build + run agent on veth0"
	@echo "  make load         sudo: attach XDP via ip link (no agent)"
	@echo "  make unload       sudo: detach XDP from veth0"
	@echo "  make verify       show loaded BPF programs + maps"
	@echo "  make maps         pretty-print BPF map contents"
	@echo "  make gen-normal   run generator in normal mode"
	@echo "  make gen-dfs      run generator in DFS mode"
	@echo "  make gen-spike    run generator in spike mode"
	@echo "  make clean        remove build artifacts"