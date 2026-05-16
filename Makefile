# ─────────────────────────────────────────────────────────────────────────────
# ebpf-rrm-engine/Makefile  —  Phase 1
#
# Architecture auto-detected from `uname -m`.
# Tested on: Ubuntu 22.04, kernel 5.15+, clang 17, arm64 and x86_64.
# ─────────────────────────────────────────────────────────────────────────────

ARCH := $(shell uname -m)

# Map uname -m output to BPF target arch flag.
# uname gives 'aarch64' on Apple Silicon VMs, 'x86_64' on Intel.
ifeq ($(ARCH),aarch64)
    BPF_ARCH := arm64
else ifeq ($(ARCH),x86_64)
    BPF_ARCH := x86
else
    $(error [!] Unsupported architecture: $(ARCH). Expected aarch64 or x86_64.)
endif

# System headers for the target arch (asm/types.h etc.)
LINUX_INC := /usr/include/$(ARCH)-linux-gnu

CLANG   := clang
BPFTOOL := bpftool

KERN_SRC := kern/rrm_xdp.c
KERN_OBJ := kern/rrm_xdp.o
PIN_PATH := /sys/fs/bpf/rrm_xdp

# Include order matters:
#   1. kern/       → vmlinux.h (all kernel types), rrm_maps.h
#   2. proto/      → capwap_lite.h (our protocol definition)
#   3. LINUX_INC   → arch-specific system headers
INCLUDES := -I./kern -I./proto -I$(LINUX_INC)

CFLAGS := \
    -O2 -g -Wall \
    -target bpf \
    -D__TARGET_ARCH_$(BPF_ARCH) \
    $(INCLUDES)

# ── Phony targets ─────────────────────────────────────────────────────────────
.PHONY: all vmlinux load unload verify maps clean help

# Default: compile XDP object
all: $(KERN_OBJ)

$(KERN_OBJ): $(KERN_SRC) kern/vmlinux.h kern/rrm_maps.h proto/capwap_lite.h
	@echo "[*] Compiling $(KERN_SRC) for BPF target (arch=$(BPF_ARCH))..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "[+] OK: $(KERN_OBJ)"
	@echo "[*] Sections in object:"
	@readelf -S $@ | grep -E 'xdp|maps|license' || true

# Generate vmlinux.h from the running kernel's BTF.
# Run this once, or after a kernel upgrade.
vmlinux:
	@echo "[*] Generating kern/vmlinux.h from /sys/kernel/btf/vmlinux ..."
	@test -f /sys/kernel/btf/vmlinux || \
	    (echo "[!] /sys/kernel/btf/vmlinux not found. Is CONFIG_DEBUG_INFO_BTF enabled?" && exit 1)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kern/vmlinux.h
	@echo "[+] Generated kern/vmlinux.h ($$(wc -l < kern/vmlinux.h) lines)"

# Attach XDP program to veth0 in generic mode.
# Using bpftool instead of ip link for better compatibility with newer kernels.
load: $(KERN_OBJ)
	@echo "[*] Checking for veth0..."
	@ip link show veth0 >/dev/null 2>&1 || (echo "[!] veth0 not found. Please create it first." && exit 1)
	@echo "[*] Loading and attaching XDP program to veth0 (xdpgeneric)..."
	@sudo rm -f $(PIN_PATH)
	sudo $(BPFTOOL) prog load $(KERN_OBJ) $(PIN_PATH) type xdp
	sudo $(BPFTOOL) net attach xdpgeneric pinned $(PIN_PATH) dev veth0
	@echo "[+] Loaded and attached. Confirm:"
	@sudo $(BPFTOOL) net show dev veth0
	@echo "[*] Trace output: sudo cat /sys/kernel/debug/tracing/trace_pipe"

# Detach XDP program from veth0 and cleanup.
unload:
	@echo "[*] Detaching XDP program from veth0..."
	-sudo $(BPFTOOL) net detach xdpgeneric dev veth0
	@echo "[*] Removing BPF pin..."
	-sudo rm -f $(PIN_PATH)
	@echo "[+] Detached"

# Show loaded programs and maps in the kernel.
verify:
	@echo "── BPF programs ─────────────────────────────────────────────"
	@sudo $(BPFTOOL) prog show
	@echo ""
	@echo "── BPF maps ─────────────────────────────────────────────────"
	@sudo $(BPFTOOL) map show

# Pretty-print BPF map contents (requires XDP program to be loaded).
maps:
	@sudo bash scripts/read_maps.sh

clean:
	@rm -f $(KERN_OBJ)
	@echo "[+] Cleaned"

help:
	@echo "Targets:"
	@echo "  make vmlinux   — generate kern/vmlinux.h (run once)"
	@echo "  make           — compile XDP object"
	@echo "  make load      — attach XDP to veth0"
	@echo "  make unload    — detach XDP from veth0"
	@echo "  make verify    — show loaded programs and maps"
	@echo "  make maps      — pretty-print BPF map contents"
	@echo "  make clean     — remove build artifacts"