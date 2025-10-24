# SPDX-License-Identifier: GPL-2.0
# Makefile for MinIO Protection eBPF LSM Program

# Directories
OUTPUT := .output
SRC := src
INCLUDE := include

# Tools
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC := gcc

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Flags
INCLUDES := -I$(OUTPUT) -I$(INCLUDE) -I/usr/include/bpf
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
USER_CFLAGS := -g -O2 -Wall
LDFLAGS := -lbpf -lelf -lz

# Source files
BPF_SRC := $(SRC)/minio_protect.bpf.c
USER_SRC := $(SRC)/minio_protect.c

# Output files
BPF_OBJ := $(OUTPUT)/minio_protect.bpf.o
SKEL := $(OUTPUT)/minio_protect.skel.h
USER_OBJ := $(OUTPUT)/minio_protect.o
TARGET := $(OUTPUT)/minio_protect

# Default target
.PHONY: all
all: $(TARGET)

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Check for required tools
.PHONY: check-tools
check-tools:
	@which $(CLANG) > /dev/null || (echo "Error: clang not found. Install: dnf install clang" && exit 1)
	@which $(BPFTOOL) > /dev/null || (echo "Error: bpftool not found. Install: dnf install bpftool" && exit 1)
	@pkg-config --exists libbpf || (echo "Error: libbpf not found. Install: dnf install libbpf-devel" && exit 1)
	@echo "All required tools found"

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC) | $(OUTPUT) check-tools
	@echo "  BPF      $@"
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

# Generate BPF skeleton
$(SKEL): $(BPF_OBJ)
	@echo "  SKEL     $@"
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace program
$(USER_OBJ): $(USER_SRC) $(SKEL)
	@echo "  CC       $@"
	$(CC) $(USER_CFLAGS) $(INCLUDES) -c $< -o $@

# Link final binary
$(TARGET): $(USER_OBJ)
	@echo "  LD       $@"
	$(CC) $< $(LDFLAGS) -o $@
	@echo ""
	@echo "Build successful! Binary: $(TARGET)"
	@echo ""

# Install to /usr/local/bin
.PHONY: install
install: $(TARGET)
	@echo "Installing to /usr/local/bin/minio_protect"
	install -m 0755 $(TARGET) /usr/local/bin/minio_protect
	@echo "Installation complete"

# Uninstall from /usr/local/bin
.PHONY: uninstall
uninstall:
	@echo "Removing /usr/local/bin/minio_protect"
	rm -f /usr/local/bin/minio_protect
	@echo "Uninstallation complete"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts"
	rm -rf $(OUTPUT)

# Check kernel requirements
.PHONY: check-kernel
check-kernel:
	@echo "Checking kernel requirements for eBPF LSM..."
	@echo ""
	@echo "Kernel version:"
	@uname -r
	@echo ""
	@echo "LSM modules (should include 'bpf'):"
	@cat /sys/kernel/security/lsm || echo "  WARNING: /sys/kernel/security/lsm not found"
	@echo ""
	@echo "BTF support (should exist):"
	@ls -lh /sys/kernel/btf/vmlinux 2>/dev/null || echo "  WARNING: /sys/kernel/btf/vmlinux not found"
	@echo ""
	@if cat /sys/kernel/security/lsm | grep -q bpf; then \
		echo "✓ LSM BPF is enabled"; \
	else \
		echo "✗ LSM BPF is NOT enabled"; \
		echo ""; \
		echo "To enable, add 'lsm=bpf' to kernel command line:"; \
		echo "  1. Edit /etc/default/grub"; \
		echo "  2. Add 'lsm=bpf' to GRUB_CMDLINE_LINUX"; \
		echo "  3. Run: grub2-mkconfig -o /boot/grub2/grub.cfg"; \
		echo "  4. Reboot"; \
	fi
	@echo ""

# Test basic functionality (must run as root)
.PHONY: test
test: $(TARGET)
	@echo "Testing MinIO Protection (requires root)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: Must run as root"; \
		exit 1; \
	fi
	@echo "Starting protection for UID $$(id -u)..."
	@timeout 5 $(TARGET) -u $$(id -u) -s 1 || true
	@echo ""
	@echo "Test complete (check kernel logs: dmesg | tail -20)"

# Show kernel log messages from the BPF program
.PHONY: logs
logs:
	@echo "=== MinIO Protection eBPF Logs ==="
	@echo "BPF programs use bpf_printk() which outputs to trace_pipe, not dmesg"
	@echo "Press Ctrl-C to stop"
	@echo ""
	@if [ ! -r /sys/kernel/debug/tracing/trace_pipe ]; then \
		echo "Error: Cannot read trace_pipe. Run as root or mount debugfs:"; \
		echo "  sudo mount -t debugfs none /sys/kernel/debug"; \
		exit 1; \
	fi
	@cat /sys/kernel/debug/tracing/trace_pipe | grep -E 'BLOCKED|ALLOWED|minio_protect'

# Help
.PHONY: help
help:
	@echo "MinIO Protection eBPF Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all            Build the minio_protect binary (default)"
	@echo "  check-tools    Check if required build tools are available"
	@echo "  check-kernel   Check if kernel supports eBPF LSM"
	@echo "  install        Install to /usr/local/bin"
	@echo "  uninstall      Remove from /usr/local/bin"
	@echo "  test           Run basic functionality test (requires root)"
	@echo "  logs           Show recent kernel log messages from BPF"
	@echo "  clean          Remove build artifacts"
	@echo "  help           Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - Kernel 5.7+ with CONFIG_BPF_LSM=y and lsm=bpf"
	@echo "  - clang (dnf install clang)"
	@echo "  - bpftool (dnf install bpftool)"
	@echo "  - libbpf-devel (dnf install libbpf-devel)"
	@echo ""
