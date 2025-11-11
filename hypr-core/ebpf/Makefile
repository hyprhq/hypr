# Drift eBPF Programs Makefile
#
# Compiles L4 port forwarding eBPF programs for HYPR.
# Requires: clang with BPF support, libbpf headers

# Compiler and flags
CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# eBPF compilation flags
BPF_CFLAGS := -O2 -target bpf -g
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -Wall -Werror
BPF_CFLAGS += -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -fno-stack-protector

# Include paths (adjust based on system)
# Try to detect libbpf headers automatically
LIBBPF_INCLUDE := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")
BPF_CFLAGS += $(LIBBPF_INCLUDE)

# vmlinux.h location (generated from BTF)
# Assuming vmlinux.h is in the same directory or can be generated
VMLINUX_H := vmlinux.h

# Source files
INGRESS_SRC := drift_l4_ingress.c
EGRESS_SRC := drift_l4_egress.c

# Output object files
INGRESS_OBJ := drift_l4_ingress.o
EGRESS_OBJ := drift_l4_egress.o

.PHONY: all clean help check-deps

all: check-deps $(INGRESS_OBJ) $(EGRESS_OBJ)

# Compile ingress program
$(INGRESS_OBJ): $(INGRESS_SRC) $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Built $@"

# Compile egress program
$(EGRESS_OBJ): $(EGRESS_SRC) $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Built $@"

# Check for required dependencies
check-deps:
	@which $(CLANG) > /dev/null || (echo "Error: clang not found. Install clang with BPF support." && exit 1)
	@$(CLANG) --version | grep -q "clang" || (echo "Error: clang not working properly." && exit 1)
	@test -f $(VMLINUX_H) || (echo "Warning: vmlinux.h not found. Place it in this directory or generate it." && echo "You can generate it with: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h")
	@echo "Dependencies OK"

# Generate vmlinux.h (requires bpftool and Linux kernel with BTF)
vmlinux.h:
	@echo "Generating vmlinux.h from BTF..."
	@which bpftool > /dev/null || (echo "Error: bpftool not found. Install bpftool to generate vmlinux.h" && exit 1)
	@test -f /sys/kernel/btf/vmlinux || (echo "Error: BTF not available. Ensure kernel is compiled with CONFIG_DEBUG_INFO_BTF=y" && exit 1)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "Generated vmlinux.h"

clean:
	rm -f $(INGRESS_OBJ) $(EGRESS_OBJ)
	@echo "Cleaned build artifacts"

help:
	@echo "HYPR Drift eBPF Programs"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build all eBPF programs (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  vmlinux.h    - Generate vmlinux.h from kernel BTF"
	@echo "  check-deps   - Check for required dependencies"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang with BPF support"
	@echo "  - libbpf headers"
	@echo "  - vmlinux.h (can be generated with 'make vmlinux.h')"
	@echo ""
	@echo "Environment Variables:"
	@echo "  CLANG        - Path to clang compiler (default: clang)"
	@echo "  LLC          - Path to llc (default: llc)"
