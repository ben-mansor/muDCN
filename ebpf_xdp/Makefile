# μDCN eBPF/XDP Makefile
# Builds the eBPF/XDP kernel packet handler components

# Configuration
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS := /lib/modules/$(KERNEL_VERSION)/build/include

# Compiler flags
CFLAGS := -g -O2 -Wall -Werror
CFLAGS += -I$(KERNEL_HEADERS)
LDFLAGS := -lelf -lbpf

# Source files
XDP_PROG_SRC := ndn_parser.c
XDP_LOADER_SRC := ndn_xdp_loader.c

# Output files
XDP_PROG_OBJ := ndn_parser.o
XDP_LOADER_OBJ := ndn_xdp_loader.o
XDP_LOADER := ndn_xdp_loader

# Default target
.PHONY: all
all: $(XDP_PROG_OBJ) $(XDP_LOADER)

# Build eBPF program
$(XDP_PROG_OBJ): $(XDP_PROG_SRC)
	@echo "Compiling eBPF program..."
	$(CLANG) -target bpf -D__BPF_TRACING__ $(CFLAGS) -c $< -o $@
	@echo "Generated eBPF object: $@"

# Generate BPF skeleton header
ndn_parser.skel.h: $(XDP_PROG_OBJ)
	@echo "Generating BPF skeleton header..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated BPF skeleton header: $@"

# Build loader program
$(XDP_LOADER_OBJ): $(XDP_LOADER_SRC) ndn_parser.skel.h
	@echo "Compiling loader program..."
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Generated loader object: $@"

# Link loader program
$(XDP_LOADER): $(XDP_LOADER_OBJ)
	@echo "Linking loader program..."
	$(CC) $(LDFLAGS) $< -o $@
	@echo "Generated loader: $@"

# Clean target
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(XDP_PROG_OBJ) $(XDP_LOADER_OBJ) $(XDP_LOADER) ndn_parser.skel.h
	@echo "Cleaned up"

# Install target
.PHONY: install
install: $(XDP_PROG_OBJ) $(XDP_LOADER)
	@echo "Installing..."
	install -m 755 $(XDP_LOADER) /usr/local/bin/
	install -m 644 $(XDP_PROG_OBJ) /usr/local/lib/
	@echo "Installed"

# Uninstall target
.PHONY: uninstall
uninstall:
	@echo "Uninstalling..."
	rm -f /usr/local/bin/$(XDP_LOADER)
	rm -f /usr/local/lib/$(XDP_PROG_OBJ)
	@echo "Uninstalled"

# Load eBPF program
.PHONY: load
load: $(XDP_PROG_OBJ) $(XDP_LOADER)
	@echo "Loading eBPF program..."
	sudo ./$(XDP_LOADER) -i eth0
	@echo "eBPF program loaded"

# Unload eBPF program
.PHONY: unload
unload:
	@echo "Unloading eBPF program..."
	sudo ip link set dev eth0 xdp off
	@echo "eBPF program unloaded"

# Help target
.PHONY: help
help:
	@echo "μDCN eBPF/XDP Makefile Help"
	@echo "==========================="
	@echo "make                 Build all components"
	@echo "make clean           Clean all components"
	@echo "make install         Install components"
	@echo "make uninstall       Uninstall components"
	@echo "make load            Load eBPF program"
	@echo "make unload          Unload eBPF program"
	@echo "make help            Show this help message"
