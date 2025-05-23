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

# Source files - Original version
XDP_PROG_SRC := ndn_parser.c
XDP_LOADER_SRC := ndn_xdp_loader.c

# Source files - Enhanced version (v2)
XDP_PROG_V2_SRC1 := ndn_parser_v2.c
XDP_PROG_V2_SRC2 := ndn_parser_v2_proc.c
XDP_LOADER_V2_SRC := ndn_xdp_loader_v2.c

# Output files - Original version
XDP_PROG_OBJ := ndn_parser.o
XDP_LOADER_OBJ := ndn_xdp_loader.o
XDP_LOADER := ndn_xdp_loader

# Output files - Enhanced version (v2)
XDP_PROG_V2_OBJ := ndn_parser_v2.o
XDP_LOADER_V2_OBJ := ndn_xdp_loader_v2.o
XDP_LOADER_V2 := ndn_xdp_loader_v2

# Default target
.PHONY: all
all: $(XDP_PROG_OBJ) $(XDP_LOADER) $(XDP_PROG_V2_OBJ) $(XDP_LOADER_V2)

# Build eBPF program (original version)
$(XDP_PROG_OBJ): $(XDP_PROG_SRC)
	@echo "Compiling eBPF program..."
	$(CLANG) -target bpf -D__BPF_TRACING__ $(CFLAGS) -c $< -o $@
	@echo "Generated eBPF object: $@"

# Generate BPF skeleton header (original version)
ndn_parser.skel.h: $(XDP_PROG_OBJ)
	@echo "Generating BPF skeleton header..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated BPF skeleton header: $@"

# Build loader program (original version)
$(XDP_LOADER_OBJ): $(XDP_LOADER_SRC) ndn_parser.skel.h
	@echo "Compiling loader program..."
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Generated loader object: $@"

# Link loader program (original version)
$(XDP_LOADER): $(XDP_LOADER_OBJ)
	@echo "Linking loader program..."
	$(CC) $(LDFLAGS) $< -o $@
	@echo "Generated loader: $@"

# Enhanced version (v2) targets

# Build eBPF program (enhanced v2)
$(XDP_PROG_V2_OBJ): $(XDP_PROG_V2_SRC1) $(XDP_PROG_V2_SRC2)
	@echo "Compiling enhanced eBPF program v2..."
	$(CLANG) -target bpf -D__BPF_TRACING__ $(CFLAGS) -c $(XDP_PROG_V2_SRC1) -o temp1.o
	$(CLANG) -target bpf -D__BPF_TRACING__ $(CFLAGS) -c $(XDP_PROG_V2_SRC2) -o temp2.o
	$(BPFTOOL) prog link temp1.o temp2.o $(XDP_PROG_V2_OBJ)
	@echo "Generated enhanced eBPF object: $@"

# Generate BPF skeleton header (enhanced v2)
ndn_parser_v2.skel.h: $(XDP_PROG_V2_OBJ)
	@echo "Generating enhanced BPF skeleton header..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated enhanced BPF skeleton header: $@"

# Build loader program (enhanced v2)
$(XDP_LOADER_V2_OBJ): $(XDP_LOADER_V2_SRC) ndn_parser_v2.skel.h
	@echo "Compiling enhanced loader program..."
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Generated enhanced loader object: $@"

# Link loader program (enhanced v2)
$(XDP_LOADER_V2): $(XDP_LOADER_V2_OBJ)
	@echo "Linking enhanced loader program..."
	$(CC) $(LDFLAGS) $< -o $@
	@echo "Generated enhanced loader: $@"

# Clean target
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(XDP_PROG_OBJ) $(XDP_LOADER_OBJ) $(XDP_LOADER) ndn_parser.skel.h \
		$(XDP_PROG_V2_OBJ) $(XDP_LOADER_V2_OBJ) $(XDP_LOADER_V2) ndn_parser_v2.skel.h \
		temp1.o temp2.o benchmark_results/*.png benchmark_results/*.json
	@echo "Cleaned up"

# Install target - original version
.PHONY: install
install: $(XDP_PROG_OBJ) $(XDP_LOADER)
	@echo "Installing original version..."
	install -m 755 $(XDP_LOADER) /usr/local/bin/
	install -m 644 $(XDP_PROG_OBJ) /usr/local/lib/
	@echo "Installed"

# Install target - enhanced version
.PHONY: install-v2
install-v2: $(XDP_PROG_V2_OBJ) $(XDP_LOADER_V2)
	@echo "Installing enhanced version (v2)..."
	install -m 755 $(XDP_LOADER_V2) /usr/local/bin/
	install -m 644 $(XDP_PROG_V2_OBJ) /usr/local/lib/
	@echo "Installed"

# Install both versions
.PHONY: install-all
install-all: install install-v2
	@echo "Both versions installed"

# Uninstall target - original version
.PHONY: uninstall
uninstall:
	@echo "Uninstalling original version..."
	rm -f /usr/local/bin/$(XDP_LOADER)
	rm -f /usr/local/lib/$(XDP_PROG_OBJ)
	@echo "Uninstalled"

# Uninstall target - enhanced version
.PHONY: uninstall-v2
uninstall-v2:
	@echo "Uninstalling enhanced version (v2)..."
	rm -f /usr/local/bin/$(XDP_LOADER_V2)
	rm -f /usr/local/lib/$(XDP_PROG_V2_OBJ)
	@echo "Uninstalled"

# Uninstall both versions
.PHONY: uninstall-all
uninstall-all: uninstall uninstall-v2
	@echo "Both versions uninstalled"

# Load eBPF program - original version
.PHONY: load
load: $(XDP_PROG_OBJ) $(XDP_LOADER)
	@echo "Loading original eBPF program..."
	sudo ./$(XDP_LOADER) -i eth0
	@echo "Original eBPF program loaded"

# Load enhanced eBPF program - v2
.PHONY: load-v2
load-v2: $(XDP_PROG_V2_OBJ) $(XDP_LOADER_V2)
	@echo "Loading enhanced eBPF program (v2)..."
	sudo ./$(XDP_LOADER_V2) -i eth0
	@echo "Enhanced eBPF program loaded"

# Unload eBPF program
.PHONY: unload
unload:
	@echo "Unloading eBPF program..."
	sudo ip link set dev eth0 xdp off
	@echo "eBPF program unloaded"

# Run benchmark
.PHONY: benchmark
benchmark: $(XDP_PROG_V2_OBJ) $(XDP_LOADER_V2) benchmark.py
	@echo "Preparing benchmark directory..."
	mkdir -p benchmark_results
	@echo "Running benchmarks (this may take a while)..."
	sudo python3 benchmark.py -i eth0 -d 30 -o benchmark_results
	@echo "Benchmark completed. Results in benchmark_results/"

# Run quick benchmark (faster, fewer test cases)
.PHONY: benchmark-quick
benchmark-quick: $(XDP_PROG_V2_OBJ) $(XDP_LOADER_V2) benchmark.py
	@echo "Running quick benchmarks..."
	mkdir -p benchmark_results
	sudo python3 benchmark.py -i eth0 -d 10 -q -o benchmark_results
	@echo "Quick benchmark completed. Results in benchmark_results/"

# Help target
.PHONY: help
help:
	@echo "μDCN eBPF/XDP Makefile Help"
	@echo "==========================="
	@echo "Basic commands:"
	@echo "  make                 Build all components (original and v2)"
	@echo "  make clean           Clean all components"
	@echo "  make help            Show this help message"
	@echo ""
	@echo "Original version commands:"
	@echo "  make install         Install original version"
	@echo "  make uninstall       Uninstall original version"
	@echo "  make load            Load original eBPF program"
	@echo ""
	@echo "Enhanced v2 commands:"
	@echo "  make install-v2      Install enhanced v2 version"
	@echo "  make uninstall-v2    Uninstall enhanced v2 version"
	@echo "  make load-v2         Load enhanced v2 eBPF program"
	@echo ""
	@echo "Combined commands:"
	@echo "  make install-all     Install both versions"
	@echo "  make uninstall-all   Uninstall both versions"
	@echo "  make unload          Unload any loaded eBPF program"
	@echo ""
	@echo "Benchmark commands:"
	@echo "  make benchmark       Run full benchmark suite"
	@echo "  make benchmark-quick Run quick benchmark (fewer test cases)"
	@echo ""
	@echo "XDP-enhanced features in v2:"
	@echo "  - Zero-copy packet handling"
	@echo "  - Direct kernel content store operations"
	@echo "  - Optimized TLV parsing for NDN packets"
	@echo "  - Smart decision logic (cache, drop, redirect)"
	@echo "  - Enhanced performance monitoring"
