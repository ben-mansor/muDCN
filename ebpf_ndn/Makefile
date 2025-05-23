# Makefile for eBPF/XDP NDN packet handler
# This builds an XDP program that parses NDN Interest packets and handles caching

# Check for root permissions
IDU=$(shell id -u)
ifeq ($(IDU), 0)
	SUDO =
else
	SUDO = sudo
endif

# Compiler and toolchain
CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
CC ?= gcc

# Directories
SRC_DIR = src
INC_DIR = include
OBJ_DIR = build
TEST_DIR = tests

# Ensure build directory exists
$(shell mkdir -p $(OBJ_DIR))

# Compiler flags
CFLAGS = -O2 -g -Wall -Wextra -I$(INC_DIR)
BPF_CFLAGS = -target bpf -D__BPF_TRACING__ $(CFLAGS) -I/usr/include/x86_64-linux-gnu
LOADER_LIBS = -lbpf -lelf

# XDP program files
XDP_PROG_SRC = $(SRC_DIR)/ndn_xdp.c
XDP_PROG_OBJ = $(OBJ_DIR)/ndn_xdp.o
XDP_LOADER_SRC = $(SRC_DIR)/ndn_xdp_loader.c
XDP_LOADER = $(OBJ_DIR)/ndn_xdp_loader
PKT_GEN = $(OBJ_DIR)/generate_ndn_packets
XDP_SIM = $(OBJ_DIR)/ndn_xdp_sim

# Test programs
TEST_PARSER = $(OBJ_DIR)/ndn_parser_test

# Default target
.PHONY: all
all: $(XDP_PROG_OBJ) $(XDP_LOADER) $(PKT_GEN) $(XDP_SIM) $(TEST_PARSER)

# Build the XDP BPF program
$(XDP_PROG_OBJ): $(XDP_PROG_SRC)
	@echo "Compiling eBPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Generated BPF object: $@"

# Build loader program
$(XDP_LOADER): $(XDP_LOADER_SRC) $(XDP_PROG_OBJ)
	@echo "Compiling and linking loader program..."
	$(CC) $(CFLAGS) $< -o $@ $(LOADER_LIBS)
	@echo "Generated loader: $@"

# Build packet generator
$(PKT_GEN): $(TEST_DIR)/generate_ndn_packets.c
	@echo "Compiling packet generator..."
	$(CC) $(CFLAGS) $< -o $@
	@echo "Generated packet generator: $@"

# Build XDP simulator
$(XDP_SIM): $(TEST_DIR)/ndn_xdp_sim.c
	@echo "Compiling XDP simulator..."
	$(CC) $(CFLAGS) $< -o $@ -lpcap
	@echo "Generated XDP simulator: $@"

# Build parser test
$(TEST_PARSER): $(TEST_DIR)/ndn_parser_test.c
	@echo "Compiling parser test..."
	$(CC) $(CFLAGS) $< -o $@
	@echo "Generated parser test: $@"

# Run parser test
.PHONY: test-parser
test-parser: $(TEST_PARSER)
	@echo "Running NDN parser test..."
	$(OBJ_DIR)/ndn_parser_test

# Run network setup script
.PHONY: setup-test-env
setup-test-env:
	@echo "Setting up test environment..."
	$(SUDO) $(TEST_DIR)/setup_test_env.sh

# Load XDP program onto an interface
.PHONY: load
load: $(XDP_PROG_OBJ) $(XDP_LOADER) 
	@echo "Loading XDP program onto interface $(IFACE)..."
	$(SUDO) $(XDP_LOADER) -i $(IFACE) $(OPTIONS)

# Clean target
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(OBJ_DIR)/*
	@echo "Cleaned up"

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all            - Build all programs"
	@echo "  clean          - Clean up build artifacts"
	@echo "  test-parser    - Run NDN parser test"
	@echo "  setup-test-env - Set up test environment with virtual interfaces"
	@echo "  load IFACE=<interface> [OPTIONS='-s -v'] - Load XDP program onto interface"
	@echo ""
	@echo "Examples:"
	@echo "  make load IFACE=eth0       - Load XDP program onto eth0 (native mode)"
	@echo "  make load IFACE=eth0 OPTIONS='-s -v' - Load in SKB mode with verbose output"
	@echo "  make load IFACE=veth0 OPTIONS='-r veth1' - Load and redirect traffic to veth1"

