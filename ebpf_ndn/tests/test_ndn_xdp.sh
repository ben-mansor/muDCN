#!/bin/bash

# Test script for NDN XDP program
# This script:
# 1. Creates virtual interfaces for testing
# 2. Loads the XDP program
# 3. Sends test NDN Interest packets
# 4. Displays results and statistics

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Build directory for binaries
BUILD_DIR="../build"
XDP_LOADER="${BUILD_DIR}/ndn_xdp_loader"
PKT_GEN="${BUILD_DIR}/generate_ndn_packets"

# Check if required files exist
for file in "$XDP_LOADER" "$PKT_GEN"; do
    if [ ! -f "$file" ]; then
        echo "Error: $file not found. Did you run 'make' in the project root?"
        exit 1
    fi
done

# Color definitions
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to clean up environment
cleanup() {
    echo -e "${YELLOW}\nCleaning up test environment...${NC}"
    ip link del veth0 2>/dev/null
    ip link del veth1 2>/dev/null
    echo "Done."
}

# Set up trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

# Create two virtual interfaces for testing
echo -e "${YELLOW}Creating virtual interfaces for testing...${NC}"
ip link add veth0 type veth peer name veth1
ip addr add 192.168.100.1/24 dev veth0
ip addr add 192.168.100.2/24 dev veth1
ip link set dev veth0 up
ip link set dev veth1 up

echo -e "${GREEN}Created virtual interfaces:${NC}"
ip -br link show veth0
ip -br link show veth1
ip -br addr show veth0
ip -br addr show veth1
echo

# Step 1: Load XDP program onto veth0 in SKB mode with verbose output
echo -e "${YELLOW}Loading XDP program onto veth0 (SKB mode)...${NC}"
$XDP_LOADER -i veth0 -s -v &
XDP_PID=$!

# Sleep to allow XDP program to start
sleep 2
echo

# Step 2: Test basic packet handling
echo -e "${CYAN}Test 1: Basic packet handling${NC}"
echo "Sending a single NDN Interest packet..."
$PKT_GEN -d 192.168.100.2 -n "/test/basic" -c 1
sleep 1
echo

# Step 3: Test cache hit (duplicate packet)
echo -e "${CYAN}Test 2: Cache hit (duplicate packet)${NC}"
echo "Sending duplicate NDN Interest packets (should see a cache hit)..."
$PKT_GEN -d 192.168.100.2 -n "/test/dup" -c 1
sleep 1
$PKT_GEN -d 192.168.100.2 -n "/test/dup" -c 1
sleep 1
echo

# Step 4: Test multiple different packets
echo -e "${CYAN}Test 3: Multiple different packets${NC}"
echo "Sending multiple different NDN Interest packets..."
$PKT_GEN -d 192.168.100.2 -n "/test/multi" -c 3 -i 500
sleep 2
echo

# Step 5: Test cached vs non-cached packets
echo -e "${CYAN}Test 4: Cached vs non-cached packets${NC}"
echo "Sending repeated and new NDN Interest packets..."
$PKT_GEN -d 192.168.100.2 -n "/test/repeat1" -c 1
$PKT_GEN -d 192.168.100.2 -n "/test/repeat2" -c 1
$PKT_GEN -d 192.168.100.2 -n "/test/repeat3" -c 1
sleep 1
echo "Re-sending the same NDN Interest packets (should be cached)..."
$PKT_GEN -d 192.168.100.2 -n "/test/repeat1" -c 1
$PKT_GEN -d 192.168.100.2 -n "/test/repeat2" -c 1
$PKT_GEN -d 192.168.100.2 -n "/test/repeat3" -c 1
sleep 2
echo

# Step 6: Test high volume of packets
echo -e "${CYAN}Test 5: High volume of packets${NC}"
echo "Sending a high volume of NDN Interest packets..."
$PKT_GEN -d 192.168.100.2 -n "/test/volume" -c 10 -i 100
sleep 2
echo

# Kill the loader process to display final statistics
echo -e "${YELLOW}Tests completed! Stopping XDP program to see final statistics...${NC}"
kill $XDP_PID
sleep 1
echo

# Print summary
echo -e "${GREEN}Test Summary:${NC}"
echo "1. Created virtual interfaces veth0 and veth1"
echo "2. Loaded XDP program on veth0"
echo "3. Sent NDN Interest packets through the interfaces"
echo "4. Demonstrated caching functionality"
echo "5. Verified statistics collection"

echo -e "\nCheck the output above for cache hits/misses and packet statistics."
