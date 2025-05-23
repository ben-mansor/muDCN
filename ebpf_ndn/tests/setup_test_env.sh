#!/bin/bash

# This script sets up a test environment using network namespaces
# to test the NDN XDP packet handler

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Clean up any existing test environment
cleanup() {
    echo "Cleaning up test environment..."
    ip netns del ndn-consumer 2>/dev/null
    ip netns del ndn-router 2>/dev/null
    ip netns del ndn-producer 2>/dev/null
    ip link del ndn-veth0 2>/dev/null
    ip link del ndn-veth1 2>/dev/null
    echo "Clean up complete."
}

# Set up trap to clean up on exit
trap cleanup EXIT INT TERM

# Clean up any existing environment
cleanup

# Create network namespaces
echo "Creating network namespaces..."
ip netns add ndn-consumer
ip netns add ndn-router
ip netns add ndn-producer

# Create virtual ethernet pairs
echo "Creating virtual interfaces..."
# Consumer to Router
ip link add ndn-veth0 type veth peer name ndn-veth1
ip link set ndn-veth0 netns ndn-consumer
ip link set ndn-veth1 netns ndn-router

# Router to Producer
ip link add ndn-veth2 type veth peer name ndn-veth3
ip link set ndn-veth2 netns ndn-router
ip link set ndn-veth3 netns ndn-producer

# Configure interfaces in namespaces
echo "Configuring interfaces..."
# Consumer namespace
ip netns exec ndn-consumer ip addr add 192.168.1.1/24 dev ndn-veth0
ip netns exec ndn-consumer ip link set ndn-veth0 up
ip netns exec ndn-consumer ip link set lo up
ip netns exec ndn-consumer ip route add default via 192.168.1.2

# Router namespace
ip netns exec ndn-router ip addr add 192.168.1.2/24 dev ndn-veth1
ip netns exec ndn-router ip link set ndn-veth1 up
ip netns exec ndn-router ip addr add 192.168.2.1/24 dev ndn-veth2
ip netns exec ndn-router ip link set ndn-veth2 up
ip netns exec ndn-router ip link set lo up
ip netns exec ndn-router sysctl -w net.ipv4.ip_forward=1

# Producer namespace
ip netns exec ndn-producer ip addr add 192.168.2.2/24 dev ndn-veth3
ip netns exec ndn-producer ip link set ndn-veth3 up
ip netns exec ndn-producer ip link set lo up
ip netns exec ndn-producer ip route add default via 192.168.2.1

echo "Network setup complete!"
echo "Network topology:"
echo "ndn-consumer (192.168.1.1) <--> ndn-router (192.168.1.2/192.168.2.1) <--> ndn-producer (192.168.2.2)"

# Get interface indexes for XDP attachment
CONSUMER_IF=$(ip netns exec ndn-consumer ip link show ndn-veth0 | grep -o "^[0-9]*")
ROUTER_IF1=$(ip netns exec ndn-router ip link show ndn-veth1 | grep -o "^[0-9]*")
ROUTER_IF2=$(ip netns exec ndn-router ip link show ndn-veth2 | grep -o "^[0-9]*")
PRODUCER_IF=$(ip netns exec ndn-producer ip link show ndn-veth3 | grep -o "^[0-9]*")

echo "Interface indexes:"
echo "Consumer: $CONSUMER_IF"
echo "Router (facing consumer): $ROUTER_IF1"
echo "Router (facing producer): $ROUTER_IF2"
echo "Producer: $PRODUCER_IF"

# Keep the script running to maintain the namespaces
echo ""
echo "Test environment is ready. Press Ctrl+C to clean up and exit."
sleep infinity
