# μDCN eBPF/XDP NDN Packet Handler

This component implements an eBPF/XDP-based Named Data Networking (NDN) packet handler for the μDCN transport architecture. It efficiently processes NDN Interest packets at the kernel level, maintaining a cache of recently seen names to prevent duplicate forwarding.

## Table of Contents

- [Features](#features)
- [Directory Structure](#directory-structure)
- [Building the Project](#building-the-project)
- [Testing](#testing)
- [Integration with Phase 2](#integration-with-phase-2)
- [Technical Details](#technical-details)
- [Troubleshooting](#troubleshooting)

## Features

- **Fast NDN Interest Packet Processing**: Identifies and processes NDN Interest packets directly in the kernel using XDP
- **TLV Name Parsing**: Efficient parsing of NDN name components from TLV-encoded packets
- **LRU Name Caching**: Maintains a cache of recently seen Interest names to detect and drop duplicates
- **Conditional Packet Forwarding**: Selectively forwards or drops packets based on cache state
- **Flexible Redirection**: Can redirect packets between interfaces using BPF_MAP_TYPE_DEVMAP
- **Performance Monitoring**: Collects detailed statistics on packet processing

## Directory Structure

```
ebpf_ndn/
├── build/                    # Build artifacts
├── include/                  # Header files for both XDP and userspace programs
├── src/
│   ├── ndn_xdp.c            # Main XDP program for NDN processing
│   └── ndn_xdp_loader.c     # Userspace loader program
└── tests/
    ├── ndn_parser_test.c    # Test program for NDN TLV name parsing
    ├── ndn_xdp_sim.c        # Userspace simulation of XDP processing
    ├── generate_ndn_packets.c # Test NDN packet generator
    ├── setup_test_env.sh    # Script to set up test network namespaces
    └── test_ndn_xdp.sh      # End-to-end testing script
```

## Building the Project

### Prerequisites

The following packages are required to build the project:

```bash
# For Debian/Ubuntu systems
sudo apt install build-essential clang llvm libelf-dev libbpf-dev pkg-config make libpcap-dev linux-headers-$(uname -r)
```

### Compilation

To build all components:

```bash
# Create build directory
mkdir -p build

# Build all components
make
```

This will compile:
1. The XDP BPF program (`build/ndn_xdp.o`)
2. The XDP loader program (`build/ndn_xdp_loader`)
3. Test utilities

## Testing

### Basic Parser Test

To verify the NDN TLV name parsing functionality:

```bash
make test-parser
```

### End-to-End Test

For a full end-to-end test using virtual interfaces:

```bash
# Run as root
sudo ./tests/test_ndn_xdp.sh
```

This script will:
1. Create virtual interfaces
2. Load the XDP program onto an interface
3. Send test NDN Interest packets
4. Verify caching and forwarding behavior

### Manual Testing

To manually load the XDP program onto a network interface:

```bash
# In native XDP mode (requires driver support)
sudo ./build/ndn_xdp_loader -i eth0

# In SKB/generic mode (works with any interface)
sudo ./build/ndn_xdp_loader -i eth0 -s

# With verbose output
sudo ./build/ndn_xdp_loader -i eth0 -v

# With packet redirection
sudo ./build/ndn_xdp_loader -i eth0 -r eth1
```

To manually generate test packets:

```bash
# Send a single NDN Interest packet
./build/generate_ndn_packets -d 192.168.1.1 -n "/test/data"

# Send multiple different packets
./build/generate_ndn_packets -d 192.168.1.1 -n "/test/data" -c 5

# Send repeated packets to test caching
./build/generate_ndn_packets -d 192.168.1.1 -n "/test/data" -c 5 -r
```

## Integration with Phase 2

### Interfaces for Phase 2

The XDP program exposes these key interfaces for integration with Phase 2:

1. **BPF Maps**:
   - `name_cache`: LRU hash map of recently seen NDN Interest names
   - `redirect_map`: Map for packet redirection between interfaces
   - `stats_map`: Map containing performance statistics

2. **Control Protocol**:
   To control the XDP program from Phase 2 (Rust), you'll need to:
   
   a. Open and access the BPF maps:
   ```rust
   use libbpf_rs::MapHandle;
   
   // Open the map by pinned path
   let name_cache = MapHandle::open("/sys/fs/bpf/name_cache").unwrap();
   
   // Or find the map by file descriptor if using libbpf's Object API
   let stats_map = bpf_object.map("stats_map").unwrap();
   ```
   
   b. Update the redirect map to change forwarding behavior:
   ```rust
   // Redirect traffic from if_index1 to if_index2
   let key = if_index1;
   let value = if_index2;
   redirect_map.update(&key, &value, BPF_ANY).unwrap();
   ```
   
   c. Read the statistics map:
   ```rust
   let key = 0;
   let stats: NdnStats = stats_map.lookup(&key).unwrap();
   println!("Interests received: {}", stats.interests_received);
   ```

### Extending Functionality

In Phase 2, consider these extensions:

1. **Dynamic Configuration**: Create a gRPC API to configure the XDP program at runtime
2. **QUIC Integration**: Add support for detecting NDN over QUIC
3. **ML-Based Forwarding**: Use machine learning models to make intelligent forwarding decisions

## Technical Details

### XDP Attachment Modes

This program supports three XDP attachment modes:

1. **Native/Driver Mode** (`-d`): Fastest performance, requires driver support
2. **SKB/Generic Mode** (`-s`): Works with any interface, slower performance
3. **Hardware Offload** (`-H`): Offloads processing to NIC hardware, requires hardware support

### NDN TLV Parsing

The XDP program implements efficient NDN TLV parsing with these key functions:

- `parse_tlv_type()`: Extract TLV type field
- `parse_tlv_length()`: Extract and validate TLV length field
- `parse_ndn_name()`: Parse NDN name components from TLV buffer

### Performance Considerations

- **Map Size**: The default LRU cache size is 1024 entries, which can be adjusted in `ndn_xdp.c`
- **Bounds Checking**: Extensive bounds checking ensures safety but adds overhead
- **Packet Loops**: Be careful when redirecting packets to avoid forwarding loops

## Troubleshooting

### Common Issues

1. **"Cannot attach XDP program"**:
   - Try using SKB/generic mode (`-s` flag)
   - Check if the interface supports XDP
   - Ensure you're running as root

2. **"Failed to load BPF program"**:
   - Check kernel version (requires 5.3+)
   - Check compiler version (clang 10+)
   - Run `dmesg` to see kernel verification errors

3. **"No packets are being processed"**:
   - Verify packets are being sent to the correct interface and port
   - Check interface is up (`ip link show`)
   - Use tcpdump to confirm packets are arriving
