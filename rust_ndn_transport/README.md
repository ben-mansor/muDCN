# μDCN Transport Layer

A high-performance Named Data Networking (NDN) transport layer implementation using Rust and QUIC with ML-based optimizations and XDP acceleration.

## Project Status

- ✅ **Phase 1: Initial Setup & Architecture Design** - Completed
- ✅ **Phase 2: Rust gRPC Server Implementation** - Completed (v0.2)
- ✅ **Phase 3: QUIC Transport Layer Implementation** - Completed (v0.3)
- ✅ **Phase 4: ML-based MTU Prediction** - Completed (v0.4)
- ⬜ **Phase 5: XDP Acceleration** - Pending

## Architecture Overview

The μDCN transport layer is designed as a modular, high-performance NDN implementation that combines several advanced technologies:

1. **Core NDN Protocol**: Implements the NDN protocol for interest/data packet exchange
2. **QUIC Transport**: Uses QUIC for reliable, secure, and multiplexed transport
3. **ML-based MTU Optimization**: Dynamically adjusts Maximum Transmission Unit based on network conditions
4. **XDP Acceleration**: Leverages eBPF/XDP for kernel-level packet processing
5. **Python Bindings**: Provides seamless integration with Python control plane applications

### System Architecture Diagram

```
+----------------------------------+
|         Control Applications     |
|          (Python/Rust)          |
+----------------------------------+
               |
+----------------------------------+
|        Python Bindings (PyO3)    |
+----------------------------------+
               |
+---------------+-------------------+
|                                  |
|    μDCN Transport Layer (Rust)   |
|                                  |
+---------------+-------------------+
        |                |
+---------------+  +---------------+
| QUIC Engine   |  | ML-based MTU  |
|               |  | Prediction    |
+---------------+  +---------------+
        |                |
+---------------+  +---------------+
| Fragmentation |  | XDP/eBPF      |
| Module        |  | Acceleration  |
+---------------+  +---------------+
        |                |
+----------------------------------+
|           Network Layer          |
+----------------------------------+
```

## Key Components

### 1. QUIC Transport Engine

The QUIC engine provides a reliable, secure, and multiplexed transport layer with the following features:

- Connection state tracking (Connected, Idle, Closing, Failed)
- Congestion control with AIMD (Additive Increase, Multiplicative Decrease)
- Connection statistics collection for QoS monitoring
- Auto-reconnect and connection maintenance

### 2. ML-based MTU Prediction

The ML-based MTU prediction system optimizes network performance by dynamically adjusting the MTU based on current network conditions:

- Multiple ML model implementations (rule-based, linear regression, ensemble)
- Feature extraction from network statistics
- Adaptive prediction intervals
- Integration with Python ML frameworks through PyO3

### 3. XDP Acceleration

The XDP acceleration module offloads packet processing to the Linux kernel for increased performance:

- High-performance content store in kernel space
- Interest name matching in kernel space
- Hardware offload support (where available)
- Performance metrics collection

### 4. Fragmentation Module

Handles packet fragmentation and reassembly for oversized NDN packets:

- Adaptive MTU tracking
- Fragment sequencing and reassembly
- Loss detection and recovery
- Integration with ML-based MTU prediction

### 5. Python Bindings

Comprehensive Python bindings that expose the core functionality to Python applications:

- NDN packet creation and parsing
- Transport configuration and management
- Interest/data exchange
- Metrics collection

### 6. gRPC Server

The gRPC server provides a standardized interface for controlling the transport layer from external applications:

- Secure and efficient RPC-based communication
- Remote configuration and monitoring
- QUIC connection management
- XDP program configuration and statistics
- Streaming metrics and notifications

#### Building and Running the gRPC Server

```bash
# Build the gRPC server (with tokio-test feature for running tests)
cd rust_ndn_transport
cargo build --release --features="tokio-test"

# Run the server on default port (50051)
cargo run --release --bin grpc_server

# Run with custom address and port
cargo run --release --bin grpc_server -- --address 0.0.0.0 --port 8080 --debug
```

#### Using the Python Client

The repository includes a Python client for interacting with the gRPC server:

```bash
# First, generate Python bindings from the proto file
cd python_client
pip install grpcio grpcio-tools
python generate_proto.py

# Query the transport state
python client.py --server localhost:50051 state

# Create a QUIC connection
python client.py --server localhost:50051 connect --peer 192.168.1.10 --port 6363

# Send an Interest
python client.py --server localhost:50051 interest --conn CONNECTION_ID --name /example/data

# Configure XDP
python client.py --server localhost:50051 xdp --interface eth0 --program /path/to/xdp_program.o
```

## ML-based MTU Prediction

The ML-based MTU prediction system is a key innovation in the μDCN transport layer. It monitors network conditions and adjusts the MTU dynamically to optimize performance.

### Feature Set

The system tracks the following network features:

- Average RTT (Round Trip Time)
- Packet loss rate
- Throughput
- Congestion window size
- Average packet size distribution
- Network type (Ethernet, WiFi, cellular, etc.)

### ML Models

We provide multiple ML model implementations:

1. **Rule-based Model**: Uses heuristics to adjust MTU based on predefined rules
2. **Linear Regression Model**: Simple ML model for resource-constrained environments
3. **Ensemble Model**: Combines multiple models for more accurate predictions

### Integration with XDP

The ML-based MTU prediction system integrates with the XDP acceleration layer to:

- Update kernel-level packet processing parameters
- Optimize content store behavior
- Adjust fragmentation thresholds at the kernel level

## XDP Acceleration

The XDP (eXpress Data Path) acceleration component leverages eBPF technology to process NDN packets directly in the Linux kernel, significantly improving performance:

### Key Features

- **Kernel-level Content Store**: Caches NDN data packets in the kernel for ultra-fast retrieval
- **Interest Name Matching**: Performs prefix matching directly in the kernel
- **Hardware Offload**: Supports XDP hardware offload on compatible NICs
- **Dynamic Configuration**: Runtime adjustment of parameters (e.g., content store size)

### Integration with ML

The XDP module interfaces with the ML-based MTU prediction system through:

- Shared memory for configuration updates
- eBPF map-based communication
- Kernel-space metrics collection

## Usage Examples

### Basic Usage

```rust
use udcn_transport::{Config, UdcnTransport, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Configure the transport
    let mut config = Config::default();
    config.bind_address = "127.0.0.1".to_string();
    config.port = 6363;
    config.enable_ml_mtu_prediction = true;
    config.ml_model_type = "ensemble".to_string();
    
    // Create and start the transport
    let transport = UdcnTransport::new(config).await?;
    transport.start().await?;
    
    // Register a prefix
    transport.register_prefix("/example/prefix", |interest| {
        // Handle interest and return data
        // ...
    }).await?;
    
    // Run indefinitely
    tokio::signal::ctrl_c().await?;
    transport.stop().await?;
    
    Ok(())
}
```

### Python Usage

```python
from udcn_transport import UdcnTransport, create_interest, create_data

# Configure the transport
config = {
    "bind_address": "127.0.0.1:6363",
    "mtu": 1400,
    "enable_ml_mtu_prediction": True,
    "ml_model_type": "ensemble",
    "enable_metrics": True
}

# Create and start the transport
transport = UdcnTransport(config)
transport.start()

# Register a prefix
def handle_interest(interest_bytes):
    interest = parse_interest(interest_bytes)
    # Create response data
    return create_data(interest['name'], b"Hello, NDN!")

transport.register_prefix("/example/prefix", handle_interest)

# Send an interest
interest = create_interest("/example/data")
response = transport.send_interest("127.0.0.1:6363", interest)
```

## Benchmarking and Performance

The μDCN transport layer includes comprehensive benchmarking tools to evaluate performance across different network conditions and configurations:

- Network scenario emulation
- Performance metrics collection
- ML model evaluation
- XDP acceleration metrics

To run the benchmark:

```bash
cargo run --example mtu_xdp_integration -- --interface eth0 --ml-model ensemble
```

## Building and Installation

### Prerequisites

- Rust 1.58+
- Python 3.7+ (for Python bindings)
- LLVM/Clang 10+ (for XDP components)
- Linux Kernel 5.10+ (for XDP features)

### Building from Source

```bash
# Build the Rust library
cargo build --release

# Build with Python bindings
cargo build --release --features extension-module

# Install Python package
pip install -e .
```

### Testing

```bash
# Run Rust tests
cargo test

# Run Python binding tests
pytest -xvs python/tests
```

## License

MIT License

## Acknowledgments

This project builds upon research and implementations from:

- Named Data Networking (NDN) Project
- QUIC Protocol
- eBPF and XDP technologies
- ML techniques for network optimization
