#!/usr/bin/env python3
"""
μDCN ML-based MTU Prediction Demo

This example demonstrates how to use ML-based MTU prediction with
the μDCN transport layer to optimize NDN performance based on
network conditions.
"""

import os
import sys
import time
import threading
import logging
import json
from typing import Dict, Any

# Make sure the library is in the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Try to import the μDCN transport module
try:
    from udcn_transport import UdcnTransport, create_interest, create_data, parse_data, parse_interest
except ImportError:
    print("Error: Could not import udcn_transport module.")
    print("Make sure the Rust library has been built with Python bindings enabled:")
    print("  cargo build --features extension-module")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("udcn-ml-mtu-demo")

class NetworkEmulator:
    """Simple network condition emulator for testing MTU adaptation"""
    
    def __init__(self):
        self.current_scenario = "good"
        self.scenarios = {
            "good": {
                "rtt_ms": 20,
                "packet_loss_rate": 0.001,
                "throughput_mbps": 100,
                "network_type": 1,  # Ethernet
                "description": "Low latency, high bandwidth Ethernet connection"
            },
            "wifi": {
                "rtt_ms": 40,
                "packet_loss_rate": 0.01,
                "throughput_mbps": 50,
                "network_type": 2,  # WiFi
                "description": "Typical home WiFi connection"
            },
            "mobile": {
                "rtt_ms": 100,
                "packet_loss_rate": 0.03,
                "throughput_mbps": 10,
                "network_type": 3,  # Cellular
                "description": "4G mobile connection with some packet loss"
            },
            "congested": {
                "rtt_ms": 150,
                "packet_loss_rate": 0.05,
                "throughput_mbps": 5,
                "network_type": 1,  # Ethernet but congested
                "description": "Congested network with high latency and loss"
            },
            "satellite": {
                "rtt_ms": 600,
                "packet_loss_rate": 0.02,
                "throughput_mbps": 20,
                "network_type": 4,  # Satellite
                "description": "Satellite connection with very high latency"
            }
        }
        
    def get_current_scenario(self) -> Dict[str, Any]:
        """Get the current network condition scenario"""
        return self.scenarios[self.current_scenario]
    
    def set_scenario(self, scenario_name: str) -> bool:
        """Change the current network condition scenario"""
        if scenario_name in self.scenarios:
            logger.info(f"Changing network scenario to: {scenario_name}")
            self.current_scenario = scenario_name
            return True
        return False
    
    def next_scenario(self) -> str:
        """Rotate to the next network scenario"""
        scenario_names = list(self.scenarios.keys())
        current_index = scenario_names.index(self.current_scenario)
        next_index = (current_index + 1) % len(scenario_names)
        self.current_scenario = scenario_names[next_index]
        return self.current_scenario


def interest_handler(interest_bytes: bytes) -> bytes:
    """Handle an incoming interest packet"""
    # Parse the interest
    interest = parse_interest(interest_bytes)
    name = interest['name']
    
    logger.info(f"Received interest for: {name}")
    
    # Get current network conditions
    scenario = network_emulator.get_current_scenario()
    
    # Create a data packet with network condition information
    content = json.dumps({
        "name": name,
        "network_conditions": scenario,
        "timestamp": time.time(),
        "mtu": server_transport.get_current_mtu()
    }).encode('utf-8')
    
    # Artificial delay based on RTT
    time.sleep(scenario["rtt_ms"] / 1000.0)
    
    # Simulate packet loss
    if scenario["packet_loss_rate"] > 0:
        import random
        if random.random() < scenario["packet_loss_rate"]:
            logger.warning(f"Simulating packet loss for {name}")
            return create_data(name, b"PACKET_LOSS", freshness_sec=1)
    
    return create_data(name, content, freshness_sec=10)


def run_server():
    """Run the server that responds to interests with ML-based MTU optimization"""
    global server_transport
    
    # Create transport instance with ML-based MTU prediction enabled
    config = {
        "bind_address": "127.0.0.1:6363",
        "mtu": 1400,
        "enable_metrics": True,
        "enable_ml_mtu_prediction": True,
        "ml_prediction_interval": 5,  # Check every 5 seconds
        "ml_model_type": "ensemble",  # Use ensemble model
        "min_mtu": 576,
        "max_mtu": 9000
    }
    
    server_transport = UdcnTransport(config)
    
    try:
        # Start the transport
        server_transport.start()
        logger.info("Server started on 127.0.0.1:6363")
        
        # Register a prefix
        server_transport.register_prefix("/udcn/mtu-demo", interest_handler)
        logger.info("Registered prefix: /udcn/mtu-demo")
        
        # Keep the server running
        while True:
            time.sleep(1)
            
            # Periodically log metrics
            metrics = server_transport.get_metrics()
            logger.debug(f"Current metrics: {metrics}")
            
            # Log current MTU
            current_mtu = server_transport.get_current_mtu()
            logger.info(f"Current MTU: {current_mtu}")
            
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    finally:
        # Clean up
        server_transport.stop()
        logger.info("Server stopped")


def run_client():
    """Run a client that sends interests and receives data"""
    # Wait for server to start
    time.sleep(2)
    
    # Create transport instance
    config = {
        "bind_address": "127.0.0.1:0",  # Use ephemeral port
        "mtu": 1400
    }
    
    client_transport = UdcnTransport(config)
    
    try:
        # Start the transport
        client_transport.start()
        logger.info("Client started")
        
        # Send interests to the server
        server_addr = "127.0.0.1:6363"
        
        # Send interests continuously, changing network conditions every 20 interests
        interest_count = 0
        
        while True:
            # Change network conditions every 20 interests
            if interest_count % 20 == 0:
                scenario = network_emulator.next_scenario()
                logger.info(f"Switched to network scenario: {scenario}")
                logger.info(f"Conditions: {network_emulator.get_current_scenario()['description']}")
            
            interest_count += 1
            name = f"/udcn/mtu-demo/request{interest_count}"
            logger.info(f"Sending interest for: {name}")
            
            # Create interest
            interest = create_interest(name)
            
            try:
                # Send interest and get data
                response_bytes = client_transport.send_interest(server_addr, interest)
                
                # Parse data
                data = parse_data(response_bytes)
                content = data['content']
                
                # Try to parse as JSON
                try:
                    response_data = json.loads(content.decode('utf-8'))
                    logger.info(f"Response MTU: {response_data['mtu']}, " +
                               f"Network: {response_data['network_conditions']['description']}")
                except:
                    logger.info(f"Received data: {content.decode('utf-8', errors='replace')}")
                    
            except Exception as e:
                logger.error(f"Error sending interest: {e}")
            
            # Wait between interests
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Client shutting down...")
    finally:
        # Clean up
        client_transport.stop()
        logger.info("Client stopped")


if __name__ == "__main__":
    # Create network emulator
    network_emulator = NetworkEmulator()
    server_transport = None
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='μDCN ML-based MTU Prediction Demo')
    parser.add_argument('--mode', choices=['server', 'client', 'both'], default='both',
                       help='Run as server, client, or both')
    args = parser.parse_args()
    
    # Start server and/or client
    if args.mode in ('server', 'both'):
        server_thread = threading.Thread(target=run_server)
        server_thread.daemon = True
        server_thread.start()
        
    if args.mode in ('client', 'both'):
        if args.mode == 'both':
            # Give the server time to start
            time.sleep(2)
        run_client()
        
    # Wait for server to finish (it won't, since it's a daemon thread)
    if args.mode in ('server', 'both'):
        try:
            server_thread.join()
        except KeyboardInterrupt:
            print("Exiting...")
