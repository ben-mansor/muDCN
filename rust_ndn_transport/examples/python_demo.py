#!/usr/bin/env python3
"""
μDCN Python Transport Demo

This script demonstrates the use of μDCN transport from Python.
It sets up a server and client instance that communicate using NDN over QUIC.
"""

import os
import sys
import time
import threading
import logging
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
logger = logging.getLogger("udcn-python-demo")

class ContentRepository:
    """Simple content repository for serving NDN data."""
    
    def __init__(self):
        self.content = {}
        
    def add_content(self, name: str, content: bytes):
        """Add content to the repository."""
        self.content[name] = content
        logger.info(f"Added content: {name} ({len(content)} bytes)")
        
    def get_content(self, name: str) -> bytes:
        """Get content from the repository."""
        return self.content.get(name, b"Not Found")

def interest_handler(interest_bytes: bytes) -> bytes:
    """Handle an incoming interest packet."""
    # Parse the interest
    interest = parse_interest(interest_bytes)
    name = interest['name']
    
    logger.info(f"Received interest for: {name}")
    
    # Check if we have content for this name
    if name in repository.content:
        content = repository.get_content(name)
        # Create and return data packet
        return create_data(name, content, freshness_sec=10)
    else:
        # Create a data packet with an error message
        return create_data(name, b"Content not found", freshness_sec=1)

def run_server():
    """Run the server that responds to interests."""
    # Create transport instance
    config = {
        "bind_address": "127.0.0.1:6363",
        "mtu": 1400,
        "enable_metrics": True
    }
    
    transport = UdcnTransport(config)
    
    try:
        # Start the transport
        transport.start()
        logger.info("Server started on 127.0.0.1:6363")
        
        # Register a prefix
        transport.register_prefix("/demo", interest_handler)
        logger.info("Registered prefix: /demo")
        
        # Keep the server running
        while True:
            time.sleep(1)
            # Periodically log metrics
            metrics = transport.get_metrics()
            logger.debug(f"Current metrics: {metrics}")
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    finally:
        # Clean up
        transport.stop()
        logger.info("Server stopped")

def run_client():
    """Run a client that sends interests."""
    # Wait for server to start
    time.sleep(2)
    
    # Create transport instance
    config = {
        "bind_address": "127.0.0.1:0",  # Use ephemeral port
        "mtu": 1400
    }
    
    transport = UdcnTransport(config)
    
    try:
        # Start the transport
        transport.start()
        logger.info("Client started")
        
        # Send interests to the server
        server_addr = "127.0.0.1:6363"
        
        for i in range(5):
            name = f"/demo/content{i}"
            logger.info(f"Sending interest for: {name}")
            
            # Create interest
            interest = create_interest(name)
            
            try:
                # Send interest and get data
                response_bytes = transport.send_interest(server_addr, interest)
                
                # Parse data
                data = parse_data(response_bytes)
                content = data['content']
                
                logger.info(f"Received data for {data['name']}: {content.decode('utf-8')}")
            except Exception as e:
                logger.error(f"Error sending interest: {e}")
            
            # Wait a bit between interests
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        logger.info("Client shutting down...")
    finally:
        # Clean up
        transport.stop()
        logger.info("Client stopped")

if __name__ == "__main__":
    # Create content repository
    repository = ContentRepository()
    
    # Add some test content
    for i in range(5):
        name = f"/demo/content{i}"
        content = f"This is test content #{i} for μDCN transport demo".encode('utf-8')
        repository.add_content(name, content)
    
    # Start server in a separate thread
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Run client
    run_client()
    
    # Wait for server to finish (it won't, since it's a daemon thread)
    try:
        server_thread.join(timeout=1)
    except KeyboardInterrupt:
        print("Exiting...")
    
    print("Demo completed!")
