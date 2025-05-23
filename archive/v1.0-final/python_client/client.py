#!/usr/bin/env python3
"""
µDCN Python gRPC Client Example

This script demonstrates how to interact with the Rust gRPC server
using Python bindings. It performs basic operations like querying 
transport state and creating QUIC connections.
"""

import sys
import grpc
import argparse
from datetime import datetime

# Import generated protobuf/gRPC code
# Note: In a real implementation, this would be generated using grpcio-tools
# but for this demo we'll assume it's already generated
sys.path.append('../proto_gen/python')
import udcn_pb2
import udcn_pb2_grpc

class UdcnClient:
    """Client for interacting with the µDCN transport gRPC server."""
    
    def __init__(self, server_address):
        """Initialize the client with the server address."""
        self.channel = grpc.insecure_channel(server_address)
        self.stub = udcn_pb2_grpc.UdcnControlStub(self.channel)
    
    def get_transport_state(self, include_details=False):
        """Query the current state of the transport layer."""
        request = udcn_pb2.TransportStateRequest(
            include_detailed_stats=include_details
        )
        
        try:
            response = self.stub.GetTransportState(request)
            
            # Print basic information
            print(f"Transport State: {response.state}")
            print(f"Uptime: {response.uptime_seconds} seconds")
            print(f"Interests Processed: {response.interests_processed}")
            print(f"Data Packets Sent: {response.data_packets_sent}")
            print(f"Cache Hit Ratio: {response.cache_hit_ratio:.2f}")
            
            # Print detailed stats if requested
            if include_details and response.detailed_stats:
                print("\nDetailed Statistics:")
                for key, value in response.detailed_stats.items():
                    print(f"  {key}: {value}")
            
            return response
            
        except grpc.RpcError as e:
            print(f"Error getting transport state: {e.details()}")
            return None
    
    def create_quic_connection(self, peer_address, port):
        """Create a QUIC connection to a remote NDN router."""
        request = udcn_pb2.QuicConnectionRequest(
            peer_address=peer_address,
            port=port,
            client_name="python-client"
        )
        
        try:
            response = self.stub.CreateQuicConnection(request)
            
            if response.success:
                print(f"Connection established successfully!")
                print(f"Connection ID: {response.connection_id}")
                print(f"Remote Address: {response.remote_address}")
                print(f"Connection Quality: {response.quality}")
                print(f"Timestamp: {datetime.fromtimestamp(response.timestamp_ms/1000)}")
                return response.connection_id
            else:
                print(f"Connection failed: {response.error_message}")
                return None
                
        except grpc.RpcError as e:
            print(f"Error creating QUIC connection: {e.details()}")
            return None
    
    def send_interest(self, connection_id, name, lifetime_ms=4000):
        """Send an NDN interest packet over the QUIC connection."""
        request = udcn_pb2.InterestPacketRequest(
            connection_id=connection_id,
            name=name,
            lifetime_ms=lifetime_ms
        )
        
        try:
            response = self.stub.SendInterest(request)
            
            if response.success:
                print(f"Received data for {response.name}")
                print(f"Content size: {len(response.content)} bytes")
                print(f"Content type: {response.content_type}")
                print(f"Freshness period: {response.freshness_period} ms")
                
                # Print first 100 bytes of content (if binary, show hex)
                if len(response.content) > 0:
                    preview = response.content[:100]
                    try:
                        print(f"Content preview: {preview.decode('utf-8')}")
                    except UnicodeDecodeError:
                        print(f"Content preview (hex): {preview.hex()}")
                
                return response
            else:
                print(f"Interest failed: {response.error_message}")
                return None
                
        except grpc.RpcError as e:
            print(f"Error sending interest: {e.details()}")
            return None
    
    def configure_xdp(self, interface_name, program_path, mode=0):
        """Configure and load an XDP program on a network interface."""
        request = udcn_pb2.XdpConfigRequest(
            interface_name=interface_name,
            program_path=program_path,
            mode=mode,
            map_pins={}
        )
        
        try:
            response = self.stub.ConfigureXdp(request)
            
            if response.success:
                print(f"XDP program loaded successfully!")
                print(f"Program ID: {response.program_id}")
                print(f"Interface: {response.interface_name}")
                print(f"Mode: {response.mode}")
                return response.program_id
            else:
                print(f"XDP configuration failed: {response.error_message}")
                return None
                
        except grpc.RpcError as e:
            print(f"Error configuring XDP: {e.details()}")
            return None
    
    def close(self):
        """Close the gRPC channel."""
        self.channel.close()

def main():
    """Main entry point for the client example."""
    parser = argparse.ArgumentParser(description="µDCN Python gRPC Client")
    parser.add_argument("--server", default="localhost:50051", help="gRPC server address")
    parser.add_argument("--verbose", action="store_true", help="Display detailed information")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # State command
    state_parser = subparsers.add_parser("state", help="Get transport state")
    
    # QUIC connection command
    quic_parser = subparsers.add_parser("connect", help="Create QUIC connection")
    quic_parser.add_argument("--peer", required=True, help="Peer address")
    quic_parser.add_argument("--port", type=int, default=6363, help="Peer port")
    
    # Send interest command
    interest_parser = subparsers.add_parser("interest", help="Send NDN interest")
    interest_parser.add_argument("--conn", required=True, help="Connection ID")
    interest_parser.add_argument("--name", required=True, help="NDN name")
    
    # XDP configuration command
    xdp_parser = subparsers.add_parser("xdp", help="Configure XDP program")
    xdp_parser.add_argument("--interface", required=True, help="Network interface")
    xdp_parser.add_argument("--program", required=True, help="Path to XDP program")
    
    args = parser.parse_args()
    
    # Create client
    client = UdcnClient(args.server)
    
    try:
        if args.command == "state":
            client.get_transport_state(args.verbose)
        elif args.command == "connect":
            client.create_quic_connection(args.peer, args.port)
        elif args.command == "interest":
            client.send_interest(args.conn, args.name)
        elif args.command == "xdp":
            client.configure_xdp(args.interface, args.program)
        else:
            # Default: show transport state
            client.get_transport_state(args.verbose)
    finally:
        client.close()

if __name__ == "__main__":
    main()
