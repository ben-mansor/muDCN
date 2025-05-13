#!/usr/bin/env python3
"""
μDCN Testbed Traffic Generator

This script uses TRex to generate high-speed NDN traffic for testing the μDCN architecture.
It can simulate various network conditions like packet loss, delay, and DDoS attacks.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

import numpy as np
import yaml


class TRexController:
    """Controller for TRex traffic generator."""
    
    def __init__(self, config_path: str):
        """
        Initialize the TRex controller.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.trex_server_proc = None
        self.trex_client_proc = None
        
        # Create output directory
        os.makedirs("results", exist_ok=True)
    
    def _load_config(self) -> Dict:
        """
        Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
            
            # Set default values for missing config options
            defaults = {
                "trex_dir": "/opt/trex",
                "server_args": [],
                "duration": 60,
                "rate": "1gbps",
                "packet_size": 1400,
                "interfaces": ["0", "1"],
                "ndn_prefix": "/udcn/test",
                "latency_ms": 0,
                "packet_loss": 0.0,
                "output_file": "results/traffic_test.json",
            }
            
            for key, value in defaults.items():
                if key not in config:
                    config[key] = value
            
            return config
            
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)
    
    def start_server(self):
        """Start the TRex server."""
        try:
            cmd = [
                os.path.join(self.config["trex_dir"], "t-rex-64"),
                "-i",
                "--no-scapy-server",
            ]
            cmd.extend(self.config["server_args"])
            
            print(f"Starting TRex server: {' '.join(cmd)}")
            
            self.trex_server_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.config["trex_dir"],
            )
            
            # Wait for server to start
            time.sleep(5)
            
            if self.trex_server_proc.poll() is not None:
                stderr = self.trex_server_proc.stderr.read().decode("utf-8")
                raise RuntimeError(f"Failed to start TRex server: {stderr}")
            
            print("TRex server started")
            
        except Exception as e:
            print(f"Error starting TRex server: {e}")
            sys.exit(1)
    
    def stop_server(self):
        """Stop the TRex server."""
        if self.trex_server_proc:
            print("Stopping TRex server")
            self.trex_server_proc.send_signal(signal.SIGINT)
            self.trex_server_proc.wait()
            self.trex_server_proc = None
    
    def generate_ndn_traffic(self):
        """Generate NDN traffic using TRex."""
        try:
            # Create a temporary Python script for traffic generation
            script_path = os.path.join("results", "ndn_traffic.py")
            
            with open(script_path, "w") as f:
                f.write(self._generate_trex_script())
            
            # Run the TRex client script
            cmd = [
                sys.executable,
                script_path,
                "--port", "4500",
                "--duration", str(self.config["duration"]),
                "--rate", str(self.config["rate"]),
                "--ndn-prefix", self.config["ndn_prefix"],
                "--packet-size", str(self.config["packet_size"]),
                "--latency", str(self.config["latency_ms"]),
                "--loss", str(self.config["packet_loss"]),
                "--output", self.config["output_file"],
            ]
            
            print(f"Starting TRex client: {' '.join(cmd)}")
            
            self.trex_client_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            # Wait for client to finish
            stdout, stderr = self.trex_client_proc.communicate()
            
            if self.trex_client_proc.returncode != 0:
                print(f"TRex client error: {stderr.decode('utf-8')}")
                return False
            
            print("TRex client completed successfully")
            print(stdout.decode("utf-8"))
            
            # Analyze results
            self._analyze_results()
            
            return True
            
        except Exception as e:
            print(f"Error generating traffic: {e}")
            return False
    
    def _generate_trex_script(self) -> str:
        """
        Generate a TRex Python script for NDN traffic.
        
        Returns:
            TRex Python script
        """
        script = f'''
import argparse
import json
import time
from datetime import datetime
from trex_stl_lib.api import *

class NDNTrafficGenerator:
    """Generate NDN traffic for μDCN testing."""
    
    def __init__(self, port=4500, duration=60, rate="1gbps", 
                 ndn_prefix="/udcn/test", packet_size=1400,
                 latency_ms=0, loss_percent=0, output_file="results.json"):
        self.port = port
        self.duration = duration
        self.rate = rate
        self.ndn_prefix = ndn_prefix
        self.packet_size = packet_size
        self.latency_ms = latency_ms
        self.loss_percent = loss_percent
        self.output_file = output_file
        self.client = None
        self.results = {{
            "timestamp": datetime.now().isoformat(),
            "config": {{
                "duration": duration,
                "rate": rate,
                "ndn_prefix": ndn_prefix,
                "packet_size": packet_size,
                "latency_ms": latency_ms,
                "loss_percent": loss_percent,
            }},
            "metrics": {{}},
        }}
    
    def connect(self):
        """Connect to the TRex server."""
        self.client = STLClient(port=self.port)
        self.client.connect()
        self.client.reset()
        self.client.acquire(force=True)
    
    def create_ndn_stream(self):
        """Create an NDN Interest packet stream."""
        # Create an NDN Interest packet
        interest_size = min(self.packet_size, 1500)
        
        # NDN packet format: TLV with Interest type (0x05)
        ndn_header = b'\\x05\\x{:02x}'.format(len(self.ndn_prefix) + 10)
        
        # Name TLV
        name_tlv = b'\\x07\\x{:02x}'.format(len(self.ndn_prefix))
        
        # Padding to reach desired size
        padding_size = interest_size - len(ndn_header) - len(name_tlv) - len(self.ndn_prefix) - 10
        padding = b'\\x00' * max(0, padding_size)
        
        # Create the base packet
        base_pkt = Ether() / IP() / UDP(dport=6363, sport=12345) / Raw(ndn_header + name_tlv + self.ndn_prefix.encode() + padding)
        
        # Create a packet template
        pkt = STLPktBuilder(pkt=base_pkt)
        
        # Create a stream with the desired rate
        return STLStream(
            packet=pkt,
            mode=STLTXCont(pps=1000000),  # Will be overridden by rate parameter
            flow_stats=STLFlowStats(0)
        )
    
    def run(self):
        """Run the traffic generation."""
        try:
            self.connect()
            
            # Create streams
            stream = self.create_ndn_stream()
            
            # Add the stream
            self.client.add_streams(stream, ports=[0])
            
            # Configure latency and packet loss if needed
            if self.latency_ms > 0 or self.loss_percent > 0:
                print(f"Setting latency: {self.latency_ms}ms, packet loss: {self.loss_percent}%")
                
                self.client.set_service_mode(ports=[1])
                
                self.client.set_port_attr(
                    ports=[1],
                    promiscuous=True
                )
                
                if self.latency_ms > 0:
                    self.client.set_port_attr(
                        ports=[1],
                        lat=self.latency_ms
                    )
                
                if self.loss_percent > 0:
                    self.client.set_port_attr(
                        ports=[1],
                        drop_rate=self.loss_percent
                    )
            
            # Start traffic with the desired rate
            print(f"Starting traffic at {self.rate} for {self.duration} seconds")
            self.client.start(ports=[0], mult=self.rate, duration=self.duration)
            
            # Wait for traffic to complete
            self.client.wait_on_traffic(ports=[0])
            
            # Get statistics
            stats = self.client.get_stats()
            
            # Save results
            self.results["metrics"] = {{
                "tx_packets": stats["total"]["opackets"],
                "tx_bytes": stats["total"]["obytes"],
                "rx_packets": stats["total"]["ipackets"],
                "rx_bytes": stats["total"]["ibytes"],
                "packet_loss": (stats["total"]["opackets"] - stats["total"]["ipackets"]) / max(1, stats["total"]["opackets"]) * 100,
                "tx_pps": stats["total"]["tx_pps"],
                "rx_pps": stats["total"]["rx_pps"],
                "tx_bps": stats["total"]["tx_bps"],
                "rx_bps": stats["total"]["rx_bps"],
            }}
            
            with open(self.output_file, "w") as f:
                json.dump(self.results, f, indent=2)
            
            print(f"Results saved to {self.output_file}")
            
        finally:
            if self.client:
                self.client.disconnect()
    
def main():
    parser = argparse.ArgumentParser(description="Generate NDN traffic for μDCN testing")
    parser.add_argument("--port", type=int, default=4500, help="TRex server port")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--rate", type=str, default="1gbps", help="Traffic rate")
    parser.add_argument("--ndn-prefix", type=str, default="/udcn/test", help="NDN prefix")
    parser.add_argument("--packet-size", type=int, default=1400, help="Packet size in bytes")
    parser.add_argument("--latency", type=float, default=0, help="Latency in ms")
    parser.add_argument("--loss", type=float, default=0, help="Packet loss percentage")
    parser.add_argument("--output", type=str, default="results.json", help="Output file")
    
    args = parser.parse_args()
    
    generator = NDNTrafficGenerator(
        port=args.port,
        duration=args.duration,
        rate=args.rate,
        ndn_prefix=args.ndn_prefix,
        packet_size=args.packet_size,
        latency_ms=args.latency,
        loss_percent=args.loss,
        output_file=args.output
    )
    
    generator.run()

if __name__ == "__main__":
    main()
'''
        return script
    
    def _analyze_results(self):
        """Analyze test results."""
        try:
            with open(self.config["output_file"], "r") as f:
                results = json.load(f)
            
            metrics = results["metrics"]
            
            print("\n===== Test Results =====")
            print(f"Duration: {self.config['duration']} seconds")
            print(f"Rate: {self.config['rate']}")
            print(f"Packet Size: {self.config['packet_size']} bytes")
            print(f"Latency: {self.config['latency_ms']} ms")
            print(f"Packet Loss: {self.config['packet_loss']}%")
            print("\n--- Metrics ---")
            print(f"TX Packets: {metrics['tx_packets']}")
            print(f"RX Packets: {metrics['rx_packets']}")
            print(f"Actual Packet Loss: {metrics['packet_loss']:.2f}%")
            print(f"TX Rate: {metrics['tx_pps']} pps / {metrics['tx_bps'] / 1e9:.2f} Gbps")
            print(f"RX Rate: {metrics['rx_pps']} pps / {metrics['rx_bps'] / 1e9:.2f} Gbps")
            
        except Exception as e:
            print(f"Error analyzing results: {e}")


class DDosSimulator:
    """Simulate DDoS attacks for testing μDCN's resilience."""
    
    def __init__(self, config_path: str):
        """
        Initialize the DDoS simulator.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """
        Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
            
            # Set default values for missing config options
            defaults = {
                "trex_dir": "/opt/trex",
                "attack_type": "interest_flood",
                "attack_rate": "10gbps",
                "attack_duration": 30,
                "target_prefix": "/udcn/test",
                "output_file": "results/ddos_test.json",
            }
            
            for key, value in defaults.items():
                if key not in config:
                    config[key] = value
            
            return config
            
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)
    
    def run_attack(self):
        """Run a DDoS attack simulation."""
        print(f"Simulating {self.config['attack_type']} attack at {self.config['attack_rate']} for {self.config['attack_duration']} seconds")
        
        # Implement attack simulation here
        # This would launch a specific TRex script for the chosen attack


def main():
    parser = argparse.ArgumentParser(description="μDCN Testbed Traffic Generator")
    parser.add_argument("--config", type=str, required=True, help="Path to configuration file")
    parser.add_argument("--mode", type=str, default="normal", choices=["normal", "ddos"], help="Test mode")
    
    args = parser.parse_args()
    
    if args.mode == "normal":
        controller = TRexController(args.config)
        try:
            controller.start_server()
            controller.generate_ndn_traffic()
        finally:
            controller.stop_server()
    else:
        simulator = DDosSimulator(args.config)
        simulator.run_attack()


if __name__ == "__main__":
    main()
