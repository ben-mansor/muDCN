#!/usr/bin/env python3
# MTU Prediction Test Script for μDCN
# This script feeds synthetic network metrics to the ML model and logs predictions

import os
import sys
import time
import json
import random
import argparse
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from concurrent import futures

# Add parent directory to Python path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Import ML integration
from python_client.ml_integration import MLIntegration

# Import gRPC components
import grpc
from proto import udcn_pb2
from proto import udcn_pb2_grpc

class MTUTestRunner:
    """Test runner for MTU prediction model evaluation"""
    
    def __init__(self, use_grpc=False, server_addr="localhost:50051"):
        """
        Initialize the test runner
        
        Args:
            use_grpc (bool): Whether to use gRPC for MTU prediction
            server_addr (str): gRPC server address (host:port)
        """
        self.use_grpc = use_grpc
        self.server_addr = server_addr
        self.grpc_client = None
        
        if use_grpc:
            try:
                channel = grpc.insecure_channel(server_addr)
                self.grpc_client = udcn_pb2_grpc.UdcnControlStub(channel)
                print(f"Connected to gRPC server at {server_addr}")
            except Exception as e:
                print(f"Failed to connect to gRPC server: {e}")
                self.use_grpc = False
        
        # Initialize ML integration
        self.ml_integration = MLIntegration(self.grpc_client)
        
        # Results collection
        self.results = []
        self.start_time = time.time()
    
    def generate_synthetic_metrics(self, duration_sec=60, interval_sec=1.0, 
                                 scenario='random', interface='eth0'):
        """
        Generate and feed synthetic network metrics
        
        Args:
            duration_sec (int): Duration of test in seconds
            interval_sec (float): Interval between measurements
            scenario (str): Test scenario ('random', 'deteriorating', 'improving', 'fluctuating')
            interface (str): Network interface name
            
        Returns:
            list: Test results
        """
        print(f"Running {scenario} test scenario for {duration_sec} seconds...")
        
        # Initialize metrics
        if scenario == 'deteriorating':
            rtt_ms = 10.0
            loss_rate = 0.001
            throughput_mbps = 500.0
        elif scenario == 'improving':
            rtt_ms = 250.0
            loss_rate = 0.08
            throughput_mbps = 10.0
        elif scenario == 'fluctuating':
            rtt_ms = 100.0
            loss_rate = 0.02
            throughput_mbps = 100.0
        else:  # random
            rtt_ms = random.uniform(10, 250)
            loss_rate = random.uniform(0.001, 0.08)
            throughput_mbps = random.uniform(10, 500)
        
        # Scenario parameters
        if scenario == 'deteriorating':
            rtt_step = 4.0  # ms per step
            loss_step = 0.001  # percentage points per step
            tput_step = -8.0  # mbps per step
        elif scenario == 'improving':
            rtt_step = -4.0  # ms per step
            loss_step = -0.001  # percentage points per step
            tput_step = 8.0  # mbps per step
        elif scenario == 'fluctuating':
            # Will use sin wave for fluctuation
            pass
        else:  # random
            # Will use random changes
            pass
        
        # Connection IDs for test
        connection_ids = [f"conn-{i}" for i in range(1, 6)]
        
        # Run test loop
        steps = int(duration_sec / interval_sec)
        iteration = 0
        
        while iteration < steps:
            # Update metrics based on scenario
            if scenario == 'deteriorating' or scenario == 'improving':
                rtt_ms += rtt_step
                loss_rate += loss_step
                throughput_mbps += tput_step
                
                # Clamp values to reasonable ranges
                rtt_ms = max(5, min(300, rtt_ms))
                loss_rate = max(0.0001, min(0.1, loss_rate))
                throughput_mbps = max(5, min(600, throughput_mbps))
                
            elif scenario == 'fluctuating':
                # Use sin waves with different periods for realistic fluctuation
                phase = iteration / steps * 2 * np.pi
                rtt_ms = 100 + 90 * np.sin(phase)
                loss_rate = 0.02 + 0.018 * np.sin(phase * 1.5)
                throughput_mbps = 100 + 90 * np.sin(phase * 0.7)
                
            else:  # random
                # Random walk with bounds
                rtt_ms += random.uniform(-20, 20)
                loss_rate += random.uniform(-0.005, 0.005)
                throughput_mbps += random.uniform(-50, 50)
                
                # Clamp values to reasonable ranges
                rtt_ms = max(5, min(300, rtt_ms))
                loss_rate = max(0.0001, min(0.1, loss_rate))
                throughput_mbps = max(5, min(600, throughput_mbps))
            
            # Choose a random connection for this iteration
            conn_id = random.choice(connection_ids)
            
            # Predict MTU using local ML integration or gRPC
            if self.use_grpc:
                try:
                    # Use gRPC for prediction
                    request = udcn_pb2.MtuPredictionRequest(
                        rtt_ms=float(rtt_ms),
                        packet_loss_rate=float(loss_rate),
                        throughput_mbps=float(throughput_mbps),
                        connection_id=conn_id,
                        interface_name=interface
                    )
                    response = self.grpc_client.PredictMtu(request)
                    
                    result = {
                        "timestamp": time.time(),
                        "iteration": iteration,
                        "inputs": {
                            "rtt_ms": rtt_ms,
                            "packet_loss_rate": loss_rate,
                            "throughput_mbps": throughput_mbps
                        },
                        "connection_id": conn_id,
                        "interface_name": interface,
                        "scenario": scenario,
                        "predicted_mtu": response.predicted_mtu,
                        "is_override": response.is_override,
                        "confidence": response.confidence,
                        "inference_time_ms": response.inference_time_ms
                    }
                except Exception as e:
                    print(f"gRPC error: {e}")
                    result = None
            else:
                # Use local ML integration
                result = self.ml_integration.predict_mtu(
                    rtt_ms, loss_rate, throughput_mbps, conn_id, interface
                )
                result.update({
                    "iteration": iteration,
                    "scenario": scenario
                })
            
            if result:
                self.results.append(result)
                print(f"Iteration {iteration}: RTT={rtt_ms:.1f}ms, Loss={loss_rate:.4f}, "
                      f"Throughput={throughput_mbps:.1f}Mbps → MTU={result['predicted_mtu']}")
            
            # Sleep until next interval
            iteration += 1
            time.sleep(interval_sec)
        
        return self.results
    
    def visualize_results(self, output_dir=None):
        """
        Visualize test results
        
        Args:
            output_dir (str): Output directory for plots
        """
        if not self.results:
            print("No results to visualize")
            return
        
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(__file__), 'test_results')
        os.makedirs(output_dir, exist_ok=True)
        
        # Extract data
        iterations = [r["iteration"] for r in self.results]
        rtts = [r["inputs"]["rtt_ms"] for r in self.results]
        loss_rates = [r["inputs"]["packet_loss_rate"] for r in self.results]
        throughputs = [r["inputs"]["throughput_mbps"] for r in self.results]
        mtus = [r["predicted_mtu"] for r in self.results]
        
        # Create figure for metrics and MTU
        plt.figure(figsize=(15, 10))
        
        # Plot network metrics
        plt.subplot(2, 1, 1)
        plt.plot(iterations, rtts, 'r-', label='RTT (ms)')
        plt.plot(iterations, [t/5 for t in throughputs], 'g-', label='Throughput/5 (Mbps)')
        plt.plot(iterations, [l*1000 for l in loss_rates], 'b-', label='Loss Rate×1000')
        plt.xlabel('Iteration')
        plt.ylabel('Value')
        plt.title('Network Metrics')
        plt.legend()
        plt.grid(True)
        
        # Plot predicted MTU
        plt.subplot(2, 1, 2)
        plt.plot(iterations, mtus, 'k-', linewidth=2)
        plt.xlabel('Iteration')
        plt.ylabel('MTU')
        plt.title('Predicted MTU')
        plt.yticks([576, 1280, 1400, 1500, 3000, 9000])
        plt.grid(True)
        
        # Save figure
        scenario = self.results[0]["scenario"]
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'mtu_prediction_{scenario}.png'))
        plt.close()
        
        # Export results to JSON
        with open(os.path.join(output_dir, f'mtu_prediction_{scenario}.json'), 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Results visualized and saved to {output_dir}")
    
    def run_all_scenarios(self, duration_sec=30, interval_sec=0.5):
        """
        Run all test scenarios
        
        Args:
            duration_sec (int): Duration per scenario in seconds
            interval_sec (float): Interval between measurements
        """
        scenarios = ['random', 'deteriorating', 'improving', 'fluctuating']
        
        for scenario in scenarios:
            self.results = []  # Reset results
            self.generate_synthetic_metrics(
                duration_sec=duration_sec, 
                interval_sec=interval_sec,
                scenario=scenario
            )
            self.visualize_results()
    
    def test_mtu_override(self, interface='eth0'):
        """Test MTU override functionality"""
        print("\nTesting MTU override functionality:")
        
        # Get baseline prediction
        rtt_ms = 10.0
        loss_rate = 0.001
        throughput_mbps = 500.0
        conn_id = "conn-1"
        
        # Baseline prediction
        print("\nBaseline prediction:")
        result = self.ml_integration.predict_mtu(
            rtt_ms, loss_rate, throughput_mbps, conn_id, interface
        )
        print(f"RTT={rtt_ms}ms, Loss={loss_rate}, Throughput={throughput_mbps}Mbps "
              f"→ MTU={result['predicted_mtu']}")
        
        # Set override
        override_mtu = 1400
        print(f"\nSetting override to {override_mtu}:")
        if self.use_grpc:
            try:
                request = udcn_pb2.MtuOverrideRequest(
                    enable_override=True,
                    mtu_value=override_mtu
                )
                response = self.grpc_client.SetMtuOverride(request)
                print(f"Override set: {response.override_active}")
            except Exception as e:
                print(f"gRPC error: {e}")
        else:
            success = self.ml_integration.set_mtu_override(True, override_mtu)
            print(f"Override set: {success}")
        
        # Test prediction with override
        print("\nPrediction with override:")
        result = self.ml_integration.predict_mtu(
            rtt_ms, loss_rate, throughput_mbps, conn_id, interface
        )
        print(f"RTT={rtt_ms}ms, Loss={loss_rate}, Throughput={throughput_mbps}Mbps "
              f"→ MTU={result['predicted_mtu']} (override)")
        
        # Disable override
        print("\nDisabling override:")
        if self.use_grpc:
            try:
                request = udcn_pb2.MtuOverrideRequest(
                    enable_override=False
                )
                response = self.grpc_client.SetMtuOverride(request)
                print(f"Override disabled: {not response.override_active}")
            except Exception as e:
                print(f"gRPC error: {e}")
        else:
            success = self.ml_integration.set_mtu_override(False)
            print(f"Override disabled: {success}")
        
        # Test prediction without override
        print("\nPrediction after disabling override:")
        result = self.ml_integration.predict_mtu(
            rtt_ms, loss_rate, throughput_mbps, conn_id, interface
        )
        print(f"RTT={rtt_ms}ms, Loss={loss_rate}, Throughput={throughput_mbps}Mbps "
              f"→ MTU={result['predicted_mtu']}")

def main():
    parser = argparse.ArgumentParser(description='MTU Prediction Test Script')
    parser.add_argument('--grpc', action='store_true', help='Use gRPC for predictions')
    parser.add_argument('--server', default='localhost:50051', help='gRPC server address')
    parser.add_argument('--duration', type=int, default=60, help='Test duration in seconds')
    parser.add_argument('--interval', type=float, default=1.0, help='Measurement interval in seconds')
    parser.add_argument('--scenario', choices=['random', 'deteriorating', 'improving', 'fluctuating', 'all'],
                        default='random', help='Test scenario')
    parser.add_argument('--interface', default='eth0', help='Network interface name')
    parser.add_argument('--override', action='store_true', help='Test MTU override functionality')
    
    args = parser.parse_args()
    
    # Initialize test runner
    test_runner = MTUTestRunner(use_grpc=args.grpc, server_addr=args.server)
    
    if args.override:
        # Test MTU override
        test_runner.test_mtu_override(args.interface)
    elif args.scenario == 'all':
        # Run all scenarios
        test_runner.run_all_scenarios(args.duration, args.interval)
    else:
        # Run single scenario
        test_runner.generate_synthetic_metrics(
            duration_sec=args.duration,
            interval_sec=args.interval,
            scenario=args.scenario,
            interface=args.interface
        )
        test_runner.visualize_results()

if __name__ == "__main__":
    main()
