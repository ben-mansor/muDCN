#!/usr/bin/env python3
# Train and Test MTU Prediction Model
# This script trains the TensorFlow model and tests it with various network conditions

import os
import sys
import json
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

# Add the ml_models directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import the MTU predictor
from mtu_predictor import train_model, load_tflite_model, predict_mtu

def main():
    """Train and test the MTU prediction model"""
    print("μDCN MTU Prediction Model Training and Testing")
    print("-" * 50)
    
    # Check if model exists
    model_path = os.path.join(current_dir, "mtu_model.tflite")
    if not os.path.exists(model_path):
        print("Training new model...")
        model = train_model()
        print("Model training complete!")
    else:
        print(f"Found existing model at {model_path}")
    
    # Load TFLite model
    interpreter = load_tflite_model()
    
    # Generate test scenarios
    test_scenarios = [
        {
            "name": "Fast Wired Network",
            "conditions": [
                {"rtt_ms": 5, "loss": 0.0001, "throughput_mbps": 900},
                {"rtt_ms": 10, "loss": 0.0005, "throughput_mbps": 850},
                {"rtt_ms": 15, "loss": 0.001, "throughput_mbps": 800},
            ]
        },
        {
            "name": "Average Home WiFi",
            "conditions": [
                {"rtt_ms": 20, "loss": 0.005, "throughput_mbps": 300},
                {"rtt_ms": 30, "loss": 0.01, "throughput_mbps": 250},
                {"rtt_ms": 40, "loss": 0.015, "throughput_mbps": 200},
            ]
        },
        {
            "name": "Mobile LTE Connection",
            "conditions": [
                {"rtt_ms": 60, "loss": 0.01, "throughput_mbps": 50},
                {"rtt_ms": 80, "loss": 0.02, "throughput_mbps": 40},
                {"rtt_ms": 100, "loss": 0.03, "throughput_mbps": 30},
            ]
        },
        {
            "name": "Poor Connection",
            "conditions": [
                {"rtt_ms": 150, "loss": 0.05, "throughput_mbps": 10},
                {"rtt_ms": 200, "loss": 0.07, "throughput_mbps": 5},
                {"rtt_ms": 250, "loss": 0.09, "throughput_mbps": 2},
            ]
        }
    ]
    
    # Test predictions for each scenario
    results = []
    
    print("\nTesting model with various network conditions:")
    print("-" * 70)
    print("| {:<20} | {:<8} | {:<10} | {:<15} | {:<10} |".format(
        "Scenario", "RTT (ms)", "Loss Rate", "Throughput (Mbps)", "MTU"))
    print("-" * 70)
    
    for scenario in test_scenarios:
        scenario_name = scenario["name"]
        
        for condition in scenario["conditions"]:
            rtt = condition["rtt_ms"]
            loss = condition["loss"]
            throughput = condition["throughput_mbps"]
            
            # Predict MTU
            mtu = predict_mtu(interpreter, rtt, loss, throughput)
            
            # Store result
            result = {
                "scenario": scenario_name,
                "rtt_ms": rtt,
                "loss_rate": loss,
                "throughput_mbps": throughput,
                "predicted_mtu": mtu
            }
            results.append(result)
            
            # Print result
            print("| {:<20} | {:<8.1f} | {:<10.4f} | {:<15.1f} | {:<10d} |".format(
                scenario_name, rtt, loss, throughput, mtu))
    
    print("-" * 70)
    
    # Save results
    with open(os.path.join(current_dir, "prediction_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    
    # Create visualization
    create_visualization(results)
    
    print("\nResults saved to prediction_results.json")
    print("Visualization saved to prediction_results.png")

def create_visualization(results):
    """Create a visualization of MTU predictions based on network conditions"""
    # Group by scenario
    scenarios = {}
    for result in results:
        scenario = result["scenario"]
        if scenario not in scenarios:
            scenarios[scenario] = []
        scenarios[scenario].append(result)
    
    # Create figure
    plt.figure(figsize=(12, 10))
    
    # Create subplots
    plt.subplot(2, 1, 1)
    
    # Plot RTT vs MTU
    for scenario, scenario_results in scenarios.items():
        rtts = [r["rtt_ms"] for r in scenario_results]
        mtus = [r["predicted_mtu"] for r in scenario_results]
        plt.scatter(rtts, mtus, label=scenario, s=100)
    
    plt.xlabel("RTT (ms)")
    plt.ylabel("Predicted MTU")
    plt.title("RTT vs Predicted MTU")
    plt.grid(True)
    plt.legend()
    
    # Plot Throughput vs MTU
    plt.subplot(2, 1, 2)
    
    for scenario, scenario_results in scenarios.items():
        throughputs = [r["throughput_mbps"] for r in scenario_results]
        mtus = [r["predicted_mtu"] for r in scenario_results]
        plt.scatter(throughputs, mtus, label=scenario, s=100)
    
    plt.xlabel("Throughput (Mbps)")
    plt.ylabel("Predicted MTU")
    plt.title("Throughput vs Predicted MTU")
    plt.grid(True)
    plt.legend()
    
    plt.tight_layout()
    plt.savefig(os.path.join(os.path.dirname(__file__), "prediction_results.png"))

if __name__ == "__main__":
    main()
