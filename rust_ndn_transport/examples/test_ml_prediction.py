#!/usr/bin/env python3
"""
Test Script for μDCN ML-based MTU Prediction

This standalone script simulates the behavior of the ML-based MTU prediction
without requiring the compiled Rust library.
"""

import os
import sys
import time
import logging
import json
from typing import Dict, Any
import random
import matplotlib.pyplot as plt
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("udcn-ml-test")

# Feature normalization parameters
FEATURE_MEANS = {
    'avg_rtt_ms': 50.0,
    'avg_throughput_bps': 5_000_000.0,
    'packet_loss_rate': 0.01,
    'congestion_window': 10.0,
    'avg_packet_size': 1200.0,
    'packet_size_stddev': 200.0,
    'network_type': 1.5,
    'time_of_day': 12.0,
}

FEATURE_STDS = {
    'avg_rtt_ms': 30.0,
    'avg_throughput_bps': 3_000_000.0,
    'packet_loss_rate': 0.02,
    'congestion_window': 5.0,
    'avg_packet_size': 500.0,
    'packet_size_stddev': 100.0,
    'network_type': 1.0,
    'time_of_day': 7.0,
}

class MtuFeatures:
    """Network features used for MTU prediction"""
    def __init__(self):
        self.avg_rtt_ms = 50.0
        self.avg_throughput_bps = 1_000_000.0
        self.packet_loss_rate = 0.0
        self.congestion_window = 10
        self.avg_packet_size = 1200
        self.packet_size_stddev = 200.0
        self.network_type = 0  # Unknown
        self.time_of_day = 12.0  # Noon
        
    def to_dict(self):
        return {
            'avg_rtt_ms': self.avg_rtt_ms,
            'avg_throughput_bps': self.avg_throughput_bps,
            'packet_loss_rate': self.packet_loss_rate,
            'congestion_window': self.congestion_window,
            'avg_packet_size': self.avg_packet_size,
            'packet_size_stddev': self.packet_size_stddev,
            'network_type': self.network_type,
            'time_of_day': self.time_of_day,
        }

class BaseMLModel:
    """Base class for ML models used in μDCN"""
    
    def __init__(self, name: str):
        self.name = name
        self.training_data = []
        self.max_training_samples = 1000
        
    def predict(self, features: Dict[str, Any]) -> int:
        """Predict optimal MTU based on features"""
        raise NotImplementedError("Subclasses must implement predict()")
    
    def update(self, features: Dict[str, Any], actual_optimal_mtu: int) -> None:
        """Update model with new data"""
        # Store training data (with a maximum limit)
        if len(self.training_data) >= self.max_training_samples:
            self.training_data.pop(0)  # Remove oldest sample
        
        self.training_data.append((features, actual_optimal_mtu))
        
    def _normalize_features(self, features: Dict[str, Any]) -> list:
        """Normalize features for ML model input"""
        feature_vector = []
        
        for feature_name in [
            'avg_rtt_ms', 'avg_throughput_bps', 'packet_loss_rate',
            'congestion_window', 'avg_packet_size', 'packet_size_stddev',
            'network_type', 'time_of_day'
        ]:
            if feature_name in features:
                # Normalize to zero mean and unit variance
                normalized_value = (float(features[feature_name]) - FEATURE_MEANS[feature_name]) / FEATURE_STDS[feature_name]
                feature_vector.append(normalized_value)
            else:
                # Use default zero if feature is missing
                feature_vector.append(0.0)
                
        return feature_vector

class SimpleRuleBasedModel(BaseMLModel):
    """Simple rule-based MTU prediction model"""
    
    def __init__(self, name: str, base_mtu: int = 1400, min_mtu: int = 576, max_mtu: int = 9000):
        super().__init__(name)
        self.base_mtu = base_mtu
        self.min_mtu = min_mtu
        self.max_mtu = max_mtu
        self.prediction_history = []
        
    def predict(self, features: Dict[str, Any]) -> int:
        """Predict optimal MTU using a rule-based approach"""
        
        # Base MTU adjusted by network conditions
        predicted_mtu = self.base_mtu
        
        # Decrease MTU when RTT is high or packet loss exists
        if features['avg_rtt_ms'] > 100.0 or features['packet_loss_rate'] > 0.01:
            predicted_mtu = int(predicted_mtu * 0.9)
        
        # Decrease further with very high RTT or high packet loss
        if features['avg_rtt_ms'] > 200.0 or features['packet_loss_rate'] > 0.05:
            predicted_mtu = int(predicted_mtu * 0.9)
        
        # Increase MTU when throughput is high and packet loss is low
        if features['avg_throughput_bps'] > 5_000_000.0 and features['packet_loss_rate'] < 0.005:
            predicted_mtu = int(predicted_mtu * 1.1)
        
        # Adjust based on average packet size
        if features['avg_packet_size'] > predicted_mtu:
            # If most packets are larger than current MTU, increase it
            predicted_mtu = min(
                int(predicted_mtu * 1.05),
                features['avg_packet_size'] + 100
            )
        elif features['avg_packet_size'] < predicted_mtu / 2:
            # If most packets are much smaller than MTU, decrease it
            predicted_mtu = int(predicted_mtu * 0.95)
        
        # Adjust for network type
        network_type = features['network_type']
        if network_type == 1:  # Ethernet - no adjustment
            pass
        elif network_type == 2:  # WiFi - slight decrease
            predicted_mtu = int(predicted_mtu * 0.95)
        elif network_type == 3:  # Cellular - larger decrease
            predicted_mtu = int(predicted_mtu * 0.85)
        
        # Bound the MTU within min and max
        predicted_mtu = max(self.min_mtu, min(predicted_mtu, self.max_mtu))
        
        # Round to nearest 100 for clean values
        predicted_mtu = ((predicted_mtu + 50) // 100) * 100
        
        return predicted_mtu

class DecisionTreeModel(BaseMLModel):
    """Simple decision tree for MTU prediction"""
    
    def __init__(self, name: str, min_mtu: int = 576, max_mtu: int = 9000):
        super().__init__(name)
        self.min_mtu = min_mtu
        self.max_mtu = max_mtu
        self.default_mtu = 1400
        
    def predict(self, features: Dict[str, Any]) -> int:
        """Predict optimal MTU using a simple decision tree approach"""
        rtt = features.get('avg_rtt_ms', 50.0)
        loss = features.get('packet_loss_rate', 0.01)
        throughput = features.get('avg_throughput_bps', 1_000_000.0)
        avg_size = features.get('avg_packet_size', 1200)
        network_type = features.get('network_type', 0)
        
        # Base MTU selection
        if network_type == 1:  # Ethernet
            mtu = 1500
        elif network_type == 2:  # WiFi
            mtu = 1400
        elif network_type == 3:  # Cellular
            mtu = 1200
        else:
            mtu = self.default_mtu
            
        # Adjust based on network conditions
        if rtt > 200 or loss > 0.05:
            # Bad network conditions: reduce MTU
            mtu = int(mtu * 0.8)
        elif rtt < 20 and loss < 0.001 and throughput > 50_000_000:
            # Excellent network: increase MTU
            mtu = min(int(mtu * 1.3), self.max_mtu)
            
        # Adjust based on packet size
        if avg_size > mtu:
            # If packets are consistently larger than MTU, increase it
            mtu = min(avg_size + 100, self.max_mtu)
        elif avg_size < mtu / 2:
            # If packets are much smaller than MTU, decrease it
            mtu = max(int(mtu * 0.9), self.min_mtu)
            
        # Round to nearest 100 for clean values
        mtu = ((mtu + 50) // 100) * 100
        
        return max(self.min_mtu, min(self.max_mtu, mtu))

class EnsembleModel(BaseMLModel):
    """Ensemble of multiple models for better predictions"""
    
    def __init__(self, name: str, base_mtu: int = 1400, min_mtu: int = 576, max_mtu: int = 9000):
        super().__init__(name)
        self.models = [
            SimpleRuleBasedModel("rule-based", base_mtu, min_mtu, max_mtu),
            DecisionTreeModel("decision-tree", min_mtu, max_mtu)
        ]
        
    def predict(self, features: Dict[str, Any]) -> int:
        """Predict using weighted ensemble of models"""
        predictions = [model.predict(features) for model in self.models]
        
        # For now, just take the average
        avg_prediction = sum(predictions) / len(predictions)
        
        # Round to nearest 100
        rounded_mtu = ((int(avg_prediction) + 50) // 100) * 100
        
        # Bound between min and max values
        bounded_mtu = max(576, min(9000, rounded_mtu))
        
        return bounded_mtu
    
    def update(self, features: Dict[str, Any], actual_optimal_mtu: int) -> None:
        """Update all models in the ensemble"""
        super().update(features, actual_optimal_mtu)
        
        # Update each individual model
        for model in self.models:
            model.update(features, actual_optimal_mtu)

# Network scenario definitions for testing
class NetworkScenario:
    """Definition of a network scenario for testing"""
    def __init__(self, name: str, desc: str, rtt: float, loss: float, throughput: float, net_type: int):
        self.name = name
        self.description = desc
        self.rtt_ms = rtt
        self.packet_loss = loss
        self.throughput_mbps = throughput
        self.network_type = net_type
        
    def to_features(self) -> Dict[str, Any]:
        """Convert scenario to feature dictionary"""
        features = MtuFeatures()
        features.avg_rtt_ms = self.rtt_ms
        features.packet_loss_rate = self.packet_loss
        features.avg_throughput_bps = self.throughput_mbps * 1_000_000.0  # Convert to bps
        features.network_type = self.network_type
        
        # Randomize packet size a bit to simulate real traffic
        features.avg_packet_size = random.randint(800, 1600)
        features.packet_size_stddev = random.uniform(100.0, 300.0)
        
        return features.to_dict()

# Create a set of diverse network scenarios for testing
def create_scenarios():
    return [
        NetworkScenario(
            "ethernet", 
            "High-performance LAN connection",
            10, 0.0001, 1000, 1 # Ethernet
        ),
        NetworkScenario(
            "wifi", 
            "Standard home WiFi connection",
            30, 0.01, 50, 2 # WiFi
        ),
        NetworkScenario(
            "4g", 
            "Mobile 4G connection with some packet loss",
            80, 0.03, 12, 3 # Cellular
        ),
        NetworkScenario(
            "congested", 
            "Congested network with high latency",
            200, 0.05, 10, 1 # Ethernet but congested
        ),
        NetworkScenario(
            "satellite", 
            "High-latency satellite connection",
            600, 0.02, 20, 4 # Satellite
        ),
    ]

def test_model(model, scenarios, iterations=50):
    """Test a model with various network scenarios"""
    results = []
    
    # For each scenario
    for scenario in scenarios:
        logger.info(f"Testing scenario: {scenario.name} - {scenario.description}")
        
        scenario_results = []
        
        # Run multiple iterations for this scenario
        for i in range(iterations):
            # Get features with slight randomization to simulate real traffic variations
            features = scenario.to_features()
            
            # Add some random variance to make it more realistic
            features['avg_rtt_ms'] *= random.uniform(0.9, 1.1) 
            features['packet_loss_rate'] *= random.uniform(0.8, 1.2)
            features['avg_throughput_bps'] *= random.uniform(0.9, 1.1)
            
            # Predict MTU
            predicted_mtu = model.predict(features)
            
            # Record result
            scenario_results.append({
                'iteration': i,
                'scenario': scenario.name,
                'features': features,
                'predicted_mtu': predicted_mtu
            })
            
            # Update the model (simulate feedback loop)
            # In real system, this would be based on actual performance
            optimal_mtu = calculate_simulated_optimal_mtu(features)
            model.update(features, optimal_mtu)
        
        results.extend(scenario_results)
        
    return results

def calculate_simulated_optimal_mtu(features):
    """Calculate simulated optimal MTU based on network features"""
    # This is a simplified simulation of what the optimal MTU would be
    # In a real system, this would be determined by actual performance metrics
    
    base = 1400
    
    # Better conditions: higher MTU
    if features['avg_rtt_ms'] < 30 and features['packet_loss_rate'] < 0.005:
        base = 1500
    
    # Even better conditions: jumbo frames
    if features['avg_rtt_ms'] < 10 and features['packet_loss_rate'] < 0.001 and features['avg_throughput_bps'] > 500_000_000:
        base = 9000
    
    # Poor conditions: lower MTU
    if features['avg_rtt_ms'] > 100 or features['packet_loss_rate'] > 0.02:
        base = 1200
    
    # Very poor conditions: much lower MTU
    if features['avg_rtt_ms'] > 300 or features['packet_loss_rate'] > 0.05:
        base = 900
    
    # Apply some random variance
    base = int(base * random.uniform(0.95, 1.05))
    
    # Round to nearest 100
    return ((base + 50) // 100) * 100

def visualize_results(results, output_dir='results'):
    """Visualize test results with charts"""
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Group results by scenario
    scenarios = {}
    for result in results:
        scenario_name = result['scenario']
        if scenario_name not in scenarios:
            scenarios[scenario_name] = []
        scenarios[scenario_name].append(result)
    
    # Plot MTU predictions for each scenario
    plt.figure(figsize=(12, 8))
    
    for scenario_name, scenario_results in scenarios.items():
        mtus = [r['predicted_mtu'] for r in scenario_results]
        iterations = [r['iteration'] for r in scenario_results]
        plt.plot(iterations, mtus, label=scenario_name, marker='o', linestyle='-', alpha=0.7)
    
    plt.title('MTU Predictions by Network Scenario')
    plt.xlabel('Iteration')
    plt.ylabel('Predicted MTU (bytes)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    
    # Save plot
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    plt.savefig(os.path.join(output_dir, f'mtu_predictions_{timestamp}.png'))
    plt.close()
    
    # Plot relationship between RTT and MTU
    plt.figure(figsize=(12, 8))
    
    rtts = [r['features']['avg_rtt_ms'] for r in results]
    mtus = [r['predicted_mtu'] for r in results]
    scenarios = [r['scenario'] for r in results]
    
    # Create color map for scenarios
    scenario_names = list(set(scenarios))
    colors = plt.cm.tab10(range(len(scenario_names)))
    color_map = {scenario: colors[i] for i, scenario in enumerate(scenario_names)}
    
    for scenario in scenario_names:
        indices = [i for i, s in enumerate(scenarios) if s == scenario]
        plt.scatter([rtts[i] for i in indices], [mtus[i] for i in indices], 
                  label=scenario, alpha=0.7, color=color_map[scenario])
    
    plt.title('RTT vs Predicted MTU')
    plt.xlabel('RTT (ms)')
    plt.ylabel('Predicted MTU (bytes)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    
    # Save plot
    plt.savefig(os.path.join(output_dir, f'rtt_vs_mtu_{timestamp}.png'))
    plt.close()
    
    # Plot relationship between packet loss and MTU
    plt.figure(figsize=(12, 8))
    
    loss_rates = [r['features']['packet_loss_rate'] * 100 for r in results]  # Convert to percentage
    mtus = [r['predicted_mtu'] for r in results]
    
    for scenario in scenario_names:
        indices = [i for i, s in enumerate(scenarios) if s == scenario]
        plt.scatter([loss_rates[i] for i in indices], [mtus[i] for i in indices], 
                  label=scenario, alpha=0.7, color=color_map[scenario])
    
    plt.title('Packet Loss vs Predicted MTU')
    plt.xlabel('Packet Loss (%)')
    plt.ylabel('Predicted MTU (bytes)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    
    # Save plot
    plt.savefig(os.path.join(output_dir, f'loss_vs_mtu_{timestamp}.png'))
    plt.close()
    
    # Save raw results as JSON
    with open(os.path.join(output_dir, f'results_{timestamp}.json'), 'w') as f:
        json.dump(results, f, indent=2)
    
    return os.path.join(output_dir, f'mtu_predictions_{timestamp}.png')

def main():
    # Create ML models
    rule_based_model = SimpleRuleBasedModel("rule-based")
    decision_tree_model = DecisionTreeModel("decision-tree")
    ensemble_model = EnsembleModel("ensemble")
    
    # Create network scenarios
    scenarios = create_scenarios()
    
    # Test models
    logger.info("Testing Rule-Based Model...")
    rule_based_results = test_model(rule_based_model, scenarios)
    
    logger.info("Testing Decision Tree Model...")
    decision_tree_results = test_model(decision_tree_model, scenarios)
    
    logger.info("Testing Ensemble Model...")
    ensemble_results = test_model(ensemble_model, scenarios)
    
    # Visualize results
    logger.info("Visualizing Rule-Based Model results...")
    rule_based_plot = visualize_results(rule_based_results, 'results/rule_based')
    
    logger.info("Visualizing Decision Tree Model results...")
    decision_tree_plot = visualize_results(decision_tree_results, 'results/decision_tree')
    
    logger.info("Visualizing Ensemble Model results...")
    ensemble_plot = visualize_results(ensemble_results, 'results/ensemble')
    
    logger.info(f"Visualization complete. Results saved in the 'results' directory.")
    logger.info(f"Rule-based model plot: {rule_based_plot}")
    logger.info(f"Decision tree model plot: {decision_tree_plot}")
    logger.info(f"Ensemble model plot: {ensemble_plot}")
    
    # Print summary statistics
    for model_name, results in [
        ("Rule-Based", rule_based_results),
        ("Decision Tree", decision_tree_results),
        ("Ensemble", ensemble_results)
    ]:
        print(f"\n=== {model_name} Model Summary ===")
        
        # Calculate statistics by scenario
        for scenario in scenarios:
            scenario_results = [r for r in results if r['scenario'] == scenario.name]
            if scenario_results:
                mtus = [r['predicted_mtu'] for r in scenario_results]
                avg_mtu = sum(mtus) / len(mtus)
                min_mtu = min(mtus)
                max_mtu = max(mtus)
                
                print(f"Scenario: {scenario.name} ({scenario.description})")
                print(f"  Network: RTT={scenario.rtt_ms}ms, Loss={scenario.packet_loss*100:.2f}%, Throughput={scenario.throughput_mbps}Mbps")
                print(f"  Average MTU: {avg_mtu:.0f} bytes")
                print(f"  Min MTU: {min_mtu} bytes")
                print(f"  Max MTU: {max_mtu} bytes")
                print()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Error in test script: {e}", exc_info=True)
