#!/usr/bin/env python3
"""
μDCN ML-based MTU Prediction Model

This module implements a simple machine learning model for predicting
optimal MTU sizes based on network conditions. It interfaces with the
Rust-based transport layer through PyO3 bindings.
"""

import os
import sys
import time
import logging
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("udcn-ml-mtu")

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

@dataclass
class NetworkFeatures:
    """Network features used for MTU prediction"""
    avg_rtt_ms: float
    avg_throughput_bps: float
    packet_loss_rate: float
    congestion_window: int
    avg_packet_size: int
    packet_size_stddev: float
    network_type: int
    time_of_day: float


class BaseMLModel:
    """Base class for ML models used in μDCN"""
    
    def __init__(self, name: str):
        self.name = name
        self.training_data: List[Tuple[Dict[str, float], int]] = []
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
        
    def _normalize_features(self, features: Dict[str, Any]) -> np.ndarray:
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
                
        return np.array(feature_vector)


class LinearRegressionModel(BaseMLModel):
    """Simple linear regression model for MTU prediction"""
    
    def __init__(self, name: str):
        super().__init__(name)
        # Initialize weights for [bias, rtt, throughput, loss, cwnd, avg_size, stddev, net_type, time]
        self.weights = np.array([1200.0, -100.0, 50.0, -200.0, 30.0, 0.8, -20.0, 0.0, 0.0])
        self.learning_rate = 0.01
        
    def predict(self, features: Dict[str, Any]) -> int:
        """Predict optimal MTU based on features using linear regression"""
        normalized_features = self._normalize_features(features)
        # Add bias term
        x = np.concatenate(([1.0], normalized_features))
        
        # Apply prediction weights
        predicted_mtu = np.dot(x, self.weights)
        
        # Bound the prediction between reasonable values
        bounded_mtu = max(576, min(9000, predicted_mtu))
        
        # Round to nearest 100 for clean values
        rounded_mtu = int(round(bounded_mtu / 100.0) * 100)
        
        return rounded_mtu
    
    def update(self, features: Dict[str, Any], actual_optimal_mtu: int) -> None:
        """Update model weights using simple gradient descent"""
        super().update(features, actual_optimal_mtu)
        
        # Skip training if we don't have enough data yet
        if len(self.training_data) < 10:
            return
            
        # Use the last 50 samples for training
        training_subset = self.training_data[-50:]
        
        # Simple gradient descent iteration
        for features, target_mtu in training_subset:
            normalized_features = self._normalize_features(features)
            x = np.concatenate(([1.0], normalized_features))
            
            # Current prediction
            prediction = np.dot(x, self.weights)
            
            # Error
            error = target_mtu - prediction
            
            # Update weights
            gradient = x * error * self.learning_rate
            self.weights += gradient
            
        logger.debug(f"Updated model weights: {self.weights}")


class DecisionTreeModel(BaseMLModel):
    """Simple decision tree for MTU prediction"""
    
    def __init__(self, name: str):
        super().__init__(name)
        self.min_mtu = 576
        self.max_mtu = 9000
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
        mtu = int(round(mtu / 100.0) * 100)
        
        return max(self.min_mtu, min(self.max_mtu, mtu))


class EnsembleModel(BaseMLModel):
    """Ensemble of multiple models for better predictions"""
    
    def __init__(self, name: str):
        super().__init__(name)
        self.models = [
            LinearRegressionModel("linear"),
            DecisionTreeModel("decision_tree")
        ]
        
    def predict(self, features: Dict[str, Any]) -> int:
        """Predict using weighted ensemble of models"""
        predictions = [model.predict(features) for model in self.models]
        
        # For now, just take the average
        avg_prediction = sum(predictions) / len(predictions)
        
        # Round to nearest 100
        rounded_mtu = int(round(avg_prediction / 100.0) * 100)
        
        # Bound between min and max values
        bounded_mtu = max(576, min(9000, rounded_mtu))
        
        return bounded_mtu
    
    def update(self, features: Dict[str, Any], actual_optimal_mtu: int) -> None:
        """Update all models in the ensemble"""
        super().update(features, actual_optimal_mtu)
        
        # Update each individual model
        for model in self.models:
            model.update(features, actual_optimal_mtu)


def create_model(model_type: str) -> BaseMLModel:
    """Create a model of the specified type"""
    if model_type == "linear":
        return LinearRegressionModel("linear_regression")
    elif model_type == "decision_tree":
        return DecisionTreeModel("decision_tree")
    elif model_type == "ensemble":
        return EnsembleModel("ensemble")
    else:
        # Default to ensemble
        logger.warning(f"Unknown model type '{model_type}', using ensemble model")
        return EnsembleModel("ensemble")


if __name__ == "__main__":
    # Test the model
    model = create_model("ensemble")
    
    # Example network features
    test_features = {
        'avg_rtt_ms': 35.0,
        'avg_throughput_bps': 10_000_000.0,
        'packet_loss_rate': 0.001,
        'congestion_window': 15,
        'avg_packet_size': 1300,
        'packet_size_stddev': 150.0,
        'network_type': 1,  # Ethernet
        'time_of_day': 14.0,  # 2pm
    }
    
    # Get prediction
    mtu = model.predict(test_features)
    print(f"Predicted optimal MTU: {mtu}")
    
    # Update model with "actual" optimal value
    model.update(test_features, 1600)
    
    # Try different network conditions
    test_features['avg_rtt_ms'] = 150.0
    test_features['packet_loss_rate'] = 0.03
    test_features['network_type'] = 3  # Cellular
    
    # Get new prediction
    mtu = model.predict(test_features)
    print(f"Predicted optimal MTU for poor network: {mtu}")
