#!/usr/bin/env python3
# ML Integration for μDCN Python Control Plane
# Integrates the TFLite MTU prediction model with the gRPC client

import os
import sys
import time
import logging
import numpy as np
from pathlib import Path

# Add the ml_models directory to Python path
sys.path.append(str(Path(__file__).parent.parent / 'ml_models'))

# Import the MTU predictor
from mtu_predictor_wrapper import MTUPredictor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'ml_integration.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('ml_integration')

class MLIntegration:
    """ML integration for the μDCN Python control plane"""
    
    def __init__(self, grpc_client=None, model_path=None):
        """
        Initialize the ML integration
        
        Args:
            grpc_client: gRPC client for communication with the Rust transport layer
            model_path: Path to the TFLite model
        """
        self.grpc_client = grpc_client
        
        # Initialize MTU predictor
        try:
            model_dir = Path(__file__).parent.parent / 'ml_models'
            if model_path is None:
                model_path = model_dir / 'mtu_model.tflite'
            
            logger.info(f"Initializing MTU predictor with model at {model_path}")
            self.mtu_predictor = MTUPredictor(model_path)
            logger.info("MTU predictor initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize MTU predictor: {e}")
            raise
    
    def set_grpc_client(self, grpc_client):
        """Set the gRPC client for communication with the Rust transport layer"""
        self.grpc_client = grpc_client
    
    def predict_mtu(self, rtt_ms, packet_loss_rate, throughput_mbps, 
                   connection_id=None, interface_name=None, additional_metrics=None):
        """
        Predict the optimal MTU size based on network statistics
        
        Args:
            rtt_ms (float): Round-trip time in milliseconds
            packet_loss_rate (float): Packet loss rate (0.0 to 1.0)
            throughput_mbps (float): Throughput in Mbps
            connection_id (str): Optional QUIC connection ID
            interface_name (str): Optional network interface name
            additional_metrics (dict): Optional additional metrics for prediction
            
        Returns:
            dict: Prediction result with predicted MTU and metadata
        """
        logger.info(
            f"Predicting MTU for rtt={rtt_ms}ms, loss={packet_loss_rate:.4f}, "
            f"throughput={throughput_mbps}Mbps"
        )
        
        # Use the local model for prediction
        start_time = time.time()
        predicted_mtu = self.mtu_predictor.predict(rtt_ms, packet_loss_rate, throughput_mbps)
        inference_time = (time.time() - start_time) * 1000  # ms
        
        # If gRPC client is available, update the MTU on the transport layer
        if self.grpc_client is not None and interface_name is not None:
            try:
                from proto import udcn_pb2
                request = udcn_pb2.MtuRequest(
                    mtu=predicted_mtu,
                    interface_name=interface_name,
                    confidence=0.9,  # Placeholder
                    metadata={
                        "source": "ml_prediction",
                        "rtt_ms": str(rtt_ms),
                        "packet_loss_rate": str(packet_loss_rate),
                        "throughput_mbps": str(throughput_mbps)
                    }
                )
                response = self.grpc_client.UpdateMtu(request)
                if response.success:
                    logger.info(f"MTU updated successfully: {response.current_mtu}")
                else:
                    logger.error(f"Failed to update MTU: {response.error_message}")
            except Exception as e:
                logger.error(f"Error updating MTU via gRPC: {e}")
        
        # Prepare response
        result = {
            "predicted_mtu": predicted_mtu,
            "inference_time_ms": inference_time,
            "timestamp": time.time(),
            "inputs": {
                "rtt_ms": rtt_ms,
                "packet_loss_rate": packet_loss_rate,
                "throughput_mbps": throughput_mbps
            }
        }
        
        if connection_id:
            result["connection_id"] = connection_id
            
        if interface_name:
            result["interface_name"] = interface_name
        
        return result
    
    def set_mtu_override(self, enable_override, mtu_value=None):
        """
        Set or clear MTU prediction override
        
        Args:
            enable_override (bool): Whether to enable override
            mtu_value (int): MTU value to use for override, or None to disable
            
        Returns:
            bool: True if successful, False otherwise
        """
        if enable_override and mtu_value is None:
            logger.error("MTU value must be provided when enabling override")
            return False
        
        try:
            if enable_override:
                logger.info(f"Setting MTU override to {mtu_value}")
                self.mtu_predictor.set_override(mtu_value)
            else:
                logger.info("Disabling MTU override")
                self.mtu_predictor.set_override(None)
            return True
        except Exception as e:
            logger.error(f"Error setting MTU override: {e}")
            return False
    
    def get_prediction_history(self, max_entries=None):
        """
        Get the prediction history
        
        Args:
            max_entries (int): Maximum number of entries to return, or None for all
            
        Returns:
            list: List of prediction records
        """
        try:
            return self.mtu_predictor.get_prediction_history(max_entries)
        except Exception as e:
            logger.error(f"Error getting prediction history: {e}")
            return []
    
    def export_prediction_log(self, output_file=None):
        """
        Export prediction log to a JSON file
        
        Args:
            output_file (str): Output file path, or None to use default
            
        Returns:
            str: Path to the exported file, or None if export failed
        """
        try:
            return self.mtu_predictor.export_prediction_log(output_file)
        except Exception as e:
            logger.error(f"Error exporting prediction log: {e}")
            return None

# Simple test function
if __name__ == "__main__":
    ml_integration = MLIntegration()
    
    # Test with various network conditions
    test_conditions = [
        # RTT (ms), Loss Rate, Throughput (Mbps), Connection ID, Interface
        (10, 0.001, 500, "conn-1", "eth0"),
        (150, 0.05, 50, "conn-2", "eth0"),
        (250, 0.08, 10, "conn-3", "eth0")
    ]
    
    print("\nMTU Predictions:")
    print("-" * 80)
    print("| RTT (ms) | Loss Rate | Throughput (Mbps) | Connection ID | Interface | Predicted MTU |")
    print("-" * 80)
    
    for rtt, loss, throughput, conn_id, iface in test_conditions:
        result = ml_integration.predict_mtu(rtt, loss, throughput, conn_id, iface)
        print(f"| {rtt:8.1f} | {loss:9.4f} | {throughput:16.1f} | {conn_id:12s} | {iface:9s} | {result['predicted_mtu']:13d} |")
    
    print("-" * 80)
    
    # Test override
    print("\nTesting override:")
    ml_integration.set_mtu_override(True, 1400)
    result = ml_integration.predict_mtu(10, 0.001, 500, "conn-1", "eth0")
    print(f"Override active - MTU set to {result['predicted_mtu']}")
    
    # Disable override
    ml_integration.set_mtu_override(False)
    result = ml_integration.predict_mtu(10, 0.001, 500, "conn-1", "eth0")
    print(f"Override disabled - Predicted MTU: {result['predicted_mtu']}")
    
    # Export prediction log
    log_file = ml_integration.export_prediction_log()
    print(f"\nPrediction log exported to {log_file}")
