#!/usr/bin/env python3
# MTU Predictor Wrapper for μDCN
# This wrapper integrates the TFLite model with the Python control plane

import os
import time
import json
import numpy as np
import tensorflow as tf
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'mtu_predictor.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('mtu_predictor')

class MTUPredictor:
    """Wrapper for the TensorFlow Lite MTU prediction model"""
    
    def __init__(self, model_path=None):
        """Initialize the MTU predictor with a TFLite model"""
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), 'mtu_model.tflite')
        
        self.model_path = model_path
        self.interpreter = None
        self.prediction_log = []
        self.override_value = None
        
        self._load_model()
    
    def _load_model(self):
        """Load the TensorFlow Lite model"""
        try:
            if not os.path.exists(self.model_path):
                logger.error(f"Model file not found: {self.model_path}")
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            logger.info(f"Loading TFLite model from {self.model_path}")
            self.interpreter = tf.lite.Interpreter(model_path=self.model_path)
            self.interpreter.allocate_tensors()
            logger.info("TFLite model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load TFLite model: {e}")
            raise
    
    def predict(self, rtt_ms, packet_loss_rate, throughput_mbps, log_prediction=True):
        """
        Predict the optimal MTU size based on network statistics
        
        Args:
            rtt_ms (float): Round-trip time in milliseconds
            packet_loss_rate (float): Packet loss rate (0.0 to 1.0)
            throughput_mbps (float): Throughput in Mbps
            log_prediction (bool): Whether to log the prediction
            
        Returns:
            int: Predicted optimal MTU size
        """
        # Check if override is set
        if self.override_value is not None:
            if log_prediction:
                self._log_prediction(
                    rtt_ms, packet_loss_rate, throughput_mbps,
                    self.override_value, is_override=True
                )
            return self.override_value
        
        # Ensure the interpreter is loaded
        if self.interpreter is None:
            self._load_model()
        
        # Get input and output tensors
        input_details = self.interpreter.get_input_details()
        output_details = self.interpreter.get_output_details()
        
        # Prepare input data
        input_data = np.array([[rtt_ms, packet_loss_rate, throughput_mbps]], dtype=np.float32)
        
        # Set input tensor
        self.interpreter.set_tensor(input_details[0]['index'], input_data)
        
        # Run inference
        start_time = time.time()
        self.interpreter.invoke()
        inference_time = time.time() - start_time
        
        # Get output tensor
        output_data = self.interpreter.get_tensor(output_details[0]['index'])
        
        # Get predicted MTU
        raw_prediction = float(output_data[0][0])
        
        # Discretize to common MTU values
        if raw_prediction < 800:
            predicted_mtu = 576  # Minimum safe MTU
        elif raw_prediction < 1300:
            predicted_mtu = 1280  # IPv6 minimum
        elif raw_prediction < 1450:
            predicted_mtu = 1400
        elif raw_prediction < 1550:
            predicted_mtu = 1500  # Standard Ethernet
        elif raw_prediction < 4000:
            predicted_mtu = 3000  # Jumbo frames
        else:
            predicted_mtu = 9000  # Maximum jumbo frames
        
        if log_prediction:
            self._log_prediction(
                rtt_ms, packet_loss_rate, throughput_mbps,
                predicted_mtu, raw_prediction, inference_time
            )
        
        return predicted_mtu
    
    def _log_prediction(self, rtt_ms, packet_loss_rate, throughput_mbps, 
                       mtu, raw_prediction=None, inference_time=None, is_override=False):
        """Log a prediction to the prediction history"""
        prediction_record = {
            'timestamp': time.time(),
            'inputs': {
                'rtt_ms': rtt_ms,
                'packet_loss_rate': packet_loss_rate,
                'throughput_mbps': throughput_mbps
            },
            'output': {
                'predicted_mtu': mtu
            },
            'is_override': is_override
        }
        
        if raw_prediction is not None:
            prediction_record['output']['raw_prediction'] = raw_prediction
        
        if inference_time is not None:
            prediction_record['inference_time_ms'] = inference_time * 1000
        
        self.prediction_log.append(prediction_record)
        
        # Keep log size manageable
        if len(self.prediction_log) > 1000:
            self.prediction_log = self.prediction_log[-1000:]
        
        # Log to log file
        if is_override:
            logger.info(
                f"MTU Override: {mtu} (rtt={rtt_ms}ms, loss={packet_loss_rate:.4f}, "
                f"throughput={throughput_mbps}Mbps)"
            )
        else:
            logger.info(
                f"MTU Prediction: {mtu} (rtt={rtt_ms}ms, loss={packet_loss_rate:.4f}, "
                f"throughput={throughput_mbps}Mbps, raw={raw_prediction:.2f}, "
                f"inference_time={inference_time*1000:.2f}ms)"
            )
    
    def set_override(self, mtu_value):
        """
        Override the model prediction with a fixed MTU value
        
        Args:
            mtu_value (int): MTU value to use, or None to disable override
        """
        if mtu_value is not None and (mtu_value < 576 or mtu_value > 9000):
            logger.warning(f"MTU override value {mtu_value} is outside valid range (576-9000)")
        
        self.override_value = mtu_value
        logger.info(f"MTU prediction override {'set to ' + str(mtu_value) if mtu_value else 'disabled'}")
    
    def get_prediction_history(self, limit=None):
        """
        Get prediction history
        
        Args:
            limit (int): Maximum number of records to return, or None for all
            
        Returns:
            list: List of prediction records
        """
        if limit is None or limit >= len(self.prediction_log):
            return self.prediction_log
        else:
            return self.prediction_log[-limit:]
    
    def export_prediction_log(self, output_file=None):
        """
        Export prediction log to a JSON file
        
        Args:
            output_file (str): Output file path, or None to use default
            
        Returns:
            str: Path to the exported file
        """
        if output_file is None:
            output_file = os.path.join(os.path.dirname(__file__), 'prediction_log.json')
        
        with open(output_file, 'w') as f:
            json.dump(self.prediction_log, f, indent=2)
        
        logger.info(f"Exported prediction log to {output_file}")
        return output_file

# Simple test function
if __name__ == "__main__":
    predictor = MTUPredictor()
    
    # Test with various network conditions
    test_conditions = [
        # RTT (ms), Loss Rate, Throughput (Mbps)
        (10, 0.001, 500),    # Low RTT, low loss, high throughput
        (150, 0.05, 50),     # Medium RTT, medium loss, medium throughput
        (250, 0.08, 10)      # High RTT, high loss, low throughput
    ]
    
    print("\nMTU Predictions:")
    print("-" * 65)
    print("| RTT (ms) | Loss Rate | Throughput (Mbps) | Predicted MTU | Note |")
    print("-" * 65)
    
    for rtt, loss, throughput in test_conditions:
        mtu = predictor.predict(rtt, loss, throughput)
        if rtt < 50 and loss < 0.01 and throughput > 100:
            note = "Fast network"
        elif rtt > 200 or loss > 0.05:
            note = "Poor network"
        else:
            note = "Average network"
        print(f"| {rtt:8.1f} | {loss:9.4f} | {throughput:16.1f} | {mtu:13d} | {note:4s} |")
    
    # Test override
    print("\nTesting override:")
    predictor.set_override(1400)
    mtu = predictor.predict(10, 0.001, 500)
    print(f"Override active - MTU set to {mtu}")
    
    # Disable override
    predictor.set_override(None)
    mtu = predictor.predict(10, 0.001, 500)
    print(f"Override disabled - Predicted MTU: {mtu}")
    
    # Export log
    predictor.export_prediction_log()
    print("\nPrediction log exported to prediction_log.json")
