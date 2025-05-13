#!/usr/bin/env python3
"""
μDCN Controller

This module provides the main controller for the μDCN architecture.
It coordinates the ML-based MTU prediction, monitoring, and communication
with the Rust transport layer via gRPC.
"""

import logging
import time
import json
from typing import Dict, List, Any, Optional, Tuple
import threading
from pathlib import Path
import yaml

from .ml_engine import MtuPredictor
from .monitoring import NetworkMonitor
from .transport_client import TransportClient, TransportClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class UdcnController:
    """
    Main controller for the μDCN architecture.
    
    The controller coordinates the ML-based MTU prediction, monitoring,
    and communication with the transport layer.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the controller with the given configuration.
        
        Args:
            config_path: Path to the configuration file. If None, use default config.
        """
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.ml_engine = MtuPredictor(self.config.get('ml_engine', {}))
        self.monitor = NetworkMonitor(self.config.get('monitoring', {}))
        
        # Extract transport client configuration
        transport_config = self.config.get('transport', {})
        self.transport_client = TransportClient(
            host=transport_config.get('host', 'localhost'),
            port=transport_config.get('port', 9091),
            timeout=transport_config.get('timeout', 10),
            max_retries=transport_config.get('max_retries', 3),
            retry_delay=transport_config.get('retry_delay', 1.0)
        )
        
        # Control variables
        self.running = False
        self.control_thread = None
        self.prediction_interval = self.config.get('prediction_interval', 60)  # seconds
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the configuration file. If None, use default config.
            
        Returns:
            Dictionary containing the configuration.
        """
        default_config = {
            'prediction_interval': 60,
            'ml_engine': {
                'model_path': str(Path(__file__).parent / 'models' / 'mtu_model.tflite'),
                'feature_scaling': 'standard',
                'confidence_threshold': 0.8
            },
            'monitoring': {
                'metrics_interval': 5,
                'interface': '',  # Auto-detect
                'prometheus_port': 8000
            },
            'transport': {
                'host': 'localhost',
                'port': 9091,
                'timeout': 10,
                'max_retries': 3,
                'retry_delay': 1.0
            }
        }
        
        if config_path is None:
            return default_config
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Merge with default config to ensure all required fields exist
            merged_config = default_config.copy()
            for section, values in config.items():
                if section in merged_config and isinstance(merged_config[section], dict):
                    merged_config[section].update(values)
                else:
                    merged_config[section] = values
            
            return merged_config
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            logger.info("Using default configuration")
            return default_config
    
    def start(self) -> None:
        """Start the controller."""
        if self.running:
            logger.warning("Controller is already running")
            return
        
        logger.info("Starting μDCN Controller")
        
        # Start the network monitor
        self.monitor.start()
        
        # Start the transport layer (if it's not already running)
        try:
            success, error, state = self.transport_client.control_transport("start")
            if not success:
                logger.warning(f"Failed to start transport layer: {error}")
        except TransportClientError as e:
            logger.error(f"Failed to connect to transport layer: {e}")
        
        # Start the control loop in a separate thread
        self.running = True
        self.control_thread = threading.Thread(target=self._control_loop)
        self.control_thread.daemon = True
        self.control_thread.start()
        
        logger.info("μDCN Controller started")
    
    def stop(self) -> None:
        """Stop the controller."""
        if not self.running:
            logger.warning("Controller is not running")
            return
        
        logger.info("Stopping μDCN Controller")
        
        # Stop the control loop
        self.running = False
        if self.control_thread:
            self.control_thread.join(timeout=5.0)
        
        # Stop the network monitor
        self.monitor.stop()
        
        # Close the transport client connection
        self.transport_client.close()
        
        logger.info("μDCN Controller stopped")
    
    def _control_loop(self) -> None:
        """Main control loop for ML-based MTU prediction and adaptation."""
        while self.running:
            try:
                # Get network metrics from the monitor
                network_metrics = self.monitor.get_metrics()
                
                # Get transport metrics from the transport layer
                try:
                    transport_metrics = self.transport_client.get_metrics()
                except TransportClientError as e:
                    logger.error(f"Failed to get transport metrics: {e}")
                    transport_metrics = {}
                
                # Combine metrics for prediction
                combined_metrics = {**network_metrics, **transport_metrics}
                
                # Make MTU prediction
                predicted_mtu, confidence = self.ml_engine.predict_mtu(combined_metrics)
                
                # Log the prediction
                logger.info(f"MTU prediction: {predicted_mtu} bytes (confidence: {confidence:.2f})")
                
                # Get current MTU from transport layer
                try:
                    transport_state = self.transport_client.get_transport_state()
                    current_mtu = int(transport_state.get('detailed_stats', {}).get('metric_mtu', 0))
                    
                    # Only update if prediction is different and confidence is high enough
                    if (predicted_mtu != current_mtu and 
                        confidence >= self.config['ml_engine']['confidence_threshold']):
                        logger.info(f"Updating MTU from {current_mtu} to {predicted_mtu}")
                        
                        # Update the MTU via gRPC
                        success, error, prev_mtu, new_mtu = self.transport_client.update_mtu(
                            mtu=predicted_mtu,
                            confidence=confidence
                        )
                        
                        if success:
                            logger.info(f"MTU updated successfully: {prev_mtu} -> {new_mtu}")
                        else:
                            logger.error(f"Failed to update MTU: {error}")
                    
                except TransportClientError as e:
                    logger.error(f"Failed to update MTU: {e}")
                
            except Exception as e:
                logger.exception(f"Error in control loop: {e}")
            
            # Sleep until next prediction
            time.sleep(self.prediction_interval)
    
    def register_prefix(self, prefix: str, is_producer: bool = True) -> Optional[int]:
        """
        Register a prefix with the transport layer.
        
        Args:
            prefix: NDN name prefix to register.
            is_producer: If True, register as a producer; otherwise as a forwarder.
            
        Returns:
            Registration ID if successful, None otherwise.
        """
        try:
            success, error, reg_id = self.transport_client.register_prefix(
                prefix=prefix,
                is_producer=is_producer
            )
            
            if success:
                logger.info(f"Registered prefix: {prefix} (ID: {reg_id})")
                return reg_id
            else:
                logger.error(f"Failed to register prefix: {error}")
                return None
                
        except TransportClientError as e:
            logger.error(f"Failed to register prefix: {e}")
            return None
    
    def unregister_prefix(self, registration_id: int) -> bool:
        """
        Unregister a previously registered prefix.
        
        Args:
            registration_id: The ID returned when the prefix was registered.
            
        Returns:
            True if successful, False otherwise.
        """
        try:
            success, error = self.transport_client.unregister_prefix(registration_id)
            
            if success:
                logger.info(f"Unregistered prefix ID: {registration_id}")
                return True
            else:
                logger.error(f"Failed to unregister prefix: {error}")
                return False
                
        except TransportClientError as e:
            logger.error(f"Failed to unregister prefix: {e}")
            return False
    
    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """
        Get information about network interfaces.
        
        Returns:
            List of dictionaries with interface information.
        """
        try:
            return self.transport_client.get_network_interfaces()
        except TransportClientError as e:
            logger.error(f"Failed to get network interfaces: {e}")
            return []
    
    def get_transport_metrics(self) -> Dict[str, Any]:
        """
        Get metrics from the transport layer.
        
        Returns:
            Dictionary of metric names to values.
        """
        try:
            return self.transport_client.get_metrics()
        except TransportClientError as e:
            logger.error(f"Failed to get transport metrics: {e}")
            return {}
    
    def get_transport_state(self) -> Dict[str, Any]:
        """
        Get the current state of the transport layer.
        
        Returns:
            Dictionary with state and statistics.
        """
        try:
            return self.transport_client.get_transport_state(include_detailed_stats=True)
        except TransportClientError as e:
            logger.error(f"Failed to get transport state: {e}")
            return {"state": "unknown", "error": str(e)}
    
    def update_mtu(self, mtu: int, confidence: float = 1.0) -> Tuple[bool, str, int, int]:
        """
        Update the MTU of the transport layer.
        
        Args:
            mtu: The new MTU value.
            confidence: Confidence level of the prediction (0.0-1.0).
            
        Returns:
            Tuple of (success, error_message, previous_mtu, current_mtu)
        """
        try:
            return self.transport_client.update_mtu(mtu=mtu, confidence=confidence)
        except TransportClientError as e:
            logger.error(f"Failed to update MTU: {e}")
            return (False, str(e), 0, 0)
    
    def configure_transport(self, **kwargs) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Configure the transport layer parameters.
        
        Args:
            **kwargs: Configuration parameters to update.
            
        Returns:
            Tuple of (success, error_message, current_config)
        """
        try:
            return self.transport_client.configure_transport(**kwargs)
        except TransportClientError as e:
            logger.error(f"Failed to configure transport: {e}")
            return (False, str(e), {})
