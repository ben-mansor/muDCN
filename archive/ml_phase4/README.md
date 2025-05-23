# μDCN Machine Learning MTU Prediction - Phase 4 Archive

This archive contains the stable version (v0.4) of the ML-based MTU prediction components developed during Phase 4 of the μDCN project.

## Contents

### ML Models Directory
- `mtu_predictor.py` - Core ML model implementation with TensorFlow Lite
- `mtu_predictor_wrapper.py` - Wrapper class for integrating the model with the control plane
- `train_and_test_model.py` - Script for training and testing the model with synthetic data

### Python Client Directory
- `ml_integration.py` - Integration layer between Python control plane and ML predictor
- `mtu_test_script.py` - Test script for the MTU prediction system

## Synthetic Dataset

The synthetic dataset generated for training the model is created dynamically by the `train_and_test_model.py` script. This approach was chosen to ensure reproducible training results and to allow for adaptability to different network conditions.

## Testing

The test scripts and logs provide verification that the ML-based MTU prediction system works as expected across a variety of network conditions, including:
- Fast wired networks
- Average home WiFi
- Mobile LTE connections
- Poor connections with high latency and packet loss

## Version Information

This code has been tagged as v0.4 stable in the repository. No modifications should be made to the ML prediction module, model, or gRPC API without explicit approval.

## Date

Archive created: May 16, 2025
