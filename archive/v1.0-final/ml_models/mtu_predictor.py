#!/usr/bin/env python3
# MTU Prediction Model using TensorFlow
# μDCN Phase 4: ML-based MTU Prediction

import os
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt

# Set random seed for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

# Configuration
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "mtu_model")
TFLITE_MODEL_PATH = os.path.join(MODEL_DIR, "mtu_model.tflite")

# Input features: [rtt_ms, packet_loss_rate, throughput_mbps]
# Output: Optimal MTU size (usually between 576 and 9000)

def generate_synthetic_data(samples=1000):
    """Generate synthetic data for training the MTU prediction model"""
    
    # Network conditions
    rtt_values = np.random.uniform(1, 300, samples)  # RTT in ms (1-300ms)
    loss_rates = np.random.uniform(0, 0.1, samples)  # Loss rates (0-10%)
    throughput_values = np.random.uniform(1, 1000, samples)  # Throughput in Mbps
    
    # Create input features
    X = np.column_stack((rtt_values, loss_rates, throughput_values))
    
    # Generate MTU sizes based on a rule-based approach for synthetic data
    # This is a simplified heuristic function:
    # - Low RTT, low loss, high throughput → Higher MTU
    # - High RTT, high loss, low throughput → Lower MTU
    Y = np.zeros(samples)
    
    for i in range(samples):
        rtt, loss, throughput = X[i]
        
        # Base MTU starts at 1500 (standard Ethernet)
        base_mtu = 1500
        
        # RTT factor: reduce MTU for high RTT
        rtt_factor = max(0.6, 1 - (rtt / 300) * 0.4)
        
        # Loss factor: significantly reduce MTU with increased loss
        loss_factor = max(0.5, 1 - loss * 5)
        
        # Throughput factor: increase MTU for high throughput
        throughput_factor = min(1.5, 0.8 + (throughput / 1000) * 0.7)
        
        # Calculate final MTU
        mtu = base_mtu * rtt_factor * loss_factor * throughput_factor
        
        # Discretize MTU to common values
        if mtu < 800:
            mtu = 576  # Minimum safe MTU
        elif mtu < 1300:
            mtu = 1280  # IPv6 minimum
        elif mtu < 1450:
            mtu = 1400
        elif mtu < 1550:
            mtu = 1500  # Standard Ethernet
        elif mtu < 4000:
            mtu = 3000  # Jumbo frames
        else:
            mtu = 9000  # Maximum jumbo frames
        
        Y[i] = mtu
    
    return X, Y

def build_model():
    """Build and compile the MTU prediction model"""
    model = keras.Sequential([
        layers.Input(shape=(3,)),  # 3 input features
        layers.Dense(64, activation='relu'),
        layers.Dense(32, activation='relu'),
        layers.Dense(16, activation='relu'),
        layers.Dense(1)  # Output layer (MTU size)
    ])
    
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='mse',  # Mean squared error for regression
        metrics=['mae']  # Mean absolute error
    )
    
    return model

def visualize_predictions(model, X_test, y_test):
    """Visualize model predictions vs actual values"""
    # Make predictions
    y_pred = model.predict(X_test).flatten()
    
    # Plot predictions vs actual values
    plt.figure(figsize=(12, 6))
    plt.scatter(y_test, y_pred, alpha=0.5)
    plt.plot([min(y_test), max(y_test)], [min(y_test), max(y_test)], 'r--')
    plt.xlabel('Actual MTU')
    plt.ylabel('Predicted MTU')
    plt.title('MTU Prediction: Actual vs Predicted')
    plt.savefig(os.path.join(MODEL_DIR, 'mtu_prediction_results.png'))
    plt.close()

def train_model():
    """Train and save the MTU prediction model"""
    # Generate synthetic data
    X, y = generate_synthetic_data(10000)
    
    # Split into training and test sets (80/20)
    split_idx = int(0.8 * len(X))
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    
    # Build and train model
    model = build_model()
    
    # Train the model
    history = model.fit(
        X_train, y_train,
        epochs=50,
        batch_size=32,
        validation_split=0.2,
        verbose=1
    )
    
    # Evaluate model
    test_loss, test_mae = model.evaluate(X_test, y_test)
    print(f"Test MAE: {test_mae:.2f} bytes")
    
    # Visualize results
    visualize_predictions(model, X_test, y_test)
    
    # Plot training history
    plt.figure(figsize=(12, 6))
    plt.plot(history.history['loss'], label='Training Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.title('Training and Validation Loss')
    plt.legend()
    plt.savefig(os.path.join(MODEL_DIR, 'training_history.png'))
    plt.close()
    
    # Save model in h5 format
    model.save(MODEL_PATH)
    print(f"Saved model to {MODEL_PATH}")
    
    # Convert to TFLite
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    tflite_model = converter.convert()
    
    # Save TFLite model
    with open(TFLITE_MODEL_PATH, 'wb') as f:
        f.write(tflite_model)
    
    print(f"Saved TFLite model to {TFLITE_MODEL_PATH}")
    
    return model

def load_tflite_model():
    """Load TFLite model for inference"""
    interpreter = tf.lite.Interpreter(model_path=TFLITE_MODEL_PATH)
    interpreter.allocate_tensors()
    return interpreter

def predict_mtu(interpreter, rtt_ms, packet_loss_rate, throughput_mbps):
    """Predict MTU using the TFLite model"""
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    
    # Prepare input data
    input_data = np.array([[rtt_ms, packet_loss_rate, throughput_mbps]], dtype=np.float32)
    
    # Set input tensor
    interpreter.set_tensor(input_details[0]['index'], input_data)
    
    # Run inference
    interpreter.invoke()
    
    # Get output tensor
    output_data = interpreter.get_tensor(output_details[0]['index'])
    
    # Get predicted MTU
    predicted_mtu = int(round(output_data[0][0]))
    
    # Discretize to common MTU values
    if predicted_mtu < 800:
        predicted_mtu = 576
    elif predicted_mtu < 1300:
        predicted_mtu = 1280
    elif predicted_mtu < 1450:
        predicted_mtu = 1400
    elif predicted_mtu < 1550:
        predicted_mtu = 1500
    elif predicted_mtu < 4000:
        predicted_mtu = 3000
    else:
        predicted_mtu = 9000
    
    return predicted_mtu

if __name__ == "__main__":
    # Check if model exists, if not train it
    if not os.path.exists(TFLITE_MODEL_PATH):
        print("Training new MTU prediction model...")
        model = train_model()
    else:
        print(f"Found existing model at {TFLITE_MODEL_PATH}")
    
    # Test model with some sample data
    interpreter = load_tflite_model()
    
    # Test cases
    test_cases = [
        # RTT (ms), Loss Rate, Throughput (Mbps)
        (10, 0.001, 500),    # Low RTT, low loss, high throughput
        (150, 0.05, 50),     # Medium RTT, medium loss, medium throughput
        (250, 0.08, 10)      # High RTT, high loss, low throughput
    ]
    
    print("\nMTU Predictions:")
    print("-" * 60)
    print("| RTT (ms) | Loss Rate | Throughput (Mbps) | Predicted MTU |")
    print("-" * 60)
    
    for rtt, loss, throughput in test_cases:
        mtu = predict_mtu(interpreter, rtt, loss, throughput)
        print(f"| {rtt:8.1f} | {loss:9.3f} | {throughput:16.1f} | {mtu:13d} |")
    
    print("-" * 60)
