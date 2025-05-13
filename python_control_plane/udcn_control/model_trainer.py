#!/usr/bin/env python3
"""
μDCN ML Model Trainer

This script trains and exports a TensorFlow Lite model for predicting
optimal MTU sizes based on network conditions.
"""

import argparse
import os
import logging
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def generate_synthetic_data(
    num_samples: int = 10000,
    noise_level: float = 0.1
) -> pd.DataFrame:
    """
    Generate synthetic data for training the MTU prediction model.
    
    Args:
        num_samples: Number of samples to generate
        noise_level: Level of noise to add to the data
        
    Returns:
        DataFrame containing the synthetic data
    """
    logger.info(f"Generating {num_samples} synthetic data samples")
    
    # Generate network metrics
    packet_loss = np.random.exponential(scale=2.0, size=num_samples) 
    packet_loss = np.minimum(packet_loss, 100.0)  # Cap at 100%
    
    latency = np.random.lognormal(mean=2.0, sigma=1.0, size=num_samples)  # in ms
    latency = np.minimum(latency, 1000.0)  # Cap at 1 second
    
    throughput = np.random.lognormal(mean=3.0, sigma=1.0, size=num_samples)  # in Mbps
    throughput = np.minimum(throughput, 10000.0)  # Cap at 10 Gbps
    
    jitter = np.random.exponential(scale=5.0, size=num_samples)  # in ms
    jitter = np.minimum(jitter, 100.0)  # Cap at 100 ms
    
    buffer_pressure = np.random.beta(2.0, 5.0, size=num_samples)  # 0-1 value
    
    congestion = np.random.beta(1.5, 4.0, size=num_samples)  # 0-1 value
    
    # Define a function to compute optimal MTU based on network conditions
    # This is a simplified model - in reality, this would be more complex
    def compute_optimal_mtu(
        pl: float, lat: float, tp: float, jit: float, bp: float, cong: float
    ) -> int:
        # Base MTU varies between 576 and 9000
        base_mtu = 1500
        
        # Adjust based on packet loss (higher loss -> lower MTU)
        mtu = base_mtu * np.exp(-0.05 * pl)
        
        # Adjust based on latency (higher latency -> lower MTU)
        mtu *= np.exp(-0.002 * lat)
        
        # Adjust based on throughput (higher throughput -> higher MTU)
        mtu *= np.log1p(tp) / np.log1p(100)
        
        # Adjust based on jitter (higher jitter -> lower MTU)
        mtu *= np.exp(-0.01 * jit)
        
        # Adjust based on buffer pressure (higher pressure -> lower MTU)
        mtu *= (1.0 - 0.5 * bp)
        
        # Adjust based on congestion (higher congestion -> lower MTU)
        mtu *= (1.0 - 0.7 * cong)
        
        # Ensure MTU is within reasonable bounds
        mtu = np.clip(mtu, 576, 9000)
        
        # Round to nearest multiple of 8
        mtu = int(round(mtu / 8) * 8)
        
        return mtu
    
    # Compute optimal MTU
    optimal_mtu = np.array([
        compute_optimal_mtu(pl, lat, tp, jit, bp, cong)
        for pl, lat, tp, jit, bp, cong 
        in zip(packet_loss, latency, throughput, jitter, buffer_pressure, congestion)
    ])
    
    # Add noise to make it more realistic
    if noise_level > 0:
        noise = np.random.normal(scale=noise_level * 100, size=num_samples)
        optimal_mtu = np.clip(
            optimal_mtu + noise.astype(int), 
            576, 
            9000
        )
        # Round to nearest multiple of 8
        optimal_mtu = (optimal_mtu // 8 * 8).astype(int)
    
    # Create DataFrame
    df = pd.DataFrame({
        "packet_loss": packet_loss,
        "latency": latency,
        "throughput": throughput,
        "jitter": jitter,
        "buffer_pressure": buffer_pressure,
        "congestion": congestion,
        "optimal_mtu": optimal_mtu
    })
    
    return df


def build_model(
    input_shape: int,
    hidden_units: List[int] = [64, 32],
    dropout_rate: float = 0.2
) -> tf.keras.Model:
    """
    Build a TensorFlow model for MTU prediction.
    
    Args:
        input_shape: Number of input features
        hidden_units: Number of units in hidden layers
        dropout_rate: Dropout rate for regularization
        
    Returns:
        Compiled TensorFlow model
    """
    model = tf.keras.Sequential()
    
    # Input layer
    model.add(tf.keras.layers.Input(shape=(input_shape,)))
    
    # Hidden layers
    for units in hidden_units:
        model.add(tf.keras.layers.Dense(units, activation="relu"))
        model.add(tf.keras.layers.BatchNormalization())
        model.add(tf.keras.layers.Dropout(dropout_rate))
    
    # Output layer (MTU is a single continuous value)
    model.add(tf.keras.layers.Dense(1, activation="linear"))
    
    # Compile model
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss="mse",
        metrics=["mae"]
    )
    
    return model


def train_model(
    df: pd.DataFrame,
    features: List[str],
    target: str,
    epochs: int = 50,
    batch_size: int = 32
) -> Tuple[tf.keras.Model, StandardScaler]:
    """
    Train a TensorFlow model for MTU prediction.
    
    Args:
        df: DataFrame containing the training data
        features: List of feature column names
        target: Target column name
        epochs: Number of training epochs
        batch_size: Training batch size
        
    Returns:
        Tuple of (trained model, feature scaler)
    """
    # Split features and target
    X = df[features].values
    y = df[target].values
    
    # Split into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # Standardize features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    
    # Build model
    model = build_model(input_shape=len(features))
    
    # Train model
    logger.info("Training model...")
    history = model.fit(
        X_train, y_train,
        epochs=epochs,
        batch_size=batch_size,
        validation_data=(X_test, y_test),
        verbose=1
    )
    
    # Evaluate model
    loss, mae = model.evaluate(X_test, y_test, verbose=0)
    logger.info(f"Test loss: {loss:.4f}")
    logger.info(f"Test MAE: {mae:.4f}")
    
    return model, scaler


def convert_to_tflite(
    model: tf.keras.Model,
    output_path: str,
    quantize: bool = True
) -> None:
    """
    Convert a TensorFlow model to TensorFlow Lite format.
    
    Args:
        model: TensorFlow model to convert
        output_path: Path to save the TFLite model
        quantize: Whether to quantize the model
    """
    logger.info("Converting model to TensorFlow Lite format...")
    
    # Convert model to TFLite format
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    
    # Quantize model if requested
    if quantize:
        converter.optimizations = [tf.lite.Optimize.DEFAULT]
    
    tflite_model = converter.convert()
    
    # Save model
    with open(output_path, "wb") as f:
        f.write(tflite_model)
    
    logger.info(f"TFLite model saved to {output_path}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Train MTU prediction model")
    parser.add_argument("--output", type=str, default="models/mtu_predictor.tflite",
                        help="Output path for TFLite model")
    parser.add_argument("--samples", type=int, default=10000,
                        help="Number of synthetic samples to generate")
    parser.add_argument("--epochs", type=int, default=50,
                        help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=32,
                        help="Training batch size")
    parser.add_argument("--no-quantize", action="store_true",
                        help="Disable model quantization")
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    # Generate synthetic data
    df = generate_synthetic_data(num_samples=args.samples)
    
    # Define features and target
    features = ["packet_loss", "latency", "throughput", "jitter", "buffer_pressure", "congestion"]
    target = "optimal_mtu"
    
    # Train model
    model, scaler = train_model(
        df=df,
        features=features,
        target=target,
        epochs=args.epochs,
        batch_size=args.batch_size
    )
    
    # Convert to TFLite
    convert_to_tflite(
        model=model,
        output_path=args.output,
        quantize=not args.no_quantize
    )
    
    # Save feature names and scaler parameters
    import json
    with open(os.path.join(os.path.dirname(args.output), "model_metadata.json"), "w") as f:
        json.dump({
            "features": features,
            "scaler_mean": scaler.mean_.tolist(),
            "scaler_scale": scaler.scale_.tolist()
        }, f, indent=2)
    
    logger.info("Done!")


if __name__ == "__main__":
    main()
