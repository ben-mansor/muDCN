// MTU Prediction Module for μDCN
//
// This module provides integration with the TensorFlow Lite model for MTU prediction
// and implements the gRPC handlers for the ML-based MTU prediction service.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::error::{Error, Result};
use crate::grpc::udcn::{
    MtuPredictionRequest, MtuPredictionResponse, 
    MtuOverrideRequest, MtuOverrideResponse,
    MtuHistoryRequest, MtuHistoryResponse, MtuPredictionRecord
};

// Simple heuristic-based MTU prediction (fallback for when TFLite model isn't available)
pub struct MTUPredictor {
    // Current override value, if set
    override_value: RwLock<Option<u32>>,
    
    // Prediction history
    prediction_history: RwLock<Vec<PredictionRecord>>,
    
    // Maximum history size
    max_history_size: usize,
}

#[derive(Clone, Debug)]
pub struct PredictionRecord {
    pub rtt_ms: f32,
    pub packet_loss_rate: f32,
    pub throughput_mbps: f32,
    pub predicted_mtu: u32,
    pub raw_prediction: f32,
    pub is_override: bool,
    pub timestamp_ms: u64,
}

impl MTUPredictor {
    /// Create a new MTU predictor
    pub fn new() -> Self {
        Self {
            override_value: RwLock::new(None),
            prediction_history: RwLock::new(Vec::new()),
            max_history_size: 1000,
        }
    }
    
    /// Predict the optimal MTU size based on network metrics
    pub async fn predict_mtu(
        &self,
        rtt_ms: f32,
        packet_loss_rate: f32,
        throughput_mbps: f32,
    ) -> Result<(u32, f32)> {
        // Check if override is set
        let override_val = self.override_value.read().await;
        if let Some(mtu) = *override_val {
            // Record prediction (with override)
            self.record_prediction(
                rtt_ms, 
                packet_loss_rate, 
                throughput_mbps, 
                mtu, 
                mtu as f32, 
                true
            ).await;
            
            return Ok((mtu, 0.0)); // Return override value with 0.0 as raw value
        }
        
        // Calculate MTU using heuristic method
        // This is a simplified heuristic function:
        // - Low RTT, low loss, high throughput → Higher MTU
        // - High RTT, high loss, low throughput → Lower MTU
        
        // Base MTU starts at 1500 (standard Ethernet)
        let base_mtu = 1500.0;
        
        // RTT factor: reduce MTU for high RTT
        let rtt_factor = f32::max(0.6, 1.0 - (rtt_ms / 300.0) * 0.4);
        
        // Loss factor: significantly reduce MTU with increased loss
        let loss_factor = f32::max(0.5, 1.0 - packet_loss_rate * 5.0);
        
        // Throughput factor: increase MTU for high throughput
        let throughput_factor = f32::min(1.5, 0.8 + (throughput_mbps / 1000.0) * 0.7);
        
        // Calculate raw MTU prediction
        let raw_mtu = base_mtu * rtt_factor * loss_factor * throughput_factor;
        
        // Discretize to common MTU values
        let predicted_mtu = if raw_mtu < 800.0 {
            576 // Minimum safe MTU
        } else if raw_mtu < 1300.0 {
            1280 // IPv6 minimum
        } else if raw_mtu < 1450.0 {
            1400
        } else if raw_mtu < 1550.0 {
            1500 // Standard Ethernet
        } else if raw_mtu < 4000.0 {
            3000 // Jumbo frames
        } else {
            9000 // Maximum jumbo frames
        };
        
        // Record prediction
        self.record_prediction(
            rtt_ms, 
            packet_loss_rate, 
            throughput_mbps, 
            predicted_mtu, 
            raw_mtu, 
            false
        ).await;
        
        Ok((predicted_mtu, raw_mtu))
    }
    
    /// Record a prediction in the history
    async fn record_prediction(
        &self,
        rtt_ms: f32,
        packet_loss_rate: f32,
        throughput_mbps: f32,
        predicted_mtu: u32,
        raw_prediction: f32,
        is_override: bool,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        let record = PredictionRecord {
            rtt_ms,
            packet_loss_rate,
            throughput_mbps,
            predicted_mtu,
            raw_prediction,
            is_override,
            timestamp_ms: timestamp,
        };
        
        // Add to history
        let mut history = self.prediction_history.write().await;
        history.push(record);
        
        // Trim history if needed
        if history.len() > self.max_history_size {
            *history = history.iter().skip(history.len() - self.max_history_size).cloned().collect();
        }
    }
    
    /// Set an override value for the MTU prediction
    pub async fn set_override(&self, mtu_value: Option<u32>) -> Result<()> {
        // Validate MTU if provided
        if let Some(mtu) = mtu_value {
            if mtu < 576 || mtu > 9000 {
                return Err(Error::InvalidArgument(
                    format!("MTU value {} is outside valid range (576-9000)", mtu)
                ));
            }
        }
        
        // Set override value
        let mut override_val = self.override_value.write().await;
        *override_val = mtu_value;
        
        Ok(())
    }
    
    /// Get the current override value
    pub async fn get_override(&self) -> Option<u32> {
        let override_val = self.override_value.read().await;
        *override_val
    }
    
    /// Get prediction history
    pub async fn get_prediction_history(&self, max_entries: Option<u32>) -> Vec<PredictionRecord> {
        let history = self.prediction_history.read().await;
        
        match max_entries {
            Some(max) if max > 0 && max < history.len() as u32 => {
                history.iter().skip(history.len() - max as usize).cloned().collect()
            },
            _ => history.clone(),
        }
    }
}

// Implement to/from conversion between the Rust types and the gRPC types
impl From<&PredictionRecord> for MtuPredictionRecord {
    fn from(record: &PredictionRecord) -> Self {
        Self {
            rtt_ms: record.rtt_ms,
            packet_loss_rate: record.packet_loss_rate,
            throughput_mbps: record.throughput_mbps,
            predicted_mtu: record.predicted_mtu,
            raw_prediction: record.raw_prediction,
            is_override: record.is_override,
            timestamp_ms: record.timestamp_ms,
        }
    }
}

// Default implementation
impl Default for MTUPredictor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_mtu_prediction() {
        let predictor = MTUPredictor::new();
        
        // Test prediction with good network conditions
        let (mtu, raw) = predictor.predict_mtu(10.0, 0.001, 500.0).await.unwrap();
        assert!(mtu >= 1500, "MTU for good network conditions should be at least 1500");
        
        // Test prediction with poor network conditions
        let (mtu, raw) = predictor.predict_mtu(250.0, 0.08, 10.0).await.unwrap();
        assert!(mtu <= 1400, "MTU for poor network conditions should be at most 1400");
        
        // Test override
        predictor.set_override(Some(1400)).await.unwrap();
        let (mtu, _) = predictor.predict_mtu(10.0, 0.001, 500.0).await.unwrap();
        assert_eq!(mtu, 1400, "MTU should match override value");
        
        // Test disabling override
        predictor.set_override(None).await.unwrap();
        let (mtu, _) = predictor.predict_mtu(10.0, 0.001, 500.0).await.unwrap();
        assert!(mtu >= 1500, "MTU should return to predicted value after disabling override");
        
        // Test history
        let history = predictor.get_prediction_history(Some(10)).await;
        assert_eq!(history.len(), 4, "History should contain 4 records");
    }
    
    #[tokio::test]
    async fn test_mtu_override_validation() {
        let predictor = MTUPredictor::new();
        
        // Test setting invalid override values
        assert!(predictor.set_override(Some(100)).await.is_err(), 
                "Should reject MTU below 576");
        
        assert!(predictor.set_override(Some(10000)).await.is_err(), 
                "Should reject MTU above 9000");
        
        // Test valid override values
        assert!(predictor.set_override(Some(576)).await.is_ok(), 
                "Should accept minimum MTU of 576");
        
        assert!(predictor.set_override(Some(9000)).await.is_ok(), 
                "Should accept maximum MTU of 9000");
    }
}
