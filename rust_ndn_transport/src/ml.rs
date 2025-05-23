//
// μDCN ML-based MTU Prediction
//
// This module implements the ML-based MTU prediction capabilities
// that optimize network performance by predicting the optimal MTU
// based on network conditions and traffic patterns.
//

use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{Duration, interval};
use std::collections::VecDeque;
use log::{debug, info, warn, error};

use crate::error::Result;
use crate::quic::{ConnectionStats, ConnectionState};
use crate::metrics::MetricValue;

/// ML feature set for MTU prediction
#[derive(Debug, Clone)]
pub struct MtuFeatures {
    /// Average round-trip time in milliseconds
    pub avg_rtt_ms: f64,
    
    /// Average throughput in bytes per second
    pub avg_throughput_bps: f64,
    
    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss_rate: f64,
    
    /// Connection congestion window size
    pub congestion_window: usize,
    
    /// Average packet size in bytes
    pub avg_packet_size: usize,
    
    /// Standard deviation of packet sizes
    pub packet_size_stddev: f64,
    
    /// Network type hint (0=unknown, 1=ethernet, 2=wifi, 3=cellular)
    pub network_type: u8,
    
    /// Time of day (0-24 hours)
    pub time_of_day: f64,
}

impl Default for MtuFeatures {
    fn default() -> Self {
        Self {
            avg_rtt_ms: 50.0,
            avg_throughput_bps: 1_000_000.0, // 1 Mbps default
            packet_loss_rate: 0.0,
            congestion_window: 10,
            avg_packet_size: 1200,
            packet_size_stddev: 200.0,
            network_type: 0, // Unknown
            time_of_day: 12.0, // Noon
        }
    }
}

/// ML-based MTU prediction model interface
pub trait MtuPredictionModel: Send + Sync {
    /// Predict optimal MTU based on network features
    fn predict(&self, features: &MtuFeatures) -> Result<usize>;
    
    /// Update the model with new data
    fn update(&mut self, features: &MtuFeatures, actual_optimal_mtu: usize) -> Result<()>;
    
    /// Get model type name
    fn model_type(&self) -> &'static str;
}

/// Simple rule-based MTU prediction model
pub struct SimpleRuleBasedModel {
    /// Base MTU
    base_mtu: usize,
    
    /// Min MTU
    min_mtu: usize,
    
    /// Max MTU
    max_mtu: usize,
    
    /// History of recent predictions
    prediction_history: VecDeque<usize>,
}

impl SimpleRuleBasedModel {
    /// Create a new simple rule-based model
    pub fn new(base_mtu: usize, min_mtu: usize, max_mtu: usize) -> Self {
        Self {
            base_mtu,
            min_mtu,
            max_mtu,
            prediction_history: VecDeque::with_capacity(10),
        }
    }
}

impl MtuPredictionModel for SimpleRuleBasedModel {
    fn predict(&self, features: &MtuFeatures) -> Result<usize> {
        // Base MTU adjusted by network conditions
        let mut predicted_mtu = self.base_mtu;
        
        // Decrease MTU when RTT is high or packet loss exists
        if features.avg_rtt_ms > 100.0 || features.packet_loss_rate > 0.01 {
            predicted_mtu = (predicted_mtu as f64 * 0.9) as usize;
        }
        
        // Decrease further with very high RTT or high packet loss
        if features.avg_rtt_ms > 200.0 || features.packet_loss_rate > 0.05 {
            predicted_mtu = (predicted_mtu as f64 * 0.9) as usize;
        }
        
        // Increase MTU when throughput is high and packet loss is low
        if features.avg_throughput_bps > 5_000_000.0 && features.packet_loss_rate < 0.005 {
            predicted_mtu = (predicted_mtu as f64 * 1.1) as usize;
        }
        
        // Adjust based on average packet size
        if features.avg_packet_size > predicted_mtu {
            // If most packets are larger than current MTU, increase it
            predicted_mtu = std::cmp::min(
                (predicted_mtu as f64 * 1.05) as usize,
                features.avg_packet_size + 100
            );
        } else if features.avg_packet_size < predicted_mtu / 2 {
            // If most packets are much smaller than MTU, decrease it
            predicted_mtu = (predicted_mtu as f64 * 0.95) as usize;
        }
        
        // Adjust for network type
        match features.network_type {
            1 => {}, // Ethernet - no adjustment
            2 => predicted_mtu = (predicted_mtu as f64 * 0.95) as usize, // WiFi - slight decrease
            3 => predicted_mtu = (predicted_mtu as f64 * 0.85) as usize, // Cellular - larger decrease
            _ => {}, // Unknown - no adjustment
        }
        
        // Bound the MTU within min and max
        predicted_mtu = std::cmp::max(predicted_mtu, self.min_mtu);
        predicted_mtu = std::cmp::min(predicted_mtu, self.max_mtu);
        
        // Round to nearest 100 for clean values
        predicted_mtu = ((predicted_mtu + 50) / 100) * 100;
        
        Ok(predicted_mtu)
    }
    
    fn update(&mut self, _features: &MtuFeatures, actual_optimal_mtu: usize) -> Result<()> {
        // Add to history for future smoothing
        self.prediction_history.push_back(actual_optimal_mtu);
        
        // Keep history to a reasonable size
        if self.prediction_history.len() > 10 {
            self.prediction_history.pop_front();
        }
        
        Ok(())
    }
    
    fn model_type(&self) -> &'static str {
        "SimpleRuleBased"
    }
}

/// Python-based ML MTU prediction model
/// This will bridge to a Python ML model via PyO3
#[cfg(feature = "extension-module")]
pub struct PythonMlModel {
    /// Python model reference (managed via PyO3)
    #[cfg(feature = "extension-module")]
    model: pyo3::PyObject,
    
    /// Name of the model
    model_name: String,
}

#[cfg(feature = "extension-module")]
impl PythonMlModel {
    /// Create a new Python ML model
    pub fn new(model_name: &str) -> Result<Self> {
        use pyo3::prelude::*;
        use pyo3::types::PyDict;
        
        // Acquire the GIL
        Python::with_gil(|py| {
            // Try to import the model module
            let model_module = py.import("udcn_ml_models")?;
            
            // Create a new model instance
            let model = model_module.call_method1("create_model", (model_name,))?;
            
            Ok(Self {
                model: model.into(),
                model_name: model_name.to_string(),
            })
        }).map_err(|e| crate::error::Error::MlModel(format!("Failed to create Python ML model: {}", e)))
    }
}

#[cfg(feature = "extension-module")]
impl MtuPredictionModel for PythonMlModel {
    fn predict(&self, features: &MtuFeatures) -> Result<usize> {
        use pyo3::prelude::*;
        use pyo3::types::PyDict;
        
        // Acquire the GIL
        Python::with_gil(|py| {
            // Create a features dictionary
            let features_dict = PyDict::new(py);
            features_dict.set_item("avg_rtt_ms", features.avg_rtt_ms)?;
            features_dict.set_item("avg_throughput_bps", features.avg_throughput_bps)?;
            features_dict.set_item("packet_loss_rate", features.packet_loss_rate)?;
            features_dict.set_item("congestion_window", features.congestion_window)?;
            features_dict.set_item("avg_packet_size", features.avg_packet_size)?;
            features_dict.set_item("packet_size_stddev", features.packet_size_stddev)?;
            features_dict.set_item("network_type", features.network_type)?;
            features_dict.set_item("time_of_day", features.time_of_day)?;
            
            // Call the predict method
            let result = self.model.call_method1(py, "predict", (features_dict,))?;
            
            // Extract the predicted MTU
            let predicted_mtu = result.extract::<usize>(py)?;
            
            Ok(predicted_mtu)
        }).map_err(|e| crate::error::Error::MlModel(format!("Failed to predict MTU: {}", e)))
    }
    
    fn update(&mut self, features: &MtuFeatures, actual_optimal_mtu: usize) -> Result<()> {
        use pyo3::prelude::*;
        use pyo3::types::PyDict;
        
        // Acquire the GIL
        Python::with_gil(|py| {
            // Create a features dictionary
            let features_dict = PyDict::new(py);
            features_dict.set_item("avg_rtt_ms", features.avg_rtt_ms)?;
            features_dict.set_item("avg_throughput_bps", features.avg_throughput_bps)?;
            features_dict.set_item("packet_loss_rate", features.packet_loss_rate)?;
            features_dict.set_item("congestion_window", features.congestion_window)?;
            features_dict.set_item("avg_packet_size", features.avg_packet_size)?;
            features_dict.set_item("packet_size_stddev", features.packet_size_stddev)?;
            features_dict.set_item("network_type", features.network_type)?;
            features_dict.set_item("time_of_day", features.time_of_day)?;
            
            // Call the update method
            self.model.call_method1(py, "update", (features_dict, actual_optimal_mtu))?;
            
            Ok(())
        }).map_err(|e| crate::error::Error::MlModel(format!("Failed to update ML model: {}", e)))
    }
    
    fn model_type(&self) -> &'static str {
        "PythonML"
    }
}

/// ML-based MTU prediction service
pub struct MtuPredictionService {
    /// The ML model used for prediction
    model: Arc<RwLock<Box<dyn MtuPredictionModel>>>,
    
    /// Network features used for prediction
    features: Arc<RwLock<MtuFeatures>>,
    
    /// Prediction interval in seconds
    prediction_interval: u64,
    
    /// Whether the service is running
    running: Arc<RwLock<bool>>,
    
    /// Task handle for the prediction loop
    prediction_task: RwLock<Option<JoinHandle<()>>>,
    
    /// Callback for MTU updates
    update_callback: Arc<RwLock<Option<Box<dyn Fn(usize) -> Result<()> + Send + Sync>>>>,
}

impl MtuPredictionService {
    /// Create a new MTU prediction service
    pub fn new(model: Box<dyn MtuPredictionModel>, prediction_interval: u64) -> Self {
        Self {
            model: Arc::new(RwLock::new(model)),
            features: Arc::new(RwLock::new(MtuFeatures::default())),
            prediction_interval,
            running: Arc::new(RwLock::new(false)),
            prediction_task: RwLock::new(None),
            update_callback: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Create a new service with a rule-based model
    pub fn with_rule_based_model(base_mtu: usize, min_mtu: usize, max_mtu: usize, prediction_interval: u64) -> Self {
        let model = Box::new(SimpleRuleBasedModel::new(base_mtu, min_mtu, max_mtu));
        Self::new(model, prediction_interval)
    }
    
    /// Start the prediction service
    pub async fn start<F>(&self, update_callback: F) -> Result<()>
    where
        F: Fn(usize) -> Result<()> + Send + Sync + 'static
    {
        // Store the callback
        *self.update_callback.write().await = Some(Box::new(update_callback));
        
        // Set running flag
        *self.running.write().await = true;
        
        // Start the prediction loop
        // Create proper Arc clones of all the shared state
        let model = Arc::clone(&self.model);
        let features = Arc::clone(&self.features);
        let running = Arc::clone(&self.running);
        let update_callback = Arc::clone(&self.update_callback);
        let interval_secs = self.prediction_interval;
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));
            
            loop {
                interval.tick().await;
                
                // Check if we should continue running
                if !*running.read().await {
                    break;
                }
                
                // Get current features
                let current_features = features.read().await.clone();
                
                // Predict optimal MTU
                match model.read().await.predict(&current_features) {
                    Ok(predicted_mtu) => {
                        debug!("ML model predicted MTU: {}", predicted_mtu);
                        
                        // Call the update callback
                        if let Some(callback) = update_callback.read().await.as_ref() {
                            if let Err(e) = callback(predicted_mtu) {
                                error!("Failed to update MTU: {}", e);
                            } else {
                                info!("Updated MTU to {} based on ML prediction", predicted_mtu);
                                
                                // Update the model with the new data
                                if let Err(e) = model.write().await.update(&current_features, predicted_mtu) {
                                    error!("Failed to update ML model: {}", e);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        error!("ML model prediction failed: {}", e);
                    }
                }
            }
        });
        
        // Store the task handle
        *self.prediction_task.write().await = Some(task);
        
        info!("MTU prediction service started with {} model", self.model.read().await.model_type());
        Ok(())
    }
    
    /// Stop the prediction service
    pub async fn stop(&self) -> Result<()> {
        // Set running flag to false
        *self.running.write().await = false;
        
        // Abort the prediction task if it exists
        if let Some(task) = self.prediction_task.write().await.take() {
            task.abort();
            info!("MTU prediction service stopped");
        }
        
        Ok(())
    }
    
    /// Update network features from connection statistics
    pub async fn update_features_from_stats(&self, stats: &ConnectionStats) -> Result<()> {
        let mut features = self.features.write().await;
        
        // Use the avg_rtt_ms field directly from the updated ConnectionStats struct
        features.avg_rtt_ms = stats.avg_rtt_ms;
        
        // Calculate throughput based on data received and time (if available)
        // For now, just use a placeholder calculation
        features.avg_throughput_bps = (stats.data_received * 8) as f64; // Simple conversion from bytes to bits
        
        features.congestion_window = 0; // Will be filled in by caller
        
        // Calculate packet loss rate based on interests sent vs data received
        if stats.interests_sent > 0 {
            features.packet_loss_rate = 1.0 - (stats.data_received as f64 / stats.interests_sent as f64);
        }
        
        Ok(())
    }
    
    /// Set network type hint
    pub async fn set_network_type(&self, network_type: u8) -> Result<()> {
        let mut features = self.features.write().await;
        features.network_type = network_type;
        Ok(())
    }
    
    /// Get current features
    pub async fn get_features(&self) -> MtuFeatures {
        self.features.read().await.clone()
    }
    
    /// Get model type
    pub async fn get_model_type(&self) -> String {
        self.model.read().await.model_type().to_string()
    }
    
    /// Get metrics
    pub async fn get_metrics(&self) -> std::collections::HashMap<String, MetricValue> {
        let mut metrics = std::collections::HashMap::new();
        let features = self.features.read().await.clone();
        
        metrics.insert("ml.avg_rtt_ms".to_string(), MetricValue::Gauge(features.avg_rtt_ms));
        metrics.insert("ml.avg_throughput_bps".to_string(), MetricValue::Gauge(features.avg_throughput_bps));
        metrics.insert("ml.packet_loss_rate".to_string(), MetricValue::Gauge(features.packet_loss_rate));
        metrics.insert("ml.congestion_window".to_string(), MetricValue::Gauge(features.congestion_window as f64));
        metrics.insert("ml.avg_packet_size".to_string(), MetricValue::Gauge(features.avg_packet_size as f64));
        metrics.insert("ml.model_type".to_string(), MetricValue::Text(self.model.read().await.model_type().to_string()));
        
        metrics
    }
}
