//
// μDCN Rust Transport Layer
//
// This library implements a high-performance NDN transport layer
// using Rust and QUIC for maximum performance and safety.
//

// Module organization
pub mod ndn;            // NDN protocol implementation
pub mod quic;           // QUIC transport integration
pub mod quic_transport; // New QUIC transport implementation for Phase 2
pub mod cache;          // Content store implementation
pub mod metrics;        // Prometheus metrics collection
pub mod name;           // NDN name handling and manipulation
pub mod security;       // Cryptographic operations and verification
pub mod fragmentation;  // Packet fragmentation and reassembly
pub mod interface;      // Network interface management
pub mod error;          // Error types
pub mod python;         // Python bindings for control plane integration
pub mod ml;             // ML-based MTU prediction

// Conditionally compile gRPC module
#[cfg(feature = "grpc")]
pub mod grpc;

// Tests
#[cfg(test)]
pub mod tests;

// XDP Integration
pub mod xdp;          // Integration with eBPF/XDP components

// Export Python module when building with PyO3
#[cfg(feature = "extension-module")]
use pyo3::prelude::*;

#[cfg(feature = "extension-module")]
#[pymodule]
fn udcn_transport(py: Python, m: &PyModule) -> PyResult<()> {
    python::udcn_transport(py, m)
}

use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use std::time::Duration;
use std::time::Instant;
use dashmap::DashMap;

use crate::metrics::MetricsCollector;

// Export core types from modules
pub use crate::ndn::{Interest, Data, Nack};
pub use crate::name::Name;
pub use crate::error::{Error, Result};
pub use crate::fragmentation::Fragmenter;
pub use crate::quic::QuicEngine;
pub use crate::quic::PrefixHandler;
pub use crate::metrics::MetricValue;
pub use crate::xdp::XdpManager;
pub use crate::xdp::XdpConfig;

/// Configuration for the μDCN transport
#[derive(Debug, Clone)]
pub struct Config {
    /// Local address to bind to
    pub bind_address: String,
    
    /// Port to listen on
    pub port: u16,
    
    /// Maximum Transmission Unit (MTU) in bytes
    pub mtu: usize,
    
    /// Content store capacity
    pub cache_capacity: usize,
    
    /// Idle timeout in seconds
    pub idle_timeout: u64,
    
    /// Enable metrics collection
    pub enable_metrics: bool,
    
    /// Metrics port
    pub metrics_port: u16,
    
    /// Maximum packet size for fragmentation (in bytes)
    pub max_packet_size: usize,
    
    /// Logging level
    pub log_level: String,
    
    /// Number of retries for failed operations
    pub retries: u32,
    
    /// Retry interval in milliseconds
    pub retry_interval: u64,
    
    /// XDP configuration
    pub xdp_config: Option<XdpConfig>,
    
    /// Enable ML-based MTU prediction
    pub enable_ml_mtu_prediction: bool,
    
    /// ML prediction interval in seconds
    pub ml_prediction_interval: u64,
    
    /// ML model type ("rule-based" or "python")
    pub ml_model_type: String,
    
    /// Minimum MTU for ML prediction
    pub min_mtu: usize,
    
    /// Maximum MTU for ML prediction
    pub max_mtu: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 6363,
            mtu: 1400,
            cache_capacity: 10000,
            idle_timeout: 60,
            enable_metrics: true,
            metrics_port: 9090,
            max_packet_size: 65535,
            log_level: "info".to_string(),
            retries: 3,
            retry_interval: 1000,
            xdp_config: None,
            enable_ml_mtu_prediction: false,
            ml_prediction_interval: 30,
            ml_model_type: "rule-based".to_string(),
            min_mtu: 576,    // IPv4 minimum MTU
            max_mtu: 9000,   // Jumbo frame size
        }
    }
}

// Statistics struct
#[derive(Clone, Debug)]
pub struct TransportStatistics {
    pub uptime_seconds: u64,
    pub interests_processed: u64,
    pub data_packets_sent: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_ratio: f64,
}

// Transport state enum
#[derive(Clone, Debug, PartialEq)]
pub enum TransportState {
    Running,
    Stopped,
    Paused,
    Error,
    Starting,
    Stopping,
}

// Type aliases
type PrefixHandler = Box<dyn Fn(Interest) -> Result<Data> + Send + Sync>;
type PrefixTable = Arc<DashMap<Name, (u64, PrefixHandler)>>;
type ForwardingTable = Arc<DashMap<Name, (u64, usize)>>;

/// The main QUIC-based NDN transport layer
// Custom Debug implementation to skip fields that don't implement Debug
impl std::fmt::Debug for UdcnTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdcnTransport")
            .field("config", &self.config)
            .field("state", &self.state)
            // Skip metrics field if it has issues with Debug
            // .field("metrics", &self.metrics)
            .field("start_time", &self.start_time)
            // Skip prefix_table as it contains function pointers that don't implement Debug
            .field("forwarding_table_size", &self.forwarding_table.len())
            .field("next_registration_id", &self.next_registration_id)
            // Skip other fields that might not implement Debug
            .field("grpc_server_handle", &self.grpc_server_handle)
            .finish_non_exhaustive()
    }
}
pub struct UdcnTransport {
    config: Arc<RwLock<Config>>,
    state: Arc<RwLock<TransportState>>,
    metrics: Arc<MetricsCollector>,
    start_time: Arc<RwLock<Instant>>,
    prefix_table: PrefixTable,
    forwarding_table: ForwardingTable,
    next_registration_id: Arc<RwLock<u64>>,
    grpc_server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    ml_prediction: Arc<RwLock<Option<ml::MtuPredictionService>>>,
}

impl UdcnTransport {
    // Create a new transport instance
    pub async fn new(config: Config) -> Result<Self> {
        let metrics = Arc::new(MetricsCollector::new(
            config.metrics_port,
            config.enable_metrics,
        ));
        
        // Initialize ML prediction service if enabled
        let ml_prediction = if config.enable_ml_mtu_prediction {
            let model: Box<dyn ml::MtuPredictionModel> = if config.ml_model_type == "python" {
                #[cfg(feature = "extension-module")]
                {
                    match ml::PythonMlModel::new("udcn_mtu_predictor") {
                        Ok(model) => Box::new(model),
                        Err(_) => {
                            // Fall back to rule-based model if Python model fails
                            log::warn!("Failed to initialize Python ML model, falling back to rule-based model");
                            Box::new(ml::SimpleRuleBasedModel::new(config.mtu, config.min_mtu, config.max_mtu))
                        }
                    }
                }
                #[cfg(not(feature = "extension-module"))]
                {
                    log::warn!("Python ML model requested but extension-module feature not enabled, using rule-based model");
                    Box::new(ml::SimpleRuleBasedModel::new(config.mtu, config.min_mtu, config.max_mtu))
                }
            } else {
                // Default to rule-based model
                Box::new(ml::SimpleRuleBasedModel::new(config.mtu, config.min_mtu, config.max_mtu))
            };
            
            Some(ml::MtuPredictionService::new(model, config.ml_prediction_interval))
        } else {
            None
        };
        
        let transport = Self {
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(TransportState::Stopped)),
            metrics,
            start_time: Arc::new(RwLock::new(Instant::now())),
            prefix_table: Arc::new(DashMap::new()),
            forwarding_table: Arc::new(DashMap::new()),
            next_registration_id: Arc::new(RwLock::new(1)),
            grpc_server_handle: Arc::new(RwLock::new(None)),
            ml_prediction: Arc::new(RwLock::new(ml_prediction)),
        };
        
        Ok(transport)
    }
    
    // Start the transport
    pub async fn start(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if *state == TransportState::Running {
            return Ok(());
        }
        
        *state = TransportState::Starting;
        
        // Reset start time
        let mut start_time = self.start_time.write().await;
        *start_time = Instant::now();
        
        // Initialize QUIC engine and other components here...
        
        // Start ML-based MTU prediction if enabled
        self.start_ml_prediction().await?;
        
        // Start gRPC server if feature is enabled
        #[cfg(feature = "grpc")]
        self.start_grpc_server().await?;
        
        *state = TransportState::Running;
        Ok(())
    }
    
    // Stop the transport
    pub async fn stop(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if *state == TransportState::Stopped {
            return Ok(());
        }
        
        *state = TransportState::Stopping;
        
        // Stop gRPC server if feature is enabled
        #[cfg(feature = "grpc")]
        self.stop_grpc_server().await?;
        
        // Stop ML prediction service if running
        self.stop_ml_prediction().await?;
        
        // Shutdown QUIC engine and other components here...
        
        *state = TransportState::Stopped;
        Ok(())
    }
    
    // Pause the transport
    pub async fn pause(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if *state != TransportState::Running {
            return Err(Error::InvalidState("Transport is not running".to_string()));
        }
        
        // Implement pause logic here...
        
        *state = TransportState::Paused;
        Ok(())
    }
    
    // Resume the transport
    pub async fn resume(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if *state != TransportState::Paused {
            return Err(Error::InvalidState("Transport is not paused".to_string()));
        }
        
        // Implement resume logic here...
        
        *state = TransportState::Running;
        Ok(())
    }
    
    // Graceful shutdown
    pub async fn shutdown(&self) -> Result<()> {
        // Implement clean shutdown logic here...
        self.stop().await
    }
    
    // Register a prefix for handling interests
    pub async fn register_prefix(
        &self,
        prefix: Name,
        handler: PrefixHandler,
    ) -> Result<u64> {
        let mut next_id = self.next_registration_id.write().await;
        let registration_id = *next_id;
        *next_id += 1;
        
        self.prefix_table.insert(prefix, (registration_id, handler));
        
        Ok(registration_id)
    }
    
    // Register a prefix for forwarding
    pub async fn register_forwarding_prefix(
        &self,
        prefix: Name,
        priority: usize,
    ) -> Result<u64> {
        let mut next_id = self.next_registration_id.write().await;
        let registration_id = *next_id;
        *next_id += 1;
        
        self.forwarding_table.insert(prefix, (registration_id, priority));
        
        Ok(registration_id)
    }
    
    // Unregister a prefix
    pub async fn unregister_prefix(&self, registration_id: u64) -> Result<()> {
        // Try to remove from prefix table
        let mut removed = false;
        for entry in self.prefix_table.iter() {
            let (id, _) = entry.value();
            if *id == registration_id {
                self.prefix_table.remove(&entry.key().clone());
                removed = true;
                break;
            }
        }
        
        // Try forwarding table if not found in prefix table
        if !removed {
            for entry in self.forwarding_table.iter() {
                let (id, _) = entry.value();
                if *id == registration_id {
                    self.forwarding_table.remove(&entry.key().clone());
                    removed = true;
                    break;
                }
            }
        }
        
        if removed {
            Ok(())
        } else {
            Err(Error::NotFound(format!("Registration ID {} not found", registration_id)))
        }
    }
    
    // Update MTU
    pub async fn update_mtu(&self, mtu: usize) -> Result<()> {
        if mtu < 576 || mtu > 9000 {
            return Err(Error::InvalidArgument(
                format!("Invalid MTU: {}. Must be between 576 and 9000", mtu)
            ));
        }
        
        let mut config = self.config.write().await;
        let _old_mtu = config.mtu;
        config.mtu = mtu;
        
        // Update QUIC endpoints with new MTU
        // ...
        
        Ok(())
    }
    
    // Start ML-based MTU prediction
    pub async fn start_ml_prediction(&self) -> Result<()> {
        // Check if ML prediction is enabled in config
        let config = self.config.read().await;
        if !config.enable_ml_mtu_prediction {
            return Ok(());
        }
        
        let mut ml_service = self.ml_prediction.write().await;
        if let Some(service) = ml_service.as_mut() {
            // Create a closure that will update the MTU when the prediction service
            // determines a new optimal value
            let transport_config = self.config.clone();
            let update_callback = move |predicted_mtu: usize| {
                let mut config = match transport_config.try_write() {
                    Ok(guard) => guard,
                    Err(_) => return Err(Error::LockError("Failed to acquire config lock".to_string())),
                };
                
                // Only update if the prediction is significantly different
                if (predicted_mtu as i64 - config.mtu as i64).abs() > 100 {
                    log::info!("ML model suggests MTU change: {} -> {}", config.mtu, predicted_mtu);
                    config.mtu = predicted_mtu;
                    // The actual QUIC engine update would happen in a separate method
                }
                
                Ok(())
            };
            
            // Start the prediction service
            service.start(update_callback).await?;
            log::info!("ML-based MTU prediction service started");
        }
        
        Ok(())
    }
    
    // Stop ML-based MTU prediction
    pub async fn stop_ml_prediction(&self) -> Result<()> {
        let mut ml_service = self.ml_prediction.write().await;
        if let Some(service) = ml_service.as_mut() {
            service.stop().await?;
            log::info!("ML-based MTU prediction service stopped");
        }
        
        Ok(())
    }
    
    // Update ML prediction features with connection statistics
    pub async fn update_ml_features(&self, connection_stats: &quic::ConnectionStats) -> Result<()> {
        let ml_service = self.ml_prediction.read().await;
        if let Some(service) = ml_service.as_ref() {
            service.update_features_from_stats(connection_stats).await?;
        }
        
        Ok(())
    }
    
    // Get current MTU
    pub fn mtu(&self) -> usize {
        let config = match self.config.try_read() {
            Ok(guard) => guard,
            Err(_) => return 1500, // Default MTU value if config can't be read
        };
        config.mtu
    }
    
    // Send an interest and get data
    pub async fn send_interest(&self, interest: Interest) -> Result<Data> {
        // Check if we have a prefix registered that matches this interest
        for entry in self.prefix_table.iter() {
            let prefix = entry.key();
            let (_, handler) = entry.value();
            
            // Temporary fix: we'd normally use interest.matches(prefix)
            // For now, let's use a simple prefix check to avoid compilation errors
            if prefix.has_prefix(interest.name()) {
                return handler(interest);
            }
        }
        
        // Forward via QUIC to another node (simplified for now)
        // ...
        
        Err(Error::NotFound("No matching prefix".to_string()))
    }
    
    // Get metrics
    pub async fn get_metrics(&self) -> HashMap<String, MetricValue> {
        self.metrics.get_all_metrics().await
    }
    
    // Get network interfaces
    pub async fn get_network_interfaces(&self, _include_stats: bool) -> Result<Vec<String>> {
        // Placeholder implementation instead of interface::get_network_interfaces
        // Replace with actual implementation when available
        Ok(vec!["eth0".to_string(), "lo".to_string()])
    }
    
    // Get current state
    pub async fn state(&self) -> TransportState {
        self.state.read().await.clone()
    }
    
    // Create a mock transport instance for testing
    #[cfg(test)]
    pub fn new_mock() -> Self {
        let metrics = Arc::new(MetricsCollector::new(0, false));
        let config = Config::default();
        
        Self {
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(TransportState::Stopped)),
            metrics,
            start_time: Arc::new(RwLock::new(Instant::now())),
            prefix_table: Arc::new(DashMap::new()),
            forwarding_table: Arc::new(DashMap::new()),
            next_registration_id: Arc::new(RwLock::new(1)),
            grpc_server_handle: Arc::new(RwLock::new(None)),
            ml_prediction: Arc::new(RwLock::new(None)),
        }
    }
    
    // Configure the transport
    pub async fn configure(&self, config: Config) -> Result<()> {
        let mut current_config = self.config.write().await;
        
        // Preserve the current MTU since it's managed separately
        let current_mtu = current_config.mtu;
        
        // Update configuration
        *current_config = config;
        current_config.mtu = current_mtu;
        
        Ok(())
    }
    
    // Get current configuration
    pub async fn get_config(&self) -> Config {
        self.config.read().await.clone()
    }
    
    // Get statistics
    pub async fn get_statistics(&self) -> TransportStatistics {
        let start_time = self.start_time.read().await;
        let uptime = start_time.elapsed();
        
        let cache_hits = match self.metrics.get_metric("cache_hits").await {
            Some(crate::metrics::MetricValue::Counter(value)) => value,
            _ => 0,
        };
        let cache_misses = match self.metrics.get_metric("cache_misses").await {
            Some(crate::metrics::MetricValue::Counter(value)) => value,
            _ => 0,
        };
        let cache_hit_ratio = if cache_hits + cache_misses > 0 {
            cache_hits as f64 / (cache_hits + cache_misses) as f64
        } else {
            0.0
        };
        
        TransportStatistics {
            uptime_seconds: uptime.as_secs(),
            interests_processed: match self.metrics.get_metric("interests_processed").await {
                Some(crate::metrics::MetricValue::Counter(value)) => value,
                _ => 0,
            },
            data_packets_sent: match self.metrics.get_metric("data_packets_sent").await {
                Some(crate::metrics::MetricValue::Counter(value)) => value,
                _ => 0,
            },
            cache_hits,
            cache_misses,
            cache_hit_ratio,
        }
    }
    
    // Get detailed statistics as a string map for debugging/monitoring
    pub async fn get_detailed_statistics(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();
        
        // Get basic stats
        let basic_stats = self.get_statistics().await;
        stats.insert("uptime_seconds".to_string(), basic_stats.uptime_seconds.to_string());
        stats.insert("interests_processed".to_string(), basic_stats.interests_processed.to_string());
        stats.insert("data_packets_sent".to_string(), basic_stats.data_packets_sent.to_string());
        stats.insert("cache_hit_ratio".to_string(), format!("{:.2}", basic_stats.cache_hit_ratio));
        
        // Add current state
        let state = self.state.read().await;
        stats.insert("state".to_string(), format!("{:?}", *state));
        
        // Add info about registered prefixes
        stats.insert("registered_prefixes".to_string(), self.prefix_table.len().to_string());
        stats.insert("forwarding_prefixes".to_string(), self.forwarding_table.len().to_string());
        
        // Add metrics
        let metrics = self.metrics.get_all_metrics().await;
        for (key, value) in metrics {
            stats.insert(format!("metric_{}", key), format!("{:?}", value));
        }
        
        stats
    }
    
    // Start the gRPC server for control plane operations
    #[cfg(feature = "grpc")]  
    async fn start_grpc_server(&self) -> Result<()> {
        let mut server_handle = self.grpc_server_handle.write().await;
        
        // Skip if already started
        if server_handle.is_some() {
            return Ok(());
        }
        
        // Parse bind address for gRPC from config
        let config = self.config.read().await;
        let grpc_address = format!("{}:{}", 
            config.bind_address.split(':').next().unwrap_or("127.0.0.1"),
            config.metrics_port + 1 // Use metrics_port + 1 for gRPC
        );
        
        let addr: SocketAddr = grpc_address.parse()
            .map_err(|e| Error::InvalidArgument(format!("Invalid gRPC address: {}", e)))?;
        
        // Create Arc reference to self for the server
        let transport = Arc::new(self.clone());
        
        // Spawn gRPC server task
        let handle = tokio::spawn(async move {
            if let Err(e) = grpc::run_grpc_server(transport, addr).await {
                eprintln!("gRPC server error: {}", e);
            }
        });
        
        *server_handle = Some(handle);
        Ok(())
    }
    
    // Stop the gRPC server
    #[cfg(feature = "grpc")]  
    async fn stop_grpc_server(&self) -> Result<()> {
        let mut server_handle = self.grpc_server_handle.write().await;
        
        if let Some(handle) = server_handle.take() {
            handle.abort();
        }
        
        Ok(())
    }
}

// Clone implementation for UdcnTransport
impl Clone for UdcnTransport {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: self.state.clone(),
            metrics: self.metrics.clone(),
            start_time: self.start_time.clone(),
            prefix_table: self.prefix_table.clone(),
            forwarding_table: self.forwarding_table.clone(),
            next_registration_id: self.next_registration_id.clone(),
            grpc_server_handle: self.grpc_server_handle.clone(),
            ml_prediction: self.ml_prediction.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg_attr(feature = "tokio-test", tokio::test)]
    async fn test_transport_initialization() {
        let config = Config {
            bind_address: "127.0.0.1".to_string(),
            port: 6363,
            mtu: 1400,
            cache_capacity: 1000,
            idle_timeout: 30,
            enable_metrics: false,
            metrics_port: 0,
            max_packet_size: 65535,
            log_level: "info".to_string(),
            retries: 3,
            retry_interval: 1000,
            xdp_config: None,
            enable_ml_mtu_prediction: false,
            ml_prediction_interval: 30,
            ml_model_type: "rule-based".to_string(),
            min_mtu: 576,
            max_mtu: 9000,
        };
        
        let transport = UdcnTransport::new(config).await;
        assert!(transport.is_ok());
    }
}

