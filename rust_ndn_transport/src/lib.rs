//
// μDCN Rust Transport Layer
//
// This library implements a high-performance NDN transport layer
// using Rust and QUIC for maximum performance and safety.
//

// Module organization
pub mod ndn;           // NDN protocol implementation
pub mod quic;          // QUIC transport integration
pub mod cache;         // Content store implementation
pub mod metrics;       // Prometheus metrics collection
pub mod name;          // NDN name handling and manipulation
pub mod security;      // Cryptographic operations and verification
pub mod fragmentation; // Packet fragmentation and reassembly
pub mod interface;     // Network interface management
pub mod error;         // Error types
pub mod grpc;          // gRPC service implementation

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use error::Error;
use name::Name;
use ndn::{Interest, Data};
use metrics::{MetricsCollector, MetricValue};

// Define Result type for the crate
pub type Result<T> = std::result::Result<T, Error>;

// Configuration struct
#[derive(Clone, Debug)]
pub struct Config {
    pub mtu: usize,
    pub cache_capacity: usize,
    pub idle_timeout: u64,
    pub bind_address: String,
    pub enable_metrics: bool,
    pub metrics_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mtu: 1400,
            cache_capacity: 10000,
            idle_timeout: 30,
            bind_address: "127.0.0.1:6363".to_string(),
            enable_metrics: true,
            metrics_port: 9090,
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
type PrefixHandler = Box<dyn Fn(Interest) -> Result<Data, Error> + Send + Sync>;
type PrefixTable = Arc<DashMap<Name, (u64, PrefixHandler)>>;
type ForwardingTable = Arc<DashMap<Name, (u64, usize)>>;

// Main transport struct
pub struct UdcnTransport {
    config: Arc<RwLock<Config>>,
    state: Arc<RwLock<TransportState>>,
    metrics: Arc<MetricsCollector>,
    start_time: Arc<RwLock<Instant>>,
    prefix_table: PrefixTable,
    forwarding_table: ForwardingTable,
    next_registration_id: Arc<RwLock<u64>>,
    grpc_server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl UdcnTransport {
    // Create a new transport instance
    pub async fn new(config: Config) -> Result<Self, Error> {
        let metrics = Arc::new(MetricsCollector::new(
            config.enable_metrics,
            config.metrics_port,
        ));
        
        let transport = Self {
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(TransportState::Stopped)),
            metrics,
            start_time: Arc::new(RwLock::new(Instant::now())),
            prefix_table: Arc::new(DashMap::new()),
            forwarding_table: Arc::new(DashMap::new()),
            next_registration_id: Arc::new(RwLock::new(1)),
            grpc_server_handle: Arc::new(RwLock::new(None)),
        };
        
        Ok(transport)
    }
    
    // Start the transport
    pub async fn start(&self) -> Result<(), Error> {
        let mut state = self.state.write().await;
        if *state == TransportState::Running {
            return Ok(());
        }
        
        *state = TransportState::Starting;
        
        // Reset start time
        let mut start_time = self.start_time.write().await;
        *start_time = Instant::now();
        
        // Initialize QUIC engine and other components here...
        
        // Start gRPC server
        self.start_grpc_server().await?;
        
        *state = TransportState::Running;
        Ok(())
    }
    
    // Stop the transport
    pub async fn stop(&self) -> Result<(), Error> {
        let mut state = self.state.write().await;
        if *state == TransportState::Stopped {
            return Ok(());
        }
        
        *state = TransportState::Stopping;
        
        // Stop gRPC server
        self.stop_grpc_server().await?;
        
        // Shutdown QUIC engine and other components here...
        
        *state = TransportState::Stopped;
        Ok(())
    }
    
    // Pause the transport
    pub async fn pause(&self) -> Result<(), Error> {
        let mut state = self.state.write().await;
        if *state != TransportState::Running {
            return Err(Error::InvalidState("Transport is not running".to_string()));
        }
        
        // Implement pause logic here...
        
        *state = TransportState::Paused;
        Ok(())
    }
    
    // Resume the transport
    pub async fn resume(&self) -> Result<(), Error> {
        let mut state = self.state.write().await;
        if *state != TransportState::Paused {
            return Err(Error::InvalidState("Transport is not paused".to_string()));
        }
        
        // Implement resume logic here...
        
        *state = TransportState::Running;
        Ok(())
    }
    
    // Graceful shutdown
    pub async fn shutdown(&self) -> Result<(), Error> {
        // Implement clean shutdown logic here...
        self.stop().await
    }
    
    // Register a prefix for handling interests
    pub async fn register_prefix(
        &self,
        prefix: Name,
        handler: PrefixHandler,
    ) -> Result<u64, Error> {
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
    ) -> Result<u64, Error> {
        let mut next_id = self.next_registration_id.write().await;
        let registration_id = *next_id;
        *next_id += 1;
        
        self.forwarding_table.insert(prefix, (registration_id, priority));
        
        Ok(registration_id)
    }
    
    // Unregister a prefix
    pub async fn unregister_prefix(&self, registration_id: u64) -> Result<(), Error> {
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
    pub async fn update_mtu(&self, mtu: usize) -> Result<(), Error> {
        if mtu < 576 || mtu > 9000 {
            return Err(Error::InvalidArgument(
                format!("Invalid MTU: {}. Must be between 576 and 9000", mtu)
            ));
        }
        
        let mut config = self.config.write().await;
        let old_mtu = config.mtu;
        config.mtu = mtu;
        
        // Update QUIC endpoints with new MTU
        // ...
        
        Ok(())
    }
    
    // Get current MTU
    pub fn mtu(&self) -> usize {
        let config = self.config.try_read().unwrap_or(Config::default().into());
        config.mtu
    }
    
    // Send an interest and get data
    pub async fn send_interest(&self, interest: Interest) -> Result<Data, Error> {
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
        self.metrics.get_metrics()
    }
    
    // Get network interfaces
    pub async fn get_network_interfaces(&self, include_stats: bool) -> Result<Vec<String>, Error> {
        // Placeholder implementation instead of interface::get_network_interfaces
        // Replace with actual implementation when available
        Ok(vec!["eth0".to_string(), "lo".to_string()])
    }
    
    // Get current state
    pub async fn state(&self) -> TransportState {
        self.state.read().await.clone()
    }
    
    // Configure the transport
    pub async fn configure(&self, config: Config) -> Result<(), Error> {
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
        
        let cache_hits = self.metrics.get_counter("cache_hits").unwrap_or(0);
        let cache_misses = self.metrics.get_counter("cache_misses").unwrap_or(0);
        let cache_hit_ratio = if cache_hits + cache_misses > 0 {
            cache_hits as f64 / (cache_hits + cache_misses) as f64
        } else {
            0.0
        };
        
        TransportStatistics {
            uptime_seconds: uptime.as_secs(),
            interests_processed: self.metrics.get_counter("interests_processed").unwrap_or(0),
            data_packets_sent: self.metrics.get_counter("data_packets_sent").unwrap_or(0),
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
        let metrics = self.metrics.get_metrics();
        for (key, value) in metrics {
            stats.insert(format!("metric_{}", key), format!("{:?}", value));
        }
        
        stats
    }
    
    // Start gRPC server
    async fn start_grpc_server(&self) -> Result<(), Error> {
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
    
    // Stop gRPC server
    async fn stop_grpc_server(&self) -> Result<(), Error> {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_transport_initialization() {
        let config = Config {
            mtu: 1400,
            cache_capacity: 1000,
            idle_timeout: 30,
            bind_address: "127.0.0.1:6363".to_string(),
            enable_metrics: false,
            metrics_port: 0,
        };
        
        let transport = UdcnTransport::new(config).await;
        assert!(transport.is_ok());
    }
}
