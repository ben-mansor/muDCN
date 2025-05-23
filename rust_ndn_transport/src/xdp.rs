//
// μDCN XDP Integration
//
// This module implements integration between the Rust transport layer
// and the eBPF/XDP data plane components.
//

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::collections::HashMap;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{Duration, interval};

use crate::name::Name;
use crate::ndn::{Interest, Data};
use crate::metrics::MetricValue;
use crate::{Config, Error, Result};

/// Configuration for XDP integration
#[derive(Debug, Clone)]
pub struct XdpConfig {
    /// Path to the XDP object file
    pub xdp_obj_path: String,
    
    /// Network interface to attach XDP program to
    pub interface: String,
    
    /// XDP mode (SKB, DRV, HW, or AUTO)
    pub xdp_mode: String,
    
    /// Content store size
    pub cs_size: usize,
    
    /// Content store TTL in seconds
    pub cs_ttl: u32,
    
    /// Path to the eBPF map pinning directory
    pub map_pin_path: String,
    
    /// Whether to collect XDP metrics
    pub enable_metrics: bool,
    
    /// Metrics collection interval in seconds
    pub metrics_interval: u64,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            xdp_obj_path: "./ndn_parser.o".to_string(),
            interface: "eth0".to_string(),
            xdp_mode: "skb".to_string(),
            cs_size: 10000,
            cs_ttl: 60,
            map_pin_path: "/sys/fs/bpf/ndn".to_string(),
            enable_metrics: true,
            metrics_interval: 10,
        }
    }
}

/// Status of the XDP program
#[derive(Debug, Clone, PartialEq)]
pub enum XdpStatus {
    /// XDP program is not loaded
    NotLoaded,
    
    /// XDP program is loaded and running
    Running,
    
    /// XDP program failed to load
    Failed(String),
}

/// XDP program metrics
#[derive(Debug, Clone, Default)]
pub struct XdpMetrics {
    /// Number of packets processed
    pub packets_processed: u64,
    
    /// Number of interest packets
    pub interests: u64,
    
    /// Number of data packets
    pub data_packets: u64,
    
    /// Number of cache hits
    pub cache_hits: u64,
    
    /// Number of cache misses
    pub cache_misses: u64,
    
    /// Current cache size
    pub cache_size: u64,
    
    /// Cache evictions
    pub cache_evictions: u64,
    
    /// Processing errors
    pub errors: u64,
    
    /// Average processing time in nanoseconds
    pub avg_processing_time_ns: u64,
}

/// Manager for XDP integration
pub struct XdpManager {
    /// Configuration
    config: XdpConfig,
    
    /// Current status
    status: Arc<RwLock<XdpStatus>>,
    
    /// Metrics
    metrics: Arc<RwLock<XdpMetrics>>,
    
    /// Metrics collection task
    metrics_task: RwLock<Option<JoinHandle<()>>>,
    
    /// Registered prefixes
    prefixes: Arc<RwLock<HashMap<Name, Arc<dyn Fn(Interest) -> Result<Data> + Send + Sync>>>>,
}

impl XdpManager {
    /// Create a new XDP manager
    pub fn new(config: XdpConfig) -> Self {
        Self {
            config,
            status: Arc::new(RwLock::new(XdpStatus::NotLoaded)),
            metrics: Arc::new(RwLock::new(XdpMetrics::default())),
            metrics_task: RwLock::new(None),
            prefixes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Load and attach the XDP program
    pub async fn load(&self) -> Result<()> {
        // Check if XDP object file exists
        let obj_path = Path::new(&self.config.xdp_obj_path);
        if !obj_path.exists() {
            let err_msg = format!("XDP object file not found: {}", self.config.xdp_obj_path);
            *self.status.write().await = XdpStatus::Failed(err_msg.clone());
            return Err(Error::XdpError(err_msg));
        }
        
        // Build command to load XDP program
        let mut cmd = Command::new("ip");
        cmd.args([
            "link", "set", "dev", &self.config.interface,
            "xdp", &format!("obj {}", self.config.xdp_obj_path),
            &format!("mode {}", self.config.xdp_mode),
        ]);
        
        // Execute command
        let output = cmd.output().map_err(|e| {
            let err_msg = format!("Failed to execute XDP load command: {}", e);
            Error::XdpError(err_msg)
        })?;
        
        // Check output
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let err_msg = format!("Failed to load XDP program: {}", stderr);
            *self.status.write().await = XdpStatus::Failed(err_msg.clone());
            return Err(Error::XdpError(err_msg));
        }
        
        // Configure content store
        self.configure_content_store().await?;
        
        // Start metrics collection if enabled
        if self.config.enable_metrics {
            self.start_metrics_collection().await;
        }
        
        // Update status
        *self.status.write().await = XdpStatus::Running;
        
        log::info!("XDP program loaded successfully on {}", self.config.interface);
        Ok(())
    }
    
    /// Configure the content store
    async fn configure_content_store(&self) -> Result<()> {
        // Ensure pin directory exists
        let pin_dir = Path::new(&self.config.map_pin_path);
        if !pin_dir.exists() {
            std::fs::create_dir_all(pin_dir).map_err(|e| {
                let err_msg = format!("Failed to create BPF map pin directory: {}", e);
                Error::XdpError(err_msg)
            })?;
        }
        
        // Set content store configuration using bpftool
        let output = Command::new("bpftool")
            .args([
                "map", "update", "pinned", 
                &format!("{}/cs_config", self.config.map_pin_path),
                "key", "0", "0", "0", "0",
                "value", 
                &format!("{}", self.config.cs_size),
                &format!("{}", self.config.cs_ttl),
                "0", "0"
            ])
            .output()
            .map_err(|e| {
                let err_msg = format!("Failed to configure content store: {}", e);
                Error::XdpError(err_msg)
            })?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Warning: could not configure content store: {}", stderr);
            // Continue even if this fails - not all XDP programs may have cs_config map
        }
        
        Ok(())
    }
    
    /// Start metrics collection task
    async fn start_metrics_collection(&self) {
        // Clone the config and get Arc clones of the metrics
        let config = self.config.clone();
        let metrics = Arc::clone(&self.metrics);
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.metrics_interval));
            
            loop {
                interval.tick().await;
                
                // Read metrics from eBPF maps
                match Self::read_xdp_metrics(&config.map_pin_path).await {
                    Ok(new_metrics) => {
                        // Use the Arc-wrapped metrics field
                        *metrics.write().await = new_metrics;
                    },
                    Err(e) => {
                        log::error!("Failed to read XDP metrics: {}", e);
                    }
                }
            }
        });
        
        *self.metrics_task.write().await = Some(task);
    }
    
    /// Read metrics from eBPF maps
    async fn read_xdp_metrics(map_pin_path: &str) -> Result<XdpMetrics> {
        let mut metrics = XdpMetrics::default();
        
        // Read metrics using bpftool
        let output = Command::new("bpftool")
            .args([
                "map", "dump", "pinned", 
                &format!("{}/metrics", map_pin_path),
            ])
            .output()
            .map_err(|e| {
                let err_msg = format!("Failed to read XDP metrics: {}", e);
                Error::XdpError(err_msg)
            })?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::XdpError(format!("Failed to dump metrics map: {}", stderr)));
        }
        
        // Parse output
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("key:") && line.contains("value:") {
                let parts: Vec<&str> = line.split("value:").collect();
                if parts.len() == 2 {
                    let value_str = parts[1].trim();
                    
                    // Try to extract key and metric type
                    if let Some(key_part) = parts[0].split("key:").nth(1) {
                        let key = key_part.trim();
                        
                        // Parse the value as a u64
                        if let Ok(value) = value_str.parse::<u64>() {
                            // Match on metric key and update appropriate field
                            match key {
                                "0" => metrics.packets_processed = value,
                                "1" => metrics.interests = value,
                                "2" => metrics.data_packets = value,
                                "3" => metrics.cache_hits = value,
                                "4" => metrics.cache_misses = value,
                                "5" => metrics.cache_size = value,
                                "6" => metrics.cache_evictions = value,
                                "7" => metrics.errors = value,
                                "8" => metrics.avg_processing_time_ns = value,
                                _ => {} // Unknown metric
                            }
                        }
                    }
                }
            }
        }
        
        Ok(metrics)
    }
    
    /// Unload the XDP program
    pub async fn unload(&self) -> Result<()> {
        // Stop metrics collection
        if let Some(task) = self.metrics_task.write().await.take() {
            task.abort();
        }
        
        // Build command to unload XDP program
        let output = Command::new("ip")
            .args([
                "link", "set", "dev", &self.config.interface, "xdp", "off"
            ])
            .output()
            .map_err(|e| {
                let err_msg = format!("Failed to execute XDP unload command: {}", e);
                Error::XdpError(err_msg)
            })?;
        
        // Check output
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let err_msg = format!("Failed to unload XDP program: {}", stderr);
            *self.status.write().await = XdpStatus::Failed(err_msg.clone());
            return Err(Error::XdpError(err_msg));
        }
        
        // Update status
        *self.status.write().await = XdpStatus::NotLoaded;
        
        log::info!("XDP program unloaded from {}", self.config.interface);
        Ok(())
    }
    
    /// Get current XDP status
    pub async fn status(&self) -> XdpStatus {
        self.status.read().await.clone()
    }
    
    /// Get current XDP metrics
    pub async fn metrics(&self) -> XdpMetrics {
        self.metrics.read().await.clone()
    }
    
    /// Get metrics as a HashMap for integration with the rest of the transport layer
    pub async fn get_metrics(&self) -> HashMap<String, MetricValue> {
        let metrics = self.metrics.read().await.clone();
        let mut result = HashMap::new();
        
        result.insert("xdp.packets_processed".to_string(), 
                      MetricValue::Counter(metrics.packets_processed));
        result.insert("xdp.interests".to_string(), 
                      MetricValue::Counter(metrics.interests));
        result.insert("xdp.data_packets".to_string(), 
                      MetricValue::Counter(metrics.data_packets));
        result.insert("xdp.cache_hits".to_string(), 
                      MetricValue::Counter(metrics.cache_hits));
        result.insert("xdp.cache_misses".to_string(), 
                      MetricValue::Counter(metrics.cache_misses));
        result.insert("xdp.cache_size".to_string(), 
                      MetricValue::Gauge(metrics.cache_size as f64));
        result.insert("xdp.cache_evictions".to_string(), 
                      MetricValue::Counter(metrics.cache_evictions));
        result.insert("xdp.errors".to_string(), 
                      MetricValue::Counter(metrics.errors));
        result.insert("xdp.avg_processing_time_ns".to_string(), 
                      MetricValue::Gauge(metrics.avg_processing_time_ns as f64));
        
        result
    }
    
    /// Register a prefix handler
    pub async fn register_prefix<F>(&self, prefix: Name, handler: F) -> Result<()>
    where
        F: Fn(Interest) -> Result<Data> + Send + Sync + 'static
    {
        let mut prefixes = self.prefixes.write().await;
        prefixes.insert(prefix.clone(), Arc::new(handler));
        
        log::info!("Registered prefix {} with XDP manager", prefix);
        Ok(())
    }
    
    /// Add a Data packet to the content store
    pub async fn add_to_content_store(&self, data: &Data) -> Result<()> {
        let name = data.name().to_string();
        let data_bytes = data.to_bytes();
        
        // Use bpftool to update the content store
        let output = Command::new("bpftool")
            .args([
                "map", "update", "pinned", 
                &format!("{}/content_store", self.config.map_pin_path),
                "key", &format!("string {}", name),
                "value", "hex", &hex::encode(data_bytes)
            ])
            .output()
            .map_err(|e| {
                let err_msg = format!("Failed to add to content store: {}", e);
                Error::XdpError(err_msg)
            })?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::XdpError(format!("Failed to update content store: {}", stderr)));
        }
        
        Ok(())
    }
    
    /// Clear the content store
    pub async fn clear_content_store(&self) -> Result<()> {
        let output = Command::new("bpftool")
            .args([
                "map", "flush", "pinned", 
                &format!("{}/content_store", self.config.map_pin_path)
            ])
            .output()
            .map_err(|e| {
                let err_msg = format!("Failed to clear content store: {}", e);
                Error::XdpError(err_msg)
            })?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::XdpError(format!("Failed to flush content store: {}", stderr)));
        }
        
        Ok(())
    }
}
