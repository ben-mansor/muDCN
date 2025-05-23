// 
// μDCN ML-based MTU + XDP Integration Example
//
// This example demonstrates the integration between the ML-based MTU prediction
// system and the XDP acceleration layer for optimal NDN performance.
//

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::path::Path;

use clap::{App, Arg};
use tokio::sync::RwLock;
use tokio::time::sleep;
use log::{debug, error, info, warn};

use udcn_transport::{
    Config, UdcnTransport, XdpConfig, Error, Result,
    Name, Interest, Data, ml, MetricValue
};

// Network scenario definitions for testing
#[derive(Debug, Clone)]
struct NetworkScenario {
    name: String,
    description: String,
    rtt_ms: u64,
    packet_loss: f64,
    throughput_mbps: u64,
    network_type: u8,
}

impl NetworkScenario {
    fn new(name: &str, desc: &str, rtt: u64, loss: f64, throughput: u64, net_type: u8) -> Self {
        Self {
            name: name.to_string(),
            description: desc.to_string(),
            rtt_ms: rtt,
            packet_loss: loss,
            throughput_mbps: throughput,
            network_type: net_type,
        }
    }
}

// Create a set of diverse network scenarios for testing
fn create_scenarios() -> Vec<NetworkScenario> {
    vec![
        NetworkScenario::new(
            "ethernet", 
            "High-performance LAN connection",
            10, 0.0001, 1000, 1 // Ethernet
        ),
        NetworkScenario::new(
            "wifi", 
            "Standard home WiFi connection",
            30, 0.01, 50, 2 // WiFi
        ),
        NetworkScenario::new(
            "4g", 
            "Mobile 4G connection with some packet loss",
            80, 0.03, 12, 3 // Cellular
        ),
        NetworkScenario::new(
            "congested", 
            "Congested network with high latency",
            200, 0.05, 10, 1 // Ethernet but congested
        ),
        NetworkScenario::new(
            "satellite", 
            "High-latency satellite connection",
            600, 0.02, 20, 4 // Satellite
        ),
    ]
}

// Packet generator for testing
struct PacketGenerator {
    max_interest_size: usize,
    max_data_size: usize,
    name_prefix: String,
    packet_count: usize,
}

impl PacketGenerator {
    fn new(prefix: &str, max_interest_size: usize, max_data_size: usize) -> Self {
        Self {
            max_interest_size,
            max_data_size,
            name_prefix: prefix.to_string(),
            packet_count: 0,
        }
    }
    
    fn generate_interest(&mut self) -> Interest {
        let name = format!("{}/object{}", self.name_prefix, self.packet_count);
        self.packet_count += 1;
        
        let mut interest = Interest::new(Name::from_str(&name).unwrap());
        
        // Add random parameters to adjust size if needed
        if self.max_interest_size > 50 {
            let payload_size = fastrand::usize(10..self.max_interest_size - 40);
            let payload = vec![b'A'; payload_size];
            
            interest.set_application_parameters(&payload);
        }
        
        interest
    }
    
    fn generate_data(&self, interest: &Interest) -> Data {
        let payload_size = fastrand::usize(100..self.max_data_size);
        let payload = vec![b'D'; payload_size];
        
        Data::new(interest.name().clone(), &payload)
    }
}

// Performance metrics for testing
#[derive(Debug, Default)]
struct PerformanceMetrics {
    interest_count: usize,
    data_count: usize,
    cache_hits: usize,
    cache_misses: usize,
    error_count: usize,
    total_bytes_sent: usize,
    total_bytes_received: usize,
    avg_rtt_ms: f64,
    min_rtt_ms: f64,
    max_rtt_ms: f64,
    latency_p50_ms: f64,
    latency_p95_ms: f64,
    latency_p99_ms: f64,
    start_time: Option<Instant>,
    end_time: Option<Instant>,
    mtu_changes: Vec<(Instant, usize)>,
    rtts: Vec<f64>,
}

impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            min_rtt_ms: f64::MAX,
            max_rtt_ms: 0.0,
            ..Default::default()
        }
    }
    
    fn start_test(&mut self) {
        self.start_time = Some(Instant::now());
    }
    
    fn end_test(&mut self) {
        self.end_time = Some(Instant::now());
        
        // Calculate percentiles
        if !self.rtts.is_empty() {
            self.rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let len = self.rtts.len();
            
            self.latency_p50_ms = self.rtts[len / 2];
            self.latency_p95_ms = self.rtts[(len as f64 * 0.95) as usize];
            self.latency_p99_ms = self.rtts[(len as f64 * 0.99) as usize];
        }
    }
    
    fn record_interest(&mut self, size: usize) {
        self.interest_count += 1;
        self.total_bytes_sent += size;
    }
    
    fn record_data(&mut self, size: usize, rtt_ms: f64) {
        self.data_count += 1;
        self.total_bytes_received += size;
        
        self.rtts.push(rtt_ms);
        self.min_rtt_ms = self.min_rtt_ms.min(rtt_ms);
        self.max_rtt_ms = self.max_rtt_ms.max(rtt_ms);
        
        // Update average
        self.avg_rtt_ms = ((self.avg_rtt_ms * (self.data_count - 1) as f64) + rtt_ms) / self.data_count as f64;
    }
    
    fn record_error(&mut self) {
        self.error_count += 1;
    }
    
    fn record_mtu_change(&mut self, mtu: usize) {
        self.mtu_changes.push((Instant::now(), mtu));
    }
    
    fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }
    
    fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }
    
    fn get_duration_secs(&self) -> f64 {
        match (self.start_time, self.end_time) {
            (Some(start), Some(end)) => end.duration_since(start).as_secs_f64(),
            (Some(start), None) => Instant::now().duration_since(start).as_secs_f64(),
            _ => 0.0,
        }
    }
    
    fn get_throughput_mbps(&self) -> f64 {
        let duration_secs = self.get_duration_secs();
        if duration_secs > 0.0 {
            let total_bytes = self.total_bytes_sent + self.total_bytes_received;
            (total_bytes as f64 * 8.0) / (duration_secs * 1_000_000.0)
        } else {
            0.0
        }
    }
    
    fn print_summary(&self) {
        println!("=== Performance Test Summary ===");
        println!("Duration: {:.2} seconds", self.get_duration_secs());
        println!("Interests sent: {}", self.interest_count);
        println!("Data packets received: {}", self.data_count);
        println!("Errors: {}", self.error_count);
        println!("Success rate: {:.2}%", 
                if self.interest_count > 0 { 
                    (self.data_count as f64 / self.interest_count as f64) * 100.0 
                } else { 
                    0.0 
                });
        
        println!("\n=== Latency Metrics ===");
        println!("Average RTT: {:.2} ms", self.avg_rtt_ms);
        println!("Min RTT: {:.2} ms", self.min_rtt_ms);
        println!("Max RTT: {:.2} ms", self.max_rtt_ms);
        println!("50th percentile: {:.2} ms", self.latency_p50_ms);
        println!("95th percentile: {:.2} ms", self.latency_p95_ms);
        println!("99th percentile: {:.2} ms", self.latency_p99_ms);
        
        println!("\n=== Throughput Metrics ===");
        println!("Total data sent: {:.2} MB", self.total_bytes_sent as f64 / 1_000_000.0);
        println!("Total data received: {:.2} MB", self.total_bytes_received as f64 / 1_000_000.0);
        println!("Throughput: {:.2} Mbps", self.get_throughput_mbps());
        
        println!("\n=== Cache Metrics ===");
        println!("Cache hits: {}", self.cache_hits);
        println!("Cache misses: {}", self.cache_misses);
        println!("Cache hit ratio: {:.2}%", 
                if self.cache_hits + self.cache_misses > 0 { 
                    (self.cache_hits as f64 / (self.cache_hits + self.cache_misses) as f64) * 100.0 
                } else { 
                    0.0 
                });
        
        println!("\n=== MTU Changes ===");
        if self.mtu_changes.is_empty() {
            println!("No MTU changes recorded");
        } else {
            let start = self.start_time.unwrap();
            for (time, mtu) in &self.mtu_changes {
                println!("{:.2}s: MTU changed to {}", time.duration_since(start).as_secs_f64(), mtu);
            }
        }
        
        println!("===============================");
    }
}

async fn run_benchmark(config: Config) -> Result<()> {
    // Initialize transport
    let mut transport = UdcnTransport::new(config).await?;
    
    // Start the transport
    transport.start().await?;
    info!("Transport started");
    
    // Create performance metrics tracker
    let metrics = Arc::new(RwLock::new(PerformanceMetrics::new()));
    
    // Create packet generator
    let mut generator = PacketGenerator::new(
        "/udcn/benchmark", 
        1000,  // Max interest size
        8000   // Max data size
    );
    
    // Create network scenarios
    let scenarios = create_scenarios();
    
    info!("Running benchmark with {} network scenarios", scenarios.len());
    
    // Start metrics collection
    metrics.write().await.start_test();
    
    // Record initial MTU
    let initial_mtu = transport.mtu().await?;
    metrics.write().await.record_mtu_change(initial_mtu);
    
    // For each scenario
    for scenario in scenarios {
        info!("=== Testing scenario: {} - {} ===", scenario.name, scenario.description);
        info!("Network conditions: RTT={}ms, Loss={}%, Throughput={}Mbps", 
             scenario.rtt_ms, scenario.packet_loss * 100.0, scenario.throughput_mbps);
        
        // Update ML features for this scenario
        let mut ml_features = ml::MtuFeatures::default();
        ml_features.avg_rtt_ms = scenario.rtt_ms as f64;
        ml_features.packet_loss_rate = scenario.packet_loss;
        ml_features.avg_throughput_bps = scenario.throughput_mbps as f64 * 1_000_000.0;
        ml_features.network_type = scenario.network_type;
        
        // TODO: Implement actual network condition emulation
        
        // Send interests for this scenario (100 per scenario)
        for _ in 0..100 {
            let interest = generator.generate_interest();
            let interest_size = interest.encoded_size();
            
            // Record the interest
            metrics.write().await.record_interest(interest_size);
            
            // Measure start time
            let start_time = Instant::now();
            
            match transport.send_interest(&interest).await {
                Ok(data) => {
                    let rtt_ms = start_time.elapsed().as_millis() as f64;
                    let data_size = data.encoded_size();
                    
                    // Record the data
                    metrics.write().await.record_data(data_size, rtt_ms);
                },
                Err(e) => {
                    warn!("Error sending interest: {}", e);
                    metrics.write().await.record_error();
                }
            }
            
            // Small delay between packets
            sleep(Duration::from_millis(10)).await;
        }
        
        // Check current MTU
        let current_mtu = transport.mtu().await?;
        info!("Current MTU for scenario {}: {}", scenario.name, current_mtu);
        
        // Record if MTU changed
        if current_mtu != initial_mtu {
            metrics.write().await.record_mtu_change(current_mtu);
        }
        
        // Collect transport metrics
        let transport_metrics = transport.get_metrics().await?;
        
        // Update cache hit/miss from metrics
        if let Some(MetricValue::Counter(hits)) = transport_metrics.get("cache.hits") {
            metrics.write().await.cache_hits = *hits as usize;
        }
        
        if let Some(MetricValue::Counter(misses)) = transport_metrics.get("cache.misses") {
            metrics.write().await.cache_misses = *misses as usize;
        }
        
        // Sleep between scenarios
        sleep(Duration::from_secs(2)).await;
    }
    
    // End metrics collection
    metrics.write().await.end_test();
    
    // Print summary
    let final_metrics = metrics.read().await.clone();
    final_metrics.print_summary();
    
    // Stop the transport
    transport.stop().await?;
    info!("Transport stopped, benchmark complete");
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    // Parse command-line arguments
    let matches = App::new("μDCN ML-XDP Integration Benchmark")
        .version("1.0")
        .author("μDCN Team")
        .about("Benchmark for μDCN ML-based MTU prediction with XDP acceleration")
        .arg(Arg::with_name("interface")
            .short("i")
            .long("interface")
            .value_name("INTERFACE")
            .help("Network interface to use (for XDP)")
            .default_value("eth0")
            .takes_value(true))
        .arg(Arg::with_name("xdp-mode")
            .long("xdp-mode")
            .value_name("MODE")
            .help("XDP mode: skb, drv, hw, or off")
            .default_value("skb")
            .takes_value(true))
        .arg(Arg::with_name("ml-model")
            .long("ml-model")
            .value_name("MODEL")
            .help("ML model to use: rule-based, linear, or ensemble")
            .default_value("ensemble")
            .takes_value(true))
        .arg(Arg::with_name("no-ml")
            .long("no-ml")
            .help("Disable ML-based MTU prediction"))
        .arg(Arg::with_name("no-xdp")
            .long("no-xdp")
            .help("Disable XDP acceleration"))
        .arg(Arg::with_name("xdp-program")
            .long("xdp-program")
            .value_name("PATH")
            .help("Path to XDP program object file")
            .default_value("../ebpf_xdp/ndn_parser.o")
            .takes_value(true))
        .get_matches();
    
    // Create configuration
    let mut config = Config::default();
    
    // Basic transport configuration
    config.bind_address = "127.0.0.1".to_string();
    config.port = 6363;
    config.mtu = 1400; // Starting MTU
    config.cache_capacity = 10000;
    
    // Set up ML configuration
    config.enable_ml_mtu_prediction = !matches.is_present("no-ml");
    config.ml_prediction_interval = 5;
    config.ml_model_type = matches.value_of("ml-model").unwrap().to_string();
    config.min_mtu = 576;
    config.max_mtu = 9000;
    
    // Set up XDP configuration if enabled
    if !matches.is_present("no-xdp") {
        let xdp_obj_path = matches.value_of("xdp-program").unwrap();
        let interface = matches.value_of("interface").unwrap();
        let xdp_mode = matches.value_of("xdp-mode").unwrap();
        
        // First check if the XDP program exists
        if !Path::new(xdp_obj_path).exists() {
            return Err(Error::XdpError(format!("XDP program not found: {}", xdp_obj_path)));
        }
        
        let xdp_config = XdpConfig {
            xdp_obj_path: xdp_obj_path.to_string(),
            interface: interface.to_string(),
            xdp_mode: xdp_mode.to_string(),
            cs_size: 10000, // 10k entries
            cs_ttl: 60,     // 60 second TTL
            map_pin_path: "/sys/fs/bpf/ndn".to_string(),
            enable_metrics: true,
            metrics_interval: 5,
        };
        
        config.xdp_config = Some(xdp_config);
    }
    
    // Run the benchmark
    info!("Starting benchmark with ML={}, XDP={}", 
          config.enable_ml_mtu_prediction, 
          config.xdp_config.is_some());
    
    run_benchmark(config).await?;
    
    Ok(())
}
