//
// μDCN Metrics Collection
//
// This module implements Prometheus metrics collection for the μDCN transport layer,
// providing real-time monitoring of performance and operational statistics.
//

use lazy_static::lazy_static;
use prometheus::{
    register_counter, register_gauge, register_histogram, register_int_counter,
    Counter, Gauge, Histogram, HistogramOpts, IntCounter,
};
use std::net::SocketAddr;
use std::thread;
use std::collections::HashMap;
use warp::Filter;
use tracing::{info, error};

/// Metric value types for the metrics collector
#[derive(Debug, Clone)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
}

/// Metrics collector for gathering and reporting metrics
pub struct MetricsCollector {
    enabled: bool,
    port: u16,
    metrics: HashMap<String, MetricValue>,
}

impl MetricsCollector {
    pub fn new(enabled: bool, port: u16) -> Self {
        let metrics = HashMap::new();
        if enabled {
            init_metrics(port);
        }
        Self {
            enabled,
            port,
            metrics,
        }
    }
    
    pub fn increment_counter(&self, name: &str, value: u64) {
        // This is a simple implementation - in practice, this would
        // properly integrate with the prometheus metrics
    }
    
    pub fn get_counter(&self, name: &str) -> u64 {
        match self.metrics.get(name) {
            Some(MetricValue::Counter(v)) => *v,
            _ => 0,
        }
    }
    
    pub fn get_metrics(&self) -> HashMap<String, MetricValue> {
        self.metrics.clone()
    }
}

// Counter metrics
lazy_static! {
    // Interest metrics
    static ref INTERESTS_SENT: IntCounter = register_int_counter!(
        "udcn_interests_sent_total", 
        "Total number of NDN Interest packets sent"
    ).unwrap();

    static ref INTERESTS_RECEIVED: IntCounter = register_int_counter!(
        "udcn_interests_received_total", 
        "Total number of NDN Interest packets received"
    ).unwrap();

    static ref INTERESTS_SATISFIED: IntCounter = register_int_counter!(
        "udcn_interests_satisfied_total", 
        "Total number of NDN Interest packets that were satisfied"
    ).unwrap();

    static ref INTERESTS_TIMED_OUT: IntCounter = register_int_counter!(
        "udcn_interests_timed_out_total", 
        "Total number of NDN Interest packets that timed out"
    ).unwrap();

    static ref INTEREST_RETRANSMISSIONS: IntCounter = register_int_counter!(
        "udcn_interest_retransmissions_total", 
        "Total number of NDN Interest retransmissions"
    ).unwrap();

    // Data metrics
    static ref DATA_SENT: IntCounter = register_int_counter!(
        "udcn_data_sent_total", 
        "Total number of NDN Data packets sent"
    ).unwrap();

    static ref DATA_RECEIVED: IntCounter = register_int_counter!(
        "udcn_data_received_total", 
        "Total number of NDN Data packets received"
    ).unwrap();

    static ref DATA_BYTES_SENT: IntCounter = register_int_counter!(
        "udcn_data_bytes_sent_total", 
        "Total bytes of NDN Data sent"
    ).unwrap();

    static ref DATA_BYTES_RECEIVED: IntCounter = register_int_counter!(
        "udcn_data_bytes_received_total", 
        "Total bytes of NDN Data received"
    ).unwrap();

    // NACK metrics
    static ref NACKS_SENT: IntCounter = register_int_counter!(
        "udcn_nacks_sent_total", 
        "Total number of NDN NACK packets sent"
    ).unwrap();

    static ref NACKS_RECEIVED: IntCounter = register_int_counter!(
        "udcn_nacks_received_total", 
        "Total number of NDN NACK packets received"
    ).unwrap();

    // Content store metrics
    static ref CS_HITS: IntCounter = register_int_counter!(
        "udcn_cs_hits_total", 
        "Total number of content store hits"
    ).unwrap();

    static ref CS_MISSES: IntCounter = register_int_counter!(
        "udcn_cs_misses_total", 
        "Total number of content store misses"
    ).unwrap();

    // QUIC metrics
    static ref QUIC_STREAMS_OPENED: IntCounter = register_int_counter!(
        "udcn_quic_streams_opened_total", 
        "Total number of QUIC streams opened"
    ).unwrap();

    static ref QUIC_CONNECTIONS_OPENED: IntCounter = register_int_counter!(
        "udcn_quic_connections_opened_total", 
        "Total number of QUIC connections opened"
    ).unwrap();

    static ref QUIC_CONNECTIONS_CLOSED: IntCounter = register_int_counter!(
        "udcn_quic_connections_closed_total", 
        "Total number of QUIC connections closed"
    ).unwrap();

    static ref QUIC_ERRORS: IntCounter = register_int_counter!(
        "udcn_quic_errors_total", 
        "Total number of QUIC errors"
    ).unwrap();
}

// Gauge metrics
lazy_static! {
    static ref ACTIVE_CONNECTIONS: Gauge = register_gauge!(
        "udcn_active_connections", 
        "Number of active QUIC connections"
    ).unwrap();

    static ref ACTIVE_STREAMS: Gauge = register_gauge!(
        "udcn_active_streams", 
        "Number of active QUIC streams"
    ).unwrap();

    static ref CS_SIZE: Gauge = register_gauge!(
        "udcn_cs_size", 
        "Number of entries in the content store"
    ).unwrap();

    static ref CS_CAPACITY: Gauge = register_gauge!(
        "udcn_cs_capacity", 
        "Capacity of the content store"
    ).unwrap();

    static ref CURRENT_MTU: Gauge = register_gauge!(
        "udcn_current_mtu", 
        "Current MTU setting"
    ).unwrap();

    static ref MEMORY_USAGE: Gauge = register_gauge!(
        "udcn_memory_usage_bytes", 
        "Memory usage in bytes"
    ).unwrap();
}

// Histogram metrics
lazy_static! {
    static ref INTEREST_LATENCY: Histogram = register_histogram!(
        HistogramOpts::new(
            "udcn_interest_latency_seconds", 
            "Time to satisfy an Interest"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
    ).unwrap();

    static ref DATA_SIZE: Histogram = register_histogram!(
        HistogramOpts::new(
            "udcn_data_size_bytes", 
            "Size of Data packets in bytes"
        ).buckets(vec![100.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 50000.0, 100000.0])
    ).unwrap();

    static ref QUIC_RTT: Histogram = register_histogram!(
        HistogramOpts::new(
            "udcn_quic_rtt_seconds", 
            "QUIC round-trip time"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).unwrap();
}

/// Initialize the metrics system
pub fn init_metrics(port: u16) {
    // Start the metrics server in a separate thread
    thread::spawn(move || {
        let metrics_route = warp::path("metrics").map(|| {
            use prometheus::Encoder;
            let encoder = prometheus::TextEncoder::new();
            let mut buffer = Vec::new();
            if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
                error!("Failed to encode metrics: {}", e);
                return "Error encoding metrics".to_string();
            }
            String::from_utf8(buffer).unwrap_or_else(|_| "Error encoding metrics".to_string())
        });

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        info!("Metrics server listening on http://{}/metrics", addr);
        warp::serve(metrics_route).run(addr);
    });
}

/// Record an Interest being sent
pub fn record_interest_sent() {
    INTERESTS_SENT.inc();
}

/// Record an Interest being received
pub fn record_interest_received() {
    INTERESTS_RECEIVED.inc();
}

/// Record an Interest being satisfied
pub fn record_interest_satisfied() {
    INTERESTS_SATISFIED.inc();
}

/// Record an Interest timing out
pub fn record_interest_timeout() {
    INTERESTS_TIMED_OUT.inc();
}

/// Record an Interest retransmission
pub fn record_interest_retransmit() {
    INTEREST_RETRANSMISSIONS.inc();
}

/// Record Interest latency
pub fn record_interest_latency(seconds: f64) {
    INTEREST_LATENCY.observe(seconds);
}

/// Record a Data packet being sent
pub fn record_data_sent(size: usize) {
    DATA_SENT.inc();
    DATA_BYTES_SENT.inc_by(size as u64);
    DATA_SIZE.observe(size as f64);
}

/// Record a Data packet being received
pub fn record_data_received(size: usize) {
    DATA_RECEIVED.inc();
    DATA_BYTES_RECEIVED.inc_by(size as u64);
    DATA_SIZE.observe(size as f64);
}

/// Record a NACK being sent
pub fn record_nack_sent() {
    NACKS_SENT.inc();
}

/// Record a NACK being received
pub fn record_nack_received() {
    NACKS_RECEIVED.inc();
}

/// Record a content store hit
pub fn record_cs_hit() {
    CS_HITS.inc();
}

/// Record a content store miss
pub fn record_cs_miss() {
    CS_MISSES.inc();
}

/// Update content store metrics
pub fn update_cs_metrics(size: usize, capacity: usize) {
    CS_SIZE.set(size as f64);
    CS_CAPACITY.set(capacity as f64);
}

/// Record a QUIC connection being opened
pub fn record_quic_connection_opened() {
    QUIC_CONNECTIONS_OPENED.inc();
    ACTIVE_CONNECTIONS.inc();
}

/// Record a QUIC connection being closed
pub fn record_quic_connection_closed() {
    QUIC_CONNECTIONS_CLOSED.inc();
    ACTIVE_CONNECTIONS.dec();
}

/// Record a QUIC stream being opened
pub fn record_quic_stream_opened() {
    QUIC_STREAMS_OPENED.inc();
    ACTIVE_STREAMS.inc();
}

/// Record a QUIC stream being closed
pub fn record_quic_stream_closed() {
    ACTIVE_STREAMS.dec();
}

/// Record a QUIC error
pub fn record_quic_error() {
    QUIC_ERRORS.inc();
}

/// Record QUIC RTT
pub fn record_quic_rtt(seconds: f64) {
    QUIC_RTT.observe(seconds);
}

/// Update the current MTU setting
pub fn update_mtu(mtu: usize) {
    CURRENT_MTU.set(mtu as f64);
}

/// Record memory usage
pub fn record_memory_usage(bytes: usize) {
    MEMORY_USAGE.set(bytes as f64);
}

/// Record Interest processing miss (no handler found)
pub fn record_interest_miss() {
    register_int_counter!(
        "udcn_interest_misses_total",
        "Total number of NDN Interests with no matching handler"
    ).unwrap().inc();
}

/// Record Interest processing error
pub fn record_interest_error() {
    register_int_counter!(
        "udcn_interest_errors_total",
        "Total number of errors while processing NDN Interests"
    ).unwrap().inc();
}
