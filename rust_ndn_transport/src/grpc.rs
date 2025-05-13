use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::UdcnTransport;
use crate::name::Name;

// Include the generated proto code
pub mod udcn {
    tonic::include_proto!("udcn");
}

use udcn::{
    MtuRequest, MtuResponse,
    PrefixRegistrationRequest, PrefixRegistrationResponse,
    PrefixUnregistrationRequest, PrefixUnregistrationResponse,
    MetricsRequest, MetricsResponse, MetricValue,
    NetworkInterfacesRequest, NetworkInterfacesResponse, NetworkInterface,
    TransportControlRequest, TransportControlResponse,
    StreamMetricsRequest, MetricsData,
    TransportConfigRequest, TransportConfigResponse, TransportConfig,
    TransportStateRequest, TransportStateResponse,
};

// Import the service trait
use udcn::udcn_control_server::{UdcnControl, UdcnControlServer};

// Define the gRPC server struct
#[derive(Debug)]
pub struct UdcnControlService {
    transport: Arc<UdcnTransport>,
}

impl UdcnControlService {
    pub fn new(transport: Arc<UdcnTransport>) -> Self {
        Self { transport }
    }
    
    // Helper method to get current timestamp in milliseconds
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

#[tonic::async_trait]
impl UdcnControl for UdcnControlService {
    // Update MTU based on ML prediction
    async fn update_mtu(
        &self,
        request: Request<MtuRequest>,
    ) -> Result<Response<MtuResponse>, Status> {
        let req = request.into_inner();
        let previous_mtu = self.transport.mtu();
        
        // Log the request
        tracing::info!(
            "Received MTU update request: {} (confidence: {})",
            req.mtu, req.confidence
        );
        
        // Validate MTU value
        if req.mtu < 576 || req.mtu > 9000 {
            return Err(Status::invalid_argument(
                format!("Invalid MTU value: {}. Must be between 576 and 9000", req.mtu)
            ));
        }
        
        // Update MTU in the transport layer
        match self.transport.update_mtu(req.mtu as usize).await {
            Ok(_) => {
                let response = MtuResponse {
                    success: true,
                    error_message: String::new(),
                    previous_mtu: previous_mtu as u32,
                    current_mtu: req.mtu,
                };
                Ok(Response::new(response))
            },
            Err(e) => {
                let error_message = format!("Failed to update MTU: {}", e);
                tracing::error!("{}", error_message);
                
                let response = MtuResponse {
                    success: false,
                    error_message,
                    previous_mtu: previous_mtu as u32,
                    current_mtu: previous_mtu as u32,
                };
                Ok(Response::new(response))
            }
        }
    }

    // Register a new prefix for forwarding or production
    async fn register_prefix(
        &self,
        request: Request<PrefixRegistrationRequest>,
    ) -> Result<Response<PrefixRegistrationResponse>, Status> {
        let req = request.into_inner();
        let prefix_str = req.prefix.clone();
        
        // Parse the prefix string into a Name
        let prefix = match Name::try_from(prefix_str.clone()) {
            Ok(name) => name,
            Err(_) => {
                return Err(Status::invalid_argument(
                    format!("Invalid NDN name: {}", prefix_str)
                ));
            }
        };
        
        tracing::info!("Registering prefix: {}", prefix_str);
        
        // Different handling based on prefix type
        let registration_id = match req.r#type() {
            udcn::prefix_registration_request::PrefixType::Producer => {
                // For producer prefixes, register a handler that generates data
                // We use a dummy handler here - in production this would be customized
                let handler = Box::new(move |interest| {
                    let name = interest.name().clone();
                    let data = crate::ndn::Data::new(name, vec![0; 64]); // Dummy data
                    Ok(data)
                });
                
                match self.transport.register_prefix(prefix, handler).await {
                    Ok(id) => id,
                    Err(e) => {
                        return Err(Status::internal(
                            format!("Failed to register producer prefix: {}", e)
                        ));
                    }
                }
            },
            udcn::prefix_registration_request::PrefixType::Forwarder => {
                // For forwarder prefixes, register a forwarding rule
                // This is a simplified implementation
                match self.transport.register_forwarding_prefix(prefix, req.priority as usize).await {
                    Ok(id) => id,
                    Err(e) => {
                        return Err(Status::internal(
                            format!("Failed to register forwarder prefix: {}", e)
                        ));
                    }
                }
            }
        };
        
        let response = PrefixRegistrationResponse {
            success: true,
            error_message: String::new(),
            registration_id,
        };
        
        Ok(Response::new(response))
    }

    // Unregister a previously registered prefix
    async fn unregister_prefix(
        &self,
        request: Request<PrefixUnregistrationRequest>,
    ) -> Result<Response<PrefixUnregistrationResponse>, Status> {
        let req = request.into_inner();
        
        tracing::info!("Unregistering prefix with ID: {}", req.registration_id);
        
        // Attempt to unregister the prefix
        match self.transport.unregister_prefix(req.registration_id).await {
            Ok(_) => {
                let response = PrefixUnregistrationResponse {
                    success: true,
                    error_message: String::new(),
                };
                Ok(Response::new(response))
            },
            Err(e) => {
                let error_message = format!("Failed to unregister prefix: {}", e);
                tracing::error!("{}", error_message);
                
                let response = PrefixUnregistrationResponse {
                    success: false,
                    error_message,
                };
                Ok(Response::new(response))
            }
        }
    }

    // Get transport statistics and metrics
    async fn get_metrics(
        &self,
        request: Request<MetricsRequest>,
    ) -> Result<Response<MetricsResponse>, Status> {
        let req = request.into_inner();
        let metric_names = req.metric_names;
        
        tracing::info!("Fetching metrics: {:?}", metric_names);
        
        // Get metrics from the transport layer
        let metrics = self.transport.get_metrics().await;
        let mut response_metrics = HashMap::new();
        
        // Filter metrics based on requested names (or return all if empty)
        for (name, value) in metrics {
            if metric_names.is_empty() || metric_names.contains(&name) {
                // Convert transport metrics to gRPC metric values
                let metric_value = match value {
                    crate::metrics::MetricValue::Counter(v) => MetricValue {
                        value: Some(udcn::metric_value::Value::CounterValue(v)),
                        timestamp: Self::current_timestamp(),
                    },
                    crate::metrics::MetricValue::Gauge(v) => MetricValue {
                        value: Some(udcn::metric_value::Value::GaugeValue(v)),
                        timestamp: Self::current_timestamp(),
                    },
                    crate::metrics::MetricValue::Histogram(h) => {
                        // Convert histogram to gRPC histogram
                        let hist = udcn::Histogram {
                            buckets: h.buckets().to_vec(),
                            counts: h.counts().to_vec(),
                            sum: h.sum(),
                            count: h.count(),
                        };
                        
                        MetricValue {
                            value: Some(udcn::metric_value::Value::HistogramValue(hist)),
                            timestamp: Self::current_timestamp(),
                        }
                    }
                };
                
                response_metrics.insert(name, metric_value);
            }
        }
        
        let response = MetricsResponse {
            success: true,
            error_message: String::new(),
            metrics: response_metrics,
        };
        
        Ok(Response::new(response))
    }

    // Collect network interface information
    async fn get_network_interfaces(
        &self,
        request: Request<NetworkInterfacesRequest>,
    ) -> Result<Response<NetworkInterfacesResponse>, Status> {
        let req = request.into_inner();
        let include_stats = req.include_stats;
        
        tracing::info!("Fetching network interfaces (include_stats: {})", include_stats);
        
        // Get network interfaces from the transport layer
        match self.transport.get_network_interfaces(include_stats).await {
            Ok(interfaces) => {
                // Convert internal interface representation to gRPC representation
                let grpc_interfaces: Vec<NetworkInterface> = interfaces
                    .into_iter()
                    .map(|iface| NetworkInterface {
                        name: iface.name,
                        mac_address: iface.mac_address,
                        ip_addresses: iface.ip_addresses,
                        mtu: iface.mtu as u32,
                        is_up: iface.is_up,
                        rx_bytes: iface.rx_bytes,
                        tx_bytes: iface.tx_bytes,
                        rx_packets: iface.rx_packets,
                        tx_packets: iface.tx_packets,
                        rx_errors: iface.rx_errors,
                        tx_errors: iface.tx_errors,
                        rx_dropped: iface.rx_dropped,
                        tx_dropped: iface.tx_dropped,
                    })
                    .collect();
                
                let response = NetworkInterfacesResponse {
                    success: true,
                    error_message: String::new(),
                    interfaces: grpc_interfaces,
                };
                
                Ok(Response::new(response))
            },
            Err(e) => {
                let error_message = format!("Failed to get network interfaces: {}", e);
                tracing::error!("{}", error_message);
                
                let response = NetworkInterfacesResponse {
                    success: false,
                    error_message,
                    interfaces: Vec::new(),
                };
                
                Ok(Response::new(response))
            }
        }
    }

    // Control the state of the transport (start/stop/restart)
    async fn control_transport(
        &self,
        request: Request<TransportControlRequest>,
    ) -> Result<Response<TransportControlResponse>, Status> {
        let req = request.into_inner();
        let action = req.action();
        
        tracing::info!("Transport control requested: {:?}", action);
        
        let result = match action {
            udcn::transport_control_request::ControlAction::Start => {
                self.transport.start().await
            },
            udcn::transport_control_request::ControlAction::Stop => {
                self.transport.stop().await
            },
            udcn::transport_control_request::ControlAction::Restart => {
                self.transport.stop().await.and_then(|_| self.transport.start().await)
            },
            udcn::transport_control_request::ControlAction::Pause => {
                self.transport.pause().await
            },
            udcn::transport_control_request::ControlAction::Resume => {
                self.transport.resume().await
            },
        };
        
        match result {
            Ok(_) => {
                // Get current state
                let current_state = match self.transport.state().await {
                    crate::TransportState::Running => {
                        udcn::transport_control_response::TransportState::Running
                    },
                    crate::TransportState::Stopped => {
                        udcn::transport_control_response::TransportState::Stopped
                    },
                    crate::TransportState::Paused => {
                        udcn::transport_control_response::TransportState::Paused
                    },
                    crate::TransportState::Error => {
                        udcn::transport_control_response::TransportState::Error
                    },
                    crate::TransportState::Starting => {
                        udcn::transport_control_response::TransportState::Starting
                    },
                    crate::TransportState::Stopping => {
                        udcn::transport_control_response::TransportState::Stopping
                    },
                };
                
                let response = TransportControlResponse {
                    success: true,
                    error_message: String::new(),
                    current_state: current_state.into(),
                };
                
                Ok(Response::new(response))
            },
            Err(e) => {
                let error_message = format!("Failed to control transport: {}", e);
                tracing::error!("{}", error_message);
                
                let response = TransportControlResponse {
                    success: false,
                    error_message,
                    current_state: udcn::transport_control_response::TransportState::Error.into(),
                };
                
                Ok(Response::new(response))
            }
        }
    }

    // Streaming metrics for real-time monitoring
    type StreamMetricsStream = ReceiverStream<Result<MetricsData, Status>>;
    
    async fn stream_metrics(
        &self,
        request: Request<StreamMetricsRequest>,
    ) -> Result<Response<Self::StreamMetricsStream>, Status> {
        let req = request.into_inner();
        let metric_names = req.metric_names;
        let interval_ms = req.interval_ms;
        let max_samples = req.max_samples;
        
        tracing::info!(
            "Starting metrics stream: {:?}, interval: {}ms, max_samples: {}",
            metric_names, interval_ms, max_samples
        );
        
        // Create channel for sending metrics
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let transport = self.transport.clone();
        
        // Spawn a background task to send metrics periodically
        tokio::spawn(async move {
            let mut count = 0;
            let interval_duration = Duration::from_millis(interval_ms as u64);
            
            loop {
                if max_samples > 0 && count >= max_samples {
                    break;
                }
                
                // Get current metrics
                let metrics = transport.get_metrics().await;
                let mut response_metrics = HashMap::new();
                
                // Filter metrics based on requested names (or return all if empty)
                for (name, value) in metrics {
                    if metric_names.is_empty() || metric_names.contains(&name) {
                        // Convert transport metrics to gRPC metric values
                        let metric_value = match value {
                            crate::metrics::MetricValue::Counter(v) => MetricValue {
                                value: Some(udcn::metric_value::Value::CounterValue(v)),
                                timestamp: UdcnControlService::current_timestamp(),
                            },
                            crate::metrics::MetricValue::Gauge(v) => MetricValue {
                                value: Some(udcn::metric_value::Value::GaugeValue(v)),
                                timestamp: UdcnControlService::current_timestamp(),
                            },
                            crate::metrics::MetricValue::Histogram(h) => {
                                // Convert histogram to gRPC histogram
                                let hist = udcn::Histogram {
                                    buckets: h.buckets().to_vec(),
                                    counts: h.counts().to_vec(),
                                    sum: h.sum(),
                                    count: h.count(),
                                };
                                
                                MetricValue {
                                    value: Some(udcn::metric_value::Value::HistogramValue(hist)),
                                    timestamp: UdcnControlService::current_timestamp(),
                                }
                            }
                        };
                        
                        response_metrics.insert(name, metric_value);
                    }
                }
                
                // Send metrics data
                let metrics_data = MetricsData {
                    timestamp: UdcnControlService::current_timestamp(),
                    metrics: response_metrics,
                };
                
                if tx.send(Ok(metrics_data)).await.is_err() {
                    // Client disconnected
                    break;
                }
                
                count += 1;
                tokio::time::sleep(interval_duration).await;
            }
        });
        
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // Configure the transport layer parameters
    async fn configure_transport(
        &self,
        request: Request<TransportConfigRequest>,
    ) -> Result<Response<TransportConfigResponse>, Status> {
        let req = request.into_inner();
        
        tracing::info!("Configuring transport layer");
        
        // Build configuration
        let config = crate::Config {
            mtu: self.transport.mtu(), // Keep current MTU
            cache_capacity: req.cache_capacity as usize,
            idle_timeout: req.idle_timeout as u64,
            enable_metrics: req.enable_metrics,
            metrics_port: req.metrics_port as u16,
            bind_address: req.bind_address,
        };
        
        // Apply configuration
        match self.transport.configure(config).await {
            Ok(_) => {
                // Get current configuration
                let current_config = self.transport.get_config().await;
                
                let transport_config = TransportConfig {
                    mtu: current_config.mtu as u32,
                    cache_capacity: current_config.cache_capacity as u32,
                    idle_timeout: current_config.idle_timeout as u32,
                    enable_metrics: current_config.enable_metrics,
                    metrics_port: current_config.metrics_port as u32,
                    bind_address: current_config.bind_address,
                    advanced_config: req.advanced_config, // Pass through advanced config
                };
                
                let response = TransportConfigResponse {
                    success: true,
                    error_message: String::new(),
                    current_config: Some(transport_config),
                };
                
                Ok(Response::new(response))
            },
            Err(e) => {
                let error_message = format!("Failed to configure transport: {}", e);
                tracing::error!("{}", error_message);
                
                let response = TransportConfigResponse {
                    success: false,
                    error_message,
                    current_config: None,
                };
                
                Ok(Response::new(response))
            }
        }
    }

    // Get the current state of the transport layer
    async fn get_transport_state(
        &self,
        request: Request<TransportStateRequest>,
    ) -> Result<Response<TransportStateResponse>, Status> {
        let req = request.into_inner();
        let include_detailed_stats = req.include_detailed_stats;
        
        tracing::info!("Getting transport state (detailed_stats: {})", include_detailed_stats);
        
        // Get current state
        let state = match self.transport.state().await {
            crate::TransportState::Running => {
                udcn::transport_control_response::TransportState::Running
            },
            crate::TransportState::Stopped => {
                udcn::transport_control_response::TransportState::Stopped
            },
            crate::TransportState::Paused => {
                udcn::transport_control_response::TransportState::Paused
            },
            crate::TransportState::Error => {
                udcn::transport_control_response::TransportState::Error
            },
            crate::TransportState::Starting => {
                udcn::transport_control_response::TransportState::Starting
            },
            crate::TransportState::Stopping => {
                udcn::transport_control_response::TransportState::Stopping
            },
        };
        
        // Get statistics
        let stats = self.transport.get_statistics().await;
        
        // Get detailed stats if requested
        let detailed_stats = if include_detailed_stats {
            self.transport.get_detailed_statistics().await
        } else {
            HashMap::new()
        };
        
        let response = TransportStateResponse {
            success: true,
            error_message: String::new(),
            state: state.into(),
            uptime_seconds: stats.uptime_seconds as u32,
            interests_processed: stats.interests_processed,
            data_packets_sent: stats.data_packets_sent,
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
            cache_hit_ratio: stats.cache_hit_ratio,
            detailed_stats,
        };
        
        Ok(Response::new(response))
    }
}

// Start the gRPC server
pub async fn run_grpc_server(
    transport: Arc<UdcnTransport>,
    addr: impl Into<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.into();
    
    tracing::info!("Starting gRPC server on {}", addr);
    
    let service = UdcnControlService::new(transport);
    
    Server::builder()
        .add_service(UdcnControlServer::new(service))
        .serve(addr)
        .await?;
    
    Ok(())
}
