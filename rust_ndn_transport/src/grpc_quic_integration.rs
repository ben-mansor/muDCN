// μDCN gRPC and QUIC Integration Module
//
// This module integrates the gRPC server with the QUIC transport layer,
// allowing the control plane to manage QUIC connections and exchange
// NDN Interest/Data packets through the gRPC API.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{Error, Result};
use crate::grpc::udcn::{
    DataPacketResponse, InterestPacketRequest, QuicConnectionRequest, QuicConnectionResponse,
    ConnectionQuality, InterestFilter
};
use crate::ndn::{Data, Interest};
use crate::name::Name;
use crate::quic_transport::{QuicTransport, ConnectionState, ConnectionStats};

/// Integration adapter between gRPC and QUIC transport
pub struct GrpcQuicAdapter {
    /// The QUIC transport instance
    transport: Arc<RwLock<QuicTransport>>,
    
    /// Connection ID to socket address mapping
    connections: Arc<RwLock<HashMap<String, SocketAddr>>>,
    
    /// Next connection ID
    next_conn_id: Arc<RwLock<u64>>,
}

impl GrpcQuicAdapter {
    /// Create a new gRPC-QUIC adapter
    pub async fn new(bind_addr: &str, port: u16) -> Result<Self> {
        // Create the QUIC transport
        let quic_transport = QuicTransport::new(bind_addr, port, 30, 65535).await?;
        
        // Start the QUIC transport server
        let mut transport_mut = quic_transport.clone();
        transport_mut.start_server().await?;
        
        Ok(Self {
            transport: Arc::new(RwLock::new(quic_transport)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            next_conn_id: Arc::new(RwLock::new(1)),
        })
    }
    
    /// Create a QUIC connection to a remote NDN router
    pub async fn create_quic_connection(&self, req: QuicConnectionRequest) -> Result<QuicConnectionResponse> {
        let peer_address = req.peer_address;
        let port = req.port as u16;
        
        // Validate input
        if peer_address.is_empty() {
            return Err(Error::InvalidArgument("Peer address cannot be empty".to_string()));
        }
        
        if port == 0 || port > 65535 {
            return Err(Error::InvalidArgument("Invalid port number".to_string()));
        }
        
        // Create QUIC connection
        let transport = self.transport.read().await;
        let conn_tracker = transport.connect(&peer_address, port).await?;
        
        // Generate connection ID
        let conn_id = {
            let mut next_id = self.next_conn_id.write().await;
            let id = *next_id;
            *next_id += 1;
            format!("conn-{}-{}", peer_address.replace(".", "-"), id)
        };
        
        // Store connection mapping
        let remote_addr = format!("{}:{}", peer_address, port).parse()?;
        {
            let mut connections = self.connections.write().await;
            connections.insert(conn_id.clone(), remote_addr);
        }
        
        // Get connection stats
        let stats = conn_tracker.stats().await;
        
        // Determine connection quality
        let quality = if stats.rtt_ms < 50 {
            ConnectionQuality::Excellent as i32
        } else if stats.rtt_ms < 100 {
            ConnectionQuality::Good as i32
        } else if stats.rtt_ms < 200 {
            ConnectionQuality::Fair as i32
        } else {
            ConnectionQuality::Poor as i32
        };
        
        // Create response
        let response = QuicConnectionResponse {
            success: true,
            error_message: String::new(),
            connection_id: conn_id,
            remote_address: peer_address,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            quality,
        };
        
        Ok(response)
    }
    
    /// Send an Interest packet and receive Data
    pub async fn send_interest(&self, req: InterestPacketRequest) -> Result<DataPacketResponse> {
        let connection_id = req.connection_id.clone();
        let name_str = req.name.clone();
        let lifetime_ms = req.lifetime_ms;
        
        // Validate input
        if connection_id.is_empty() {
            return Err(Error::InvalidArgument("Connection ID cannot be empty".to_string()));
        }
        
        if name_str.is_empty() {
            return Err(Error::InvalidArgument("Interest name cannot be empty".to_string()));
        }
        
        // Get socket address for the connection
        let remote_addr = {
            let connections = self.connections.read().await;
            match connections.get(&connection_id) {
                Some(addr) => *addr,
                None => return Err(Error::NotFound(format!("Connection {} not found", connection_id))),
            }
        };
        
        // Parse the name
        let name = Name::from_uri(&name_str)?;
        
        // Create Interest packet
        let mut interest = Interest::new(name);
        interest.set_can_be_prefix(req.can_be_prefix);
        interest.set_must_be_fresh(req.must_be_fresh);
        interest.set_lifetime_ms(lifetime_ms);
        
        // Send Interest and wait for Data
        let transport = self.transport.read().await;
        let start_time = std::time::Instant::now();
        let data = transport.send_interest(remote_addr, interest).await?;
        let rtt = start_time.elapsed().as_millis() as u64;
        
        // Create response
        let response = DataPacketResponse {
            success: true,
            error_message: String::new(),
            name: data.name().to_string(),
            content: data.content(),
            content_type: data.content_type() as u32,
            freshness_period: data.freshness_period_ms(),
            signature: data.signature().unwrap_or_default(),
            signature_type: data.signature_type().unwrap_or_default(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        
        Ok(response)
    }
    
    /// Register a handler for receiving Data packets for a specific prefix
    pub async fn register_prefix_interest(&self, prefix: &str, handler: impl Fn(Interest) -> Result<Data> + Send + Sync + 'static) -> Result<()> {
        // Parse prefix
        let name = Name::from_uri(prefix)?;
        
        // Register handler with QUIC transport
        let mut transport = self.transport.write().await;
        transport.register_handler(name, handler).await?;
        
        Ok(())
    }
    
    /// Close a QUIC connection
    pub async fn close_connection(&self, connection_id: &str) -> Result<()> {
        // Get socket address for the connection
        let remote_addr = {
            let mut connections = self.connections.write().await;
            match connections.remove(connection_id) {
                Some(addr) => addr,
                None => return Err(Error::NotFound(format!("Connection {} not found", connection_id))),
            }
        };
        
        // Close the connection
        let mut transport = self.transport.write().await;
        transport.close_connection(remote_addr).await?;
        
        Ok(())
    }
    
    /// Get connection statistics
    pub async fn get_connection_stats(&self, connection_id: &str) -> Result<ConnectionStats> {
        // Get socket address for the connection
        let remote_addr = {
            let connections = self.connections.read().await;
            match connections.get(connection_id) {
                Some(addr) => *addr,
                None => return Err(Error::NotFound(format!("Connection {} not found", connection_id))),
            }
        };
        
        // Get connection stats
        let transport = self.transport.read().await;
        match transport.get_connection_stats(remote_addr).await {
            Some(stats) => Ok(stats),
            None => Err(Error::NotFound(format!("Connection {} statistics not available", connection_id))),
        }
    }
    
    /// List all active connections
    pub async fn list_connections(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections.keys().cloned().collect()
    }
    
    /// Shutdown the QUIC transport
    pub async fn shutdown(&self) -> Result<()> {
        let mut transport = self.transport.write().await;
        transport.shutdown().await?;
        Ok(())
    }
}
