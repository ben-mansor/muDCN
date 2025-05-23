// μDCN QUIC Transport Implementation
//
// This module implements a simplified QUIC transport layer for NDN
// using the quinn crate. It provides a clean interface for exchanging
// Interest and Data packets over QUIC streams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut, BufMut};
use dashmap::DashMap;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::{Certificate, PrivateKey};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};
use crate::ndn::{Data, Interest};
use crate::name::Name;
use crate::security::generate_self_signed_cert;

// Connection state tracking enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    // Connection is being established
    Connecting,
    // Connection is established and active
    Connected,
    // Connection is idle (no recent activity)
    Idle,
    // Connection is closing or has closed
    Closing,
    // Connection has failed with reason
    Failed(String),
}

// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    // Round-trip time in milliseconds (moving average)
    pub rtt_ms: u64,
    // Number of interests sent
    pub interests_sent: u64,
    // Number of data packets received
    pub data_received: u64,
    // Number of timeouts encountered
    pub timeouts: u64,
    // Number of errors encountered
    pub errors: u64,
    // Last activity timestamp
    pub last_activity: Instant,
    // Average data packet size
    pub avg_data_size: usize,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            rtt_ms: 0,
            interests_sent: 0,
            data_received: 0,
            timeouts: 0,
            errors: 0,
            last_activity: Instant::now(),
            avg_data_size: 0,
        }
    }
}

// Connection tracker
#[derive(Debug)]
pub struct ConnectionTracker {
    // The QUIC connection
    connection: Connection,
    // Connection state
    state: RwLock<ConnectionState>,
    // Connection statistics
    stats: RwLock<ConnectionStats>,
}

impl ConnectionTracker {
    // Create a new connection tracker
    pub fn new(connection: Connection) -> Self {
        Self {
            connection,
            state: RwLock::new(ConnectionState::Connecting),
            stats: RwLock::new(ConnectionStats::default()),
        }
    }

    // Update connection state
    pub async fn set_state(&self, state: ConnectionState) {
        let mut current_state = self.state.write().await;
        *current_state = state;
    }

    // Get connection state
    pub async fn state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }

    // Report successful interest/data exchange
    pub async fn report_success(&self, rtt_ms: u64, data_size: usize) {
        let mut stats = self.stats.write().await;
        
        // Update RTT (moving average with 20% weight for new value)
        if stats.rtt_ms == 0 {
            stats.rtt_ms = rtt_ms;
        } else {
            stats.rtt_ms = (stats.rtt_ms * 8 + rtt_ms * 2) / 10;
        }
        
        // Update data received counter
        stats.data_received += 1;
        
        // Update last activity timestamp
        stats.last_activity = Instant::now();
        
        // Update average data size (moving average)
        if stats.avg_data_size == 0 {
            stats.avg_data_size = data_size;
        } else {
            stats.avg_data_size = (stats.avg_data_size * 8 + data_size * 2) / 10;
        }
    }

    // Report failure (timeout or error)
    pub async fn report_failure(&self, is_timeout: bool) {
        let mut stats = self.stats.write().await;
        
        if is_timeout {
            stats.timeouts += 1;
        } else {
            stats.errors += 1;
        }
        
        // Update last activity timestamp
        stats.last_activity = Instant::now();
    }

    // Get connection statistics
    pub async fn stats(&self) -> ConnectionStats {
        self.stats.read().await.clone()
    }

    // Check if connection is idle
    pub async fn is_idle(&self, idle_threshold: Duration) -> bool {
        let stats = self.stats.read().await;
        stats.last_activity.elapsed() > idle_threshold
    }

    // Get connection
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

// Handler type for Interest packets
pub type InterestHandler = Arc<dyn Fn(Interest) -> Result<Data> + Send + Sync>;

// QUIC transport for NDN
pub struct QuicTransport {
    // Local endpoint
    endpoint: Endpoint,
    
    // Active connections
    connections: DashMap<SocketAddr, Arc<ConnectionTracker>>,
    
    // Interest handlers by name prefix
    handlers: Arc<RwLock<HashMap<Name, InterestHandler>>>,
    
    // Server task handle
    server_handle: Option<JoinHandle<()>>,
    
    // Configuration
    bind_addr: SocketAddr,
    port: u16,
    idle_timeout: Duration,
    max_packet_size: usize,
}

impl QuicTransport {
    // Create a new QUIC transport instance
    pub async fn new(
        bind_addr: &str, 
        port: u16, 
        idle_timeout_secs: u64, 
        max_packet_size: usize
    ) -> Result<Self> {
        // Parse bind address
        let addr = format!("{}:{}", bind_addr, port).parse::<SocketAddr>()?;
        
        // Generate self-signed certificate
        let (cert, key) = generate_self_signed_cert()?;
        
        // Create server config
        let server_config = create_server_config(vec![cert], key)?;
        
        // Create endpoint
        let endpoint = Endpoint::server(server_config, addr)?;
        info!("QUIC endpoint bound to {}", addr);
        
        Ok(Self {
            endpoint,
            connections: DashMap::new(),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            server_handle: None,
            bind_addr: addr,
            port,
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            max_packet_size,
        })
    }
    
    // Start the QUIC transport server
    pub async fn start_server(&mut self) -> Result<()> {
        // Clone required references for the server task
        let endpoint = self.endpoint.clone();
        let handlers = self.handlers.clone();
        let connections = self.connections.clone();
        let max_packet_size = self.max_packet_size;
        
        // Start the server task
        self.server_handle = Some(tokio::spawn(async move {
            info!("QUIC server starting on {}", endpoint.local_addr().unwrap());
            
            // Accept incoming connections
            while let Some(connecting) = endpoint.accept().await {
                // Try to establish the connection
                match connecting.await {
                    Ok(conn) => {
                        // Get remote address
                        let remote = conn.remote_address();
                        info!("Accepted connection from {}", remote);
                        
                        // Create connection tracker
                        let conn_tracker = Arc::new(ConnectionTracker::new(conn.clone()));
                        conn_tracker.set_state(ConnectionState::Connected).await;
                        connections.insert(remote, conn_tracker.clone());
                        
                        // Handle connection in a separate task
                        let handlers_clone = handlers.clone();
                        let conn_tracker_clone = conn_tracker.clone();
                        let max_packet_size_clone = max_packet_size;
                        
                        tokio::spawn(async move {
                            Self::handle_connection(
                                conn,
                                remote,
                                handlers_clone,
                                conn_tracker_clone,
                                max_packet_size_clone
                            ).await;
                        });
                    },
                    Err(e) => {
                        error!("Connection failed: {}", e);
                    }
                }
            }
            
            info!("QUIC server stopped");
        }));
        
        Ok(())
    }
    
    // Handle a QUIC connection
    async fn handle_connection(
        conn: Connection,
        remote: SocketAddr,
        handlers: Arc<RwLock<HashMap<Name, InterestHandler>>>,
        conn_tracker: Arc<ConnectionTracker>,
        max_packet_size: usize
    ) {
        info!("Handling connection from {}", remote);
        
        // Process incoming streams
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            // Handle the stream in a separate task
            let handlers_clone = handlers.clone();
            let conn_tracker_clone = conn_tracker.clone();
            let max_packet_size_clone = max_packet_size;
            
            tokio::spawn(async move {
                Self::handle_stream(
                    &mut send,
                    &mut recv,
                    handlers_clone,
                    conn_tracker_clone,
                    max_packet_size_clone
                ).await;
            });
        }
        
        info!("Connection handler finished for {}", remote);
        conn_tracker.set_state(ConnectionState::Closing).await;
    }
    
    // Handle a QUIC stream
    async fn handle_stream(
        send: &mut SendStream,
        recv: &mut RecvStream,
        handlers: Arc<RwLock<HashMap<Name, InterestHandler>>>,
        conn_tracker: Arc<ConnectionTracker>,
        max_packet_size: usize
    ) {
        // Read the Interest packet
        let interest_bytes = match recv.read_to_end(max_packet_size).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Error reading from stream: {}", e);
                conn_tracker.report_failure(false).await;
                return;
            }
        };
        
        // Decode Interest
        let interest = match Interest::from_bytes(&interest_bytes) {
            Ok(interest) => interest,
            Err(e) => {
                error!("Error decoding Interest: {}", e);
                conn_tracker.report_failure(false).await;
                return;
            }
        };
        
        debug!("Received Interest for {}", interest.name());
        
        // Find handler for this name
        let handlers_guard = handlers.read().await;
        let mut handler_opt = None;
        let mut longest_prefix = 0;
        
        for (prefix, handler) in handlers_guard.iter() {
            if interest.name().has_prefix(prefix) && prefix.len() > longest_prefix {
                handler_opt = Some(handler.clone());
                longest_prefix = prefix.len();
            }
        }
        
        // Process Interest
        let response = match handler_opt {
            Some(handler) => {
                match handler(interest) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Handler error: {}", e);
                        conn_tracker.report_failure(false).await;
                        return;
                    }
                }
            },
            None => {
                // No handler found, create a simple NACK response
                warn!("No handler for {}", interest.name());
                conn_tracker.report_failure(false).await;
                return;
            }
        };
        
        // Encode Data
        let data_bytes = response.to_bytes();
        
        // Send Data
        match send.write_all(&data_bytes).await {
            Ok(_) => {
                debug!("Sent Data for {}", interest.name());
                conn_tracker.report_success(0, data_bytes.len()).await;
            },
            Err(e) => {
                error!("Error sending Data: {}", e);
                conn_tracker.report_failure(false).await;
            }
        }
        
        // Finish sending
        if let Err(e) = send.finish().await {
            error!("Error finishing stream: {}", e);
        }
    }
    
    // Register a handler for a name prefix
    pub async fn register_handler(&self, prefix: Name, handler: impl Fn(Interest) -> Result<Data> + Send + Sync + 'static) -> Result<()> {
        let mut handlers = self.handlers.write().await;
        handlers.insert(prefix.clone(), Arc::new(handler));
        info!("Registered handler for prefix: {}", prefix);
        Ok(())
    }
    
    // Connect to a remote NDN node
    pub async fn connect(&self, remote_addr: &str, remote_port: u16) -> Result<Arc<ConnectionTracker>> {
        // Parse remote address
        let addr = format!("{}:{}", remote_addr, remote_port).parse::<SocketAddr>()?;
        
        // Check if we already have a connection
        if let Some(conn) = self.connections.get(&addr) {
            return Ok(conn.clone());
        }
        
        // Create client config
        let client_config = create_client_config()?;
        
        // Connect to the remote endpoint
        info!("Connecting to {}:{}", remote_addr, remote_port);
        let connecting = self.endpoint.connect_with(client_config, addr, "localhost")?;
        
        // Wait for connection
        let connection = connecting.await?;
        
        // Create connection tracker
        let conn_tracker = Arc::new(ConnectionTracker::new(connection));
        conn_tracker.set_state(ConnectionState::Connected).await;
        
        // Store the connection
        self.connections.insert(addr, conn_tracker.clone());
        
        Ok(conn_tracker)
    }
    
    // Send an Interest packet and wait for Data
    pub async fn send_interest(&self, remote_addr: SocketAddr, interest: Interest) -> Result<Data> {
        // Get or create connection
        let conn_tracker = if let Some(tracker) = self.connections.get(&remote_addr) {
            tracker.clone()
        } else {
            // We need to connect first - but this should normally be done explicitly
            return Err(Error::ConnectionError("Not connected to remote peer".to_string()));
        };
        
        // Check connection state
        let state = conn_tracker.state().await;
        if state != ConnectionState::Connected {
            return Err(Error::ConnectionError(format!("Connection not ready: {:?}", state)));
        }
        
        // Start time for RTT measurement
        let start_time = Instant::now();
        
        // Open bidirectional stream
        let connection = conn_tracker.connection();
        let (mut send, mut recv) = connection.open_bi().await
            .map_err(|e| Error::ConnectionError(format!("Failed to open stream: {}", e)))?;
        
        // Encode Interest
        let interest_bytes = interest.to_bytes();
        
        // Send Interest
        send.write_all(&interest_bytes).await
            .map_err(|e| Error::IoError(format!("Failed to send Interest: {}", e)))?;
        
        // Finish sending
        send.finish().await
            .map_err(|e| Error::IoError(format!("Failed to finish stream: {}", e)))?;
        
        debug!("Sent Interest for {}", interest.name());
        
        // Wait for Data
        let data_bytes = recv.read_to_end(self.max_packet_size).await
            .map_err(|e| Error::IoError(format!("Failed to receive Data: {}", e)))?;
        
        // Calculate RTT
        let rtt = start_time.elapsed().as_millis() as u64;
        
        // Decode Data
        let data = Data::from_bytes(&data_bytes)
            .map_err(|e| Error::ParsingError(format!("Failed to decode Data: {}", e)))?;
        
        // Update statistics
        conn_tracker.report_success(rtt, data_bytes.len()).await;
        
        debug!("Received Data for {}, RTT: {}ms", interest.name(), rtt);
        
        Ok(data)
    }
    
    // Close a connection
    pub async fn close_connection(&self, remote_addr: SocketAddr) -> Result<()> {
        if let Some(conn_tracker) = self.connections.get(&remote_addr) {
            conn_tracker.set_state(ConnectionState::Closing).await;
            let connection = conn_tracker.connection();
            connection.close(0u32.into(), b"connection closed by application");
            self.connections.remove(&remote_addr);
            Ok(())
        } else {
            Err(Error::ConnectionError("Connection not found".to_string()))
        }
    }
    
    // Shutdown the transport
    pub async fn shutdown(&mut self) -> Result<()> {
        // Stop server task
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
        
        // Close all connections
        for conn in self.connections.iter() {
            let connection = conn.connection();
            connection.close(0u32.into(), b"server shutting down");
        }
        
        self.connections.clear();
        self.endpoint.close(0u32.into(), b"server shutting down");
        
        Ok(())
    }
    
    // Get connection statistics for a remote address
    pub async fn get_connection_stats(&self, remote_addr: SocketAddr) -> Option<ConnectionStats> {
        if let Some(conn_tracker) = self.connections.get(&remote_addr) {
            Some(conn_tracker.stats().await)
        } else {
            None
        }
    }
    
    // Get all active connections
    pub fn get_connections(&self) -> Vec<SocketAddr> {
        self.connections.iter().map(|entry| *entry.key()).collect()
    }
}

// Helper function to create a server configuration
fn create_server_config(certs: Vec<Certificate>, key: PrivateKey) -> Result<ServerConfig> {
    let mut server_config = ServerConfig::with_single_cert(certs, key)
        .map_err(|e| Error::CryptoError(format!("Failed to create server config: {}", e)))?;
    
    // Configure transport parameters
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| Error::Other("Failed to get transport config".to_string()))?;
    
    // Set keepalive interval
    transport_config.keep_alive_interval(Some(Duration::from_secs(15)));
    
    // Set idle timeout
    transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    
    Ok(server_config)
}

// Helper function to create a client configuration
fn create_client_config() -> Result<ClientConfig> {
    // Use basic client config without certificate verification for development
    let client_config = ClientConfig::new(Arc::new(rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth()
    ));
    
    Ok(client_config)
}
