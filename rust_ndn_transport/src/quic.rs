// uDCN QUIC Transport Engine
//
// This module implements the QUIC-based transport engine that maps NDN
// names to QUIC stream IDs and handles fragmentation/reassembly.
//

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// use bytes::{Bytes, BytesMut, BufMut};
use dashmap::DashMap;
use quinn::{Connection, Endpoint, ServerConfig};
use rustls::{Certificate, PrivateKey};
// use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
// use futures::StreamExt;

use crate::ndn::{Interest, Data, Nack};
use crate::name::Name;
use crate::security::generate_self_signed_cert;
use crate::fragmentation::Fragmenter;
// use crate::metrics;
use crate::{Config, Result};

/// Handler function type for serving prefix registrations
pub type PrefixHandler = Box<dyn Fn(Interest) -> Result<Data> + Send + Sync>;

/// Struct that maps NDN names to QUIC stream IDs
#[derive(Debug)]
pub struct NameStreamMapper {
    /// Map from name prefix to stream ID
    name_to_stream: RwLock<HashMap<Name, (u64, mpsc::Sender<Interest>)>>,
    
    /// Next stream ID to assign
    next_stream_id: RwLock<u64>,
}

impl NameStreamMapper {
    /// Create a new name-to-stream mapper
    pub fn new() -> Self {
        Self {
            name_to_stream: RwLock::new(HashMap::new()),
            next_stream_id: RwLock::new(1),
        }
    }
    
    /// Associate a name with a stream ID
    pub async fn associate_name_with_stream(
        &self,
        name: &Name,
        sender: mpsc::Sender<Interest>,
    ) -> u64 {
        let mut streams = self.name_to_stream.write().await;
        let mut next_id = self.next_stream_id.write().await;
        
        let stream_id = *next_id;
        *next_id += 1;
        
        streams.insert(name.clone(), (stream_id, sender));
        stream_id
    }
    
    /// Get or create a stream ID for a name
    pub async fn get_or_create_stream_id(&self, name: &Name) -> u64 {
        let streams = self.name_to_stream.read().await;
        
        // First, look for exact match
        if let Some((stream_id, _)) = streams.get(name) {
            return *stream_id;
        }
        
        // Then, look for longest prefix match
        let mut longest_prefix = None;
        let mut longest_prefix_len = 0;
        
        for (prefix, (stream_id, _)) in streams.iter() {
            if name.starts_with(prefix) && prefix.len() > longest_prefix_len {
                longest_prefix = Some((*stream_id, prefix.clone()));
                longest_prefix_len = prefix.len();
            }
        }
        
        if let Some((stream_id, _)) = longest_prefix {
            return stream_id;
        }
        
        // No match found, we would normally create a new stream here
        // but we just return a default value for now
        0
    }
    
    /// Get the name for a stream ID
    pub async fn get_name(&self, stream_id: u64) -> Option<Name> {
        let streams = self.name_to_stream.read().await;
        
        for (name, (id, _)) in streams.iter() {
            if *id == stream_id {
                return Some(name.clone());
            }
        }
        
        None
    }
    
    /// Get the sender for a name
    pub async fn get_sender(&self, name: &Name) -> Option<mpsc::Sender<Interest>> {
        let streams = self.name_to_stream.read().await;
        
        // First, look for exact match
        if let Some((_, sender)) = streams.get(name) {
            return Some(sender.clone());
        }
        
        // Then, look for longest prefix match
        let mut longest_prefix = None;
        let mut longest_prefix_len = 0;
        
        for (prefix, (_, sender)) in streams.iter() {
            if name.starts_with(prefix) && prefix.len() > longest_prefix_len {
                longest_prefix = Some(sender.clone());
                longest_prefix_len = prefix.len();
            }
        }
        
        longest_prefix
    }
}

/// Connection state for NDN over QUIC connections
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is established and active
    Connected,
    /// Connection is idle (no recent activity)
    Idle,
    /// Connection is closing or has closed
    Closing,
    /// Connection has failed
    Failed(String),
}

/// Connection statistics for QoS monitoring
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Number of interests sent
    pub interests_sent: u64,
    /// Number of interests responded to
    pub interests_received: u64,
    /// Number of data packets sent
    pub data_sent: u64,
    /// Number of data packets received
    pub data_received: u64,
    /// Average round-trip time in milliseconds
    pub avg_rtt_ms: f64,
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss_rate: f64,
    /// Last activity timestamp
    pub last_activity: std::time::Instant,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            interests_sent: 0,
            interests_received: 0,
            data_sent: 0,
            data_received: 0,
            avg_rtt_ms: 0.0,
            packet_loss_rate: 0.0,
            last_activity: std::time::Instant::now(),
        }
    }
}

/// Enhanced connection tracker with state and statistics
#[derive(Debug)]
pub struct ConnectionTracker {
    /// QUIC connection
    connection: Connection,
    /// Connection state
    state: RwLock<ConnectionState>,
    /// Connection statistics
    stats: RwLock<ConnectionStats>,
    /// Congestion controller parameters
    congestion_window: RwLock<usize>,
    /// Health check interval for this connection
    health_check_interval: RwLock<Duration>,
}

impl ConnectionTracker {
    /// Create a new connection tracker
    pub fn new(connection: Connection) -> Self {
        Self {
            connection,
            state: RwLock::new(ConnectionState::Connecting),
            stats: RwLock::new(ConnectionStats::default()),
            congestion_window: RwLock::new(10),  // Initial congestion window size
            health_check_interval: RwLock::new(Duration::from_secs(30)),
        }
    }
    
    /// Update connection state
    pub async fn set_state(&self, state: ConnectionState) {
        let mut current_state = self.state.write().await;
        *current_state = state;
        
        let mut stats = self.stats.write().await;
        stats.last_activity = std::time::Instant::now();
        
        // Reset congestion window if connection failing
        if matches!(state, ConnectionState::Failed(_)) {
            let mut window = self.congestion_window.write().await;
            *window = 10;  // Reset to initial value
        }
    }
    
    /// Get connection state
    pub async fn state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }
    
    /// Report successful interest/data exchange
    pub async fn report_success(&self, rtt_ms: u64, data_size: usize) {
        let mut stats = self.stats.write().await;
        stats.interests_sent += 1;
        stats.data_received += 1;
        stats.rtt_ms = rtt_ms;
        stats.last_activity = std::time::Instant::now();
        
        // Update throughput based on RTT and data size
        if rtt_ms > 0 {
            let throughput = (data_size * 8 * 1000) as u64 / rtt_ms;
            // Exponential moving average (EMA) for smoothing
            stats.throughput_bps = (stats.throughput_bps * 7 + throughput * 3) / 10;
        }
        
        // Adjust congestion window based on successful operation
        let mut window = self.congestion_window.write().await;
        if *window < 100 {  // Cap at reasonable maximum
            *window += 1;    // Additive increase
        }
    }
    
    /// Report nack or timeout
    pub async fn report_failure(&self, reason: &str) {
        let mut stats = self.stats.write().await;
        stats.nacks_received += 1;
        stats.last_activity = std::time::Instant::now();
        
        // Adjust congestion window based on failure
        let mut window = self.congestion_window.write().await;
        *window = (*window * 3) / 4;  // Multiplicative decrease
        if *window < 1 {
            *window = 1;  // Minimum congestion window
        }
        
        debug!("Connection failure: {}. Adjusted congestion window to {}", reason, *window);
    }
    
    /// Get connection statistics
    pub async fn stats(&self) -> ConnectionStats {
        self.stats.read().await.clone()
    }
    
    /// Check if connection is idle
    pub async fn is_idle(&self, idle_threshold: Duration) -> bool {
        let stats = self.stats.read().await;
        stats.last_activity.elapsed() > idle_threshold
    }
    
    /// Get congestion window size
    pub async fn congestion_window(&self) -> usize {
        *self.congestion_window.read().await
    }
    
    /// Get connection
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// QUIC-based NDN transport engine
pub struct QuicEngine {
    /// Configuration
    config: Config,
    
    /// QUIC endpoint
    endpoint: Endpoint,
    
    /// Active connections with enhanced tracking
    connections: DashMap<SocketAddr, Arc<ConnectionTracker>>,
    
    /// Name stream mapper
    mapper: Arc<NameStreamMapper>,
    
    /// Prefix registrations
    prefixes: Arc<RwLock<HashMap<Name, PrefixHandler>>>,
    
    /// Server task handle
    server_handle: Option<JoinHandle<()>>,
    
    /// Connection maintenance task handle
    maintenance_handle: Option<JoinHandle<()>>,
    
    /// Fragmenter for large data objects
    fragmenter: Arc<Fragmenter>,
    
    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl std::fmt::Debug for QuicEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicEngine")
            .field("config", &self.config)
            .field("connections_count", &self.connections.len())
            .field("mapper", &self.mapper)
            // Skip prefixes field as it contains function pointers that don't implement Debug
            .field("server_handle", &self.server_handle)
            .field("fragmenter", &self.fragmenter)
            .finish_non_exhaustive()
    }
}

impl QuicEngine {
    /// Create a new QUIC engine
    pub async fn new(config: &Config) -> Result<Self> {
        // Generate self-signed certificate for QUIC server
        let (cert, key) = generate_self_signed_cert()?;
        
        // Create server config with the certificate
        let server_config = quinn::ServerConfig::with_single_cert(vec![cert], key)?;
        
        // Create QUIC endpoint
        let addr = config.bind_address.parse::<SocketAddr>()?
            .with_port(config.port);
        
        let endpoint = Endpoint::server(server_config, addr)?;
        info!("QUIC endpoint bound to {}", addr);
        
        // Create name-to-stream mapper
        let mapper = Arc::new(NameStreamMapper::new());
        
        // Create fragmenter
        let fragmenter = Arc::new(Fragmenter::new(config.mtu));
        
        Ok(Self {
            config: config.clone(),
            endpoint,
            connections: DashMap::new(),
            mapper,
            prefixes: Arc::new(RwLock::new(HashMap::new())),
            fragmenter,
            server_handle: None,
            maintenance_handle: None,
            running: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Start the QUIC engine
    pub async fn start(&mut self) -> Result<()> {
        // Set running state
        let mut running = self.running.write().await;
        *running = true;
        drop(running); // Release the lock
        
        // Clone required references for the server task
        let endpoint = self.endpoint.clone();
        let mapper = self.mapper.clone();
        let prefixes = self.prefixes.clone();
        let fragmenter = self.fragmenter.clone();
        let connections = self.connections.clone();
        let running_ref = self.running.clone();
        
        // Start the server task
        self.server_handle = Some(tokio::spawn(async move {
            // Accept incoming connections
            loop {
                // Check if we should continue running
                if !*running_ref.read().await {
                    break;
                }
                
                // Accept incoming connection
                match endpoint.accept().await {
                    Some(connecting) => {
                        // Try to establish the connection
                        match connecting.await {
                            Ok(conn) => {
                                // Get remote address
                                let remote = conn.remote_address();
                                info!("Accepted connection from {}", remote);
                                
                                // Create connection tracker
                                let conn_tracker = Arc::new(ConnectionTracker::new(conn.clone()));
                                connections.insert(remote, conn_tracker.clone());
                                
                                // Spawn a new task to handle the connection
                                let mapper_clone = mapper.clone();
                                let prefixes_clone = prefixes.clone();
                                let fragmenter_clone = fragmenter.clone();
                                let conn_tracker_clone = conn_tracker.clone();
                                
                                tokio::spawn(async move {
                                    // Mark connection as connected
                                    conn_tracker_clone.set_state(ConnectionState::Connected).await;
                                    
                                    // Handle the connection
                                    Self::handle_connection(
                                        conn,
                                        remote,
                                        mapper_clone,
                                        prefixes_clone,
                                        fragmenter_clone,
                                        conn_tracker_clone
                                    ).await;
                                });
                            },
                            Err(e) => {
                                error!("Error accepting connection: {}", e);
                            }
                        }
                    },
                    None => {
                        // No more incoming connections, possibly shutting down
                        if !*running_ref.read().await {
                            break;
                        }
                        // Brief pause to avoid busy-waiting
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        break;
                    }
                }
            }
            
            info!("QUIC server task terminated");
        }));
        
        // Start the connection maintenance task
        let connections = self.connections.clone();
        let running_ref = self.running.clone();
        let idle_timeout = Duration::from_secs(self.config.idle_timeout);
        
        self.maintenance_handle = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            
            loop {
                interval.tick().await;
                
                // Check if we should continue running
                if !*running_ref.read().await {
                    break;
                }
                
                // Check each connection for health
                for mut entry in connections.iter_mut() {
                    let addr = *entry.key();
                    let conn_tracker = entry.value();
                    
                    // Check if connection is idle
                    if conn_tracker.is_idle(idle_timeout).await {
                        info!("Connection to {} is idle, marking as Idle", addr);
                        conn_tracker.set_state(ConnectionState::Idle).await;
                    }
                    
                    // Check current state
                    match conn_tracker.state().await {
                        ConnectionState::Idle => {
                            // Check if idle for too long (2x idle timeout)
                            if conn_tracker.is_idle(idle_timeout * 2).await {
                                info!("Connection to {} idle for too long, closing", addr);
                                conn_tracker.set_state(ConnectionState::Closing).await;
                                conn_tracker.connection().close(0u32.into(), b"idle timeout");
                                connections.remove(&addr);
                            }
                        },
                        ConnectionState::Closing => {
                            // Remove connections that are marked as closing
                            connections.remove(&addr);
                        },
                        ConnectionState::Failed(_) => {
                            // Remove failed connections
                            connections.remove(&addr);
                        },
                        _ => {} // No action needed for other states
                    }
                }
            }
            
            info!("QUIC maintenance task terminated");
        }));
        
        info!("QUIC engine started");
        Ok(())
    }
    
    /// Handle a new QUIC connection
    async fn handle_connection(
        connection: quinn::Connection, 
        remote: SocketAddr,
        _mapper: Arc<NameStreamMapper>,
        prefixes: Arc<RwLock<HashMap<Name, PrefixHandler>>>,
        fragmenter: Arc<Fragmenter>,
        conn_tracker: Arc<ConnectionTracker>
    ) {
        info!("Handling connection from {}", remote);
        
        // Set initial state as connected
        conn_tracker.set_state(ConnectionState::Connected).await;
        
        loop {
            // Check congestion window before accepting a new stream
            let window_size = conn_tracker.congestion_window().await;
            if window_size < 1 {
                // Back off briefly if congestion window is zero
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            
            // Accept a new stream from the remote peer with timeout
            let stream_result = tokio::time::timeout(
                Duration::from_secs(30),
                connection.accept_bi()
            ).await;
            
            let stream = match stream_result {
                Ok(stream_res) => match stream_res {
                    Ok(stream) => stream,
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        info!("Connection closed by application: {}", remote);
                        conn_tracker.set_state(ConnectionState::Closing).await;
                        break;
                    },
                    Err(quinn::ConnectionError::ConnectionClosed { .. }) => {
                        info!("Connection closed: {}", remote);
                        conn_tracker.set_state(ConnectionState::Closing).await;
                        break;
                    },
                    Err(e) => {
                        error!("Stream accept error: {}", e);
                        conn_tracker.set_state(ConnectionState::Failed(e.to_string())).await;
                        conn_tracker.report_failure(&format!("Stream error: {}", e)).await;
                        break;
                    }
                },
                Err(_) => {
                    // Timeout occurred, continue the loop
                    continue;
                }
            };
            
            // Unpack the bidirectional stream
            let (mut send, mut recv) = stream;
            
            // Start time for RTT measurement
            let start_time = std::time::Instant::now();
            
            // Read the request with timeout
            let data_result = tokio::time::timeout(
                Duration::from_secs(10),
                recv.read_to_end(64 * 1024)
            ).await;
            
            let data = match data_result {
                Ok(read_result) => match read_result {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Error reading from stream: {}", e);
                        conn_tracker.report_failure(&format!("Read error: {}", e)).await;
                        continue;
                    }
                },
                Err(_) => {
                    // Timeout occurred
                    warn!("Timeout reading from stream");
                    conn_tracker.report_failure("Read timeout").await;
                    continue;
                }
            };
            
            // Try to parse as an interest
            match Interest::from_bytes(&data) {
                Ok(interest) => {
                    debug!("Received Interest for {}", interest.name());
                    
                    // Get the prefixes
                    let prefixes_lock = prefixes.read().await;
                    
                    // Find a matching prefix handler
                    let mut handler_opt = None;
                    let mut longest_prefix_len = 0;
                    
                    for (prefix, handler) in prefixes_lock.iter() {
                        if interest.name().starts_with(prefix) && prefix.len() > longest_prefix_len {
                            handler_opt = Some(handler);
                            longest_prefix_len = prefix.len();
                        }
                    }
                    
                    // Drop the prefixes lock before handler execution
                    drop(prefixes_lock);
                    
                    // If a handler is found, process the interest
                    if let Some(handler) = handler_opt {
                        // Process the interest
                        match handler(interest.clone()) {
                            Ok(mut data) => {
                                // Check if we need to fragment the data
                                let mtu = fragmenter.mtu().await;
                                let data_bytes = data.to_bytes();
                                
                                if data_bytes.len() > mtu {
                                    // Fragment the data
                                    debug!("Fragmenting data for {} ({} bytes > {} MTU)", 
                                           interest.name(), data_bytes.len(), mtu);
                                    
                                    let fragments = fragmenter.fragment(&data).await;
                                    
                                    // Send all fragments
                                    for fragment in fragments {
                                        if let Err(e) = send.write_all(&fragment).await {
                                            error!("Error sending fragment: {}", e);
                                            conn_tracker.report_failure(&format!("Send error: {}", e)).await;
                                            break;
                                        }
                                    }
                                } else {
                                    // Send the data directly
                                    debug!("Sending Data for {}", interest.name());
                                    if let Err(e) = send.write_all(&data_bytes).await {
                                        error!("Error sending data: {}", e);
                                        conn_tracker.report_failure(&format!("Send error: {}", e)).await;
                                    }
                                }
                                
                                // Calculate RTT and data size for statistics
                                let rtt = start_time.elapsed().as_millis() as u64;
                                let data_size = data_bytes.len();
                                
                                // Update connection statistics
                                conn_tracker.report_success(rtt, data_size).await;
                                
                                // Close the stream
                                if let Err(e) = send.finish().await {
                                    error!("Error finishing stream: {}", e);
                                }
                            },
                            Err(e) => {
                                // Create a NACK
                                let nack = Nack::new(interest.name().clone(), e.to_string());
                                let nack_bytes = nack.to_bytes();
                                
                                // Send the NACK
                                warn!("Sending NACK for {}: {}", interest.name(), e);
                                if let Err(e) = send.write_all(&nack_bytes).await {
                                    error!("Error sending NACK: {}", e);
                                    conn_tracker.report_failure(&format!("NACK error: {}", e)).await;
                                }
                                
                                // Update failure statistics
                                conn_tracker.report_failure(&format!("Handler error: {}", e)).await;
                                
                                // Close the stream
                                if let Err(e) = send.finish().await {
                                    error!("Error finishing stream: {}", e);
                                }
                            }
                        }
                    } else {
                        // No handler found, send a NACK
                        let nack = Nack::new(
                            interest.name().clone(),
                            "No handler found for prefix".to_string()
                        );
                        
                        // Send the NACK
                        warn!("No handler for {}, sending NACK", interest.name());
                        if let Err(e) = send.write_all(&nack.to_bytes()).await {
                            error!("Error sending NACK: {}", e);
                            conn_tracker.report_failure(&format!("NACK error: {}", e)).await;
                        }
                        
                        // Update failure statistics
                        conn_tracker.report_failure("No handler for prefix").await;
                        
                        // Close the stream
                        if let Err(e) = send.finish().await {
                            error!("Error finishing stream: {}", e);
                        }
                    }
                },
                Err(e) => {
                    match e {
                        quinn::ConnectionError::ApplicationClosed { .. } => {
                            info!("Connection closed gracefully");
                            break;
                        },
                        _ => {
                            error!("Connection error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
        
        info!("Connection handler finished for {}", remote);
    }
    
    /// Register a prefix with a handler function
    pub async fn register_prefix(&self, prefix: Name, handler: PrefixHandler) -> Result<u64> {
        info!("Registering prefix: {}", prefix);
        
        // Store the prefix and handler
        let mut prefixes = self.prefixes.write().await;
        prefixes.insert(prefix.clone(), handler);
        
        // Create a channel for this prefix
        let (tx, _rx) = mpsc::channel(100);
        
        // Associate the prefix with a stream ID
        let stream_id = self.mapper.associate_name_with_stream(&prefix, tx).await;
        
        Ok(stream_id)
    }
    
    /// Connect to a remote NDN router
    pub async fn connect(&self, remote_addr: SocketAddr) -> Result<Arc<ConnectionTracker>> {
        // Check if we already have a connection
        if let Some(conn) = self.connections.get(&remote_addr) {
            return Ok(conn.clone());
        }
        
        // Use basic client config without certificate verification for development
        let client_config = quinn::ClientConfig::new(Arc::new(rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
        ));
        
        // Connect to the remote endpoint
        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        let connecting = endpoint.connect_with(client_config, remote_addr, "localhost")?;
        let connection = connecting.await?;
        
        // Create a connection tracker
        let conn_tracker = Arc::new(ConnectionTracker::new(connection));
        
        // Store the connection tracker
        self.connections.insert(remote_addr, conn_tracker.clone());
        
        Ok(conn_tracker)
    }
    
    /// Send an Interest packet to a remote peer
    pub async fn send_interest(&self, remote_addr: SocketAddr, interest: Interest) -> Result<Data> {
        // Get or create connection tracker for this remote address
        let conn_tracker = if let Some(tracker) = self.connections.get(&remote_addr) {
            tracker.clone()
        } else {
            // Connect to the remote peer
            debug!("Connecting to {}", remote_addr);
            let connection = self.connect(remote_addr).await?;
            let tracker = Arc::new(ConnectionTracker::new(connection));
            self.connections.insert(remote_addr, tracker.clone());
            tracker
        };
        
        // Check connection state
        let state = conn_tracker.state().await;
        match state {
            ConnectionState::Failed(reason) => {
                // Connection previously failed, try to reconnect
                debug!("Connection to {} previously failed: {}, reconnecting", remote_addr, reason);
                let connection = self.connect(remote_addr).await?;
                let tracker = Arc::new(ConnectionTracker::new(connection));
                self.connections.insert(remote_addr, tracker.clone());
                conn_tracker.set_state(ConnectionState::Connected).await;
            },
            ConnectionState::Closing => {
                // Connection is closing, try to reconnect
                debug!("Connection to {} is closing, reconnecting", remote_addr);
                let connection = self.connect(remote_addr).await?;
                let tracker = Arc::new(ConnectionTracker::new(connection));
                self.connections.insert(remote_addr, tracker.clone());
                conn_tracker.set_state(ConnectionState::Connected).await;
            },
            ConnectionState::Idle => {
                // Connection is idle but may still be usable
                debug!("Connection to {} is idle, checking...", remote_addr);
                // We'll try to use it anyway and reconnect if needed
            },
            _ => {}
        }
        
        // Start time for RTT measurement
        let start_time = std::time::Instant::now();
        
        // Get the connection
        let connection = conn_tracker.connection().clone();
        
        // Check congestion window before sending
        let window_size = conn_tracker.congestion_window().await;
        if window_size < 1 {
            // Back off briefly if congestion window is zero
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        // Open a bidirectional stream with timeout
        let stream_result = tokio::time::timeout(
            Duration::from_secs(10),
            connection.open_bi()
        ).await;
        
        let (mut send, mut recv) = match stream_result {
            Ok(result) => match result {
                Ok(stream) => stream,
                Err(e) => {
                    // Stream opening failed, mark connection as failed
                    conn_tracker.set_state(ConnectionState::Failed(e.to_string())).await;
                    conn_tracker.report_failure(&format!("Stream open error: {}", e)).await;
                    return Err(crate::error::Error::ConnectionError(format!("Failed to open stream: {}", e)));
                }
            },
            Err(_) => {
                // Timeout occurred
                conn_tracker.report_failure("Stream open timeout").await;
                return Err(crate::error::Error::Timeout("Timed out opening stream".to_string()));
            }
        };
        
        // Serialize the interest
        let interest_bytes = interest.to_bytes();
        
        // Send the interest with timeout
        let send_result = tokio::time::timeout(
            Duration::from_secs(5),
            send.write_all(&interest_bytes)
        ).await;
        
        match send_result {
            Ok(result) => {
                if let Err(e) = result {
                    conn_tracker.report_failure(&format!("Write error: {}", e)).await;
                    return Err(crate::error::Error::IoError(format!("Failed to send interest: {}", e)));
                }
            },
            Err(_) => {
                // Timeout occurred
                conn_tracker.report_failure("Write timeout").await;
                return Err(crate::error::Error::Timeout("Timed out sending interest".to_string()));
            }
        };
        
        // Finish sending
        if let Err(e) = send.finish().await {
            warn!("Error finishing send stream: {}", e);
        }
        
        // Get the response with timeout
        let mut fragments = Vec::new();
        // Explicitly type the reassembler Option with the ReassemblyContext from our fragmentation module
        let mut reassembler: Option<crate::fragmentation::ReassemblyContext> = None;
        
        loop {
            let response_result = tokio::time::timeout(
                Duration::from_secs(30),  // Longer timeout for receiving data
                recv.read_to_end(self.config.max_packet_size)
            ).await;
            
            let response_bytes = match response_result {
                Ok(result) => match result {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        conn_tracker.report_failure(&format!("Read error: {}", e)).await;
                        return Err(crate::error::Error::IoError(format!("Failed to read response: {}", e)));
                    }
                },
                Err(_) => {
                    // Timeout occurred
                    conn_tracker.report_failure("Read timeout").await;
                    return Err(crate::error::Error::Timeout("Timed out receiving response".to_string()));
                }
            };
            
            if response_bytes.is_empty() {
                break; // End of stream
            }
            
            // Check if this is a fragment
            if let Ok(fragment) = Fragment::from_bytes(&response_bytes) {
                debug!("Received fragment {}/{} for interest {}", 
                        fragment.header().sequence(), fragment.header().total_fragments(), interest.name());
                fragments.push(fragment.clone());
                
                // Check if it's a final fragment
                if fragment.header().is_final() {
                    debug!("Received final fragment for interest {}", interest.name());
                    
                    // Initialize reassembler if not already done
                    if reassembler.is_none() {
                        // Access the fragmenter through the Arc dereference
                        let fragmenter = &*self.fragmenter;
                        
                        // Create a new reassembly context
                        reassembler = Some(fragmenter.new_reassembly_context(
                            fragment.header().fragment_id(),
                            fragment.header().total_fragments()
                        ));
                    }
                    
                    // Add all fragments to the reassembler
                    if let Some(ref mut ctx) = reassembler {
                        for frag in &fragments {
                            ctx.add_fragment(frag.header().sequence(), frag.payload().clone());
                        }
                        
                        // Try to reassemble the fragments
                        match ctx.reassemble() {
                            Ok(data_bytes) => {
                                // Parse reassembled data
                                match Data::from_bytes(&data_bytes) {
                                    Ok(data) => {
                                        // Calculate RTT and data size for statistics
                                        let rtt = start_time.elapsed().as_millis() as u64;
                                        let data_size = data_bytes.len();
                                        
                                        // Update connection statistics
                                        conn_tracker.report_success(rtt, data_size).await;
                                        
                                        debug!("Successfully reassembled {} fragments into data for interest {}", 
                                               fragments.len(), interest.name());
                                        return Ok(data);
                                    },
                                    Err(e) => {
                                        conn_tracker.report_failure(&format!("Parsing error: {}", e)).await;
                                        return Err(crate::error::Error::ParsingError(format!("Failed to parse reassembled data: {}", e)));
                                    }
                                }
                            },
                            Err(e) => {
                                // Reassembly failed
                                conn_tracker.report_failure(&format!("Reassembly error: {}", e)).await;
                                return Err(crate::error::Error::ReassemblyError("Failed to reassemble fragments".to_string()));
                            }
                        }
                    }
                    
                    break;
                }
                
                continue;
            }
            
            // Try to parse as Data if not a fragment
            match Data::from_bytes(&response_bytes) {
                Ok(data) => {
                    // Calculate RTT and data size for statistics
                    let rtt = start_time.elapsed().as_millis() as u64;
                    let data_size = response_bytes.len();
                    
                    // Update connection statistics
                    conn_tracker.report_success(rtt, data_size).await;
                    
                    debug!("Received Data for Interest {}", interest.name());
                    return Ok(data);
                },
                Err(_) => {
                    // Try to parse as NACK
                    match Nack::from_bytes(&response_bytes) {
                        Ok(nack) => {
                            warn!("Received NACK for Interest {}: {:?}", interest.name(), nack.reason());
                            // Convert NackReason to string representation for reporting
                            conn_tracker.report_failure(&format!("NACK: {:?}", nack.reason())).await;
                            return Err(crate::error::Error::Other(format!("NACK: {:?}", nack.reason())));
                        },
                        Err(e) => {
                            error!("Failed to parse response: {}", e);
                            conn_tracker.report_failure(&format!("Parse error: {}", e)).await;
                            return Err(e);
                        }
                    }
                }
            }
        }
        
        // If we got here without returning a valid Data or error, it's a protocol error
        conn_tracker.report_failure("Protocol error").await;
        Err(crate::error::Error::ProtocolError("Unexpected end of stream".to_string()))
    }
    
    /// Stop the QUIC engine
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
        
        // Close all connections
        for conn in self.connections.iter_mut() {
            // Access the connection field directly
            conn.connection.close(0u32.into(), b"server shutting down");
        }
        
        self.connections.clear();
        self.endpoint.close(0u32.into(), b"server shutting down");
        
        Ok(())
    }
}

// Helper function to create a name from a string
fn from_str(s: &str) -> Result<Name> {
    Name::from_uri(s).map_err(|e| crate::error::Error::NameParsing(e.to_string()))
}
