//
// μDCN Network Interface Module
//
// This module implements network interface management and discovery
// for the μDCN transport layer.
//

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, info};

use crate::error::Error;
use crate::Result;

/// Network protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// UDP protocol
    Udp,
    /// Direct Ethernet (no IP)
    Ethernet,
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface name
    pub name: String,
    
    /// Interface index
    pub index: u32,
    
    /// Interface MTU
    pub mtu: u32,
    
    /// Interface addresses
    pub addresses: Vec<IpAddr>,
    
    /// Interface is up
    pub is_up: bool,
    
    /// Interface supports multicast
    pub is_multicast: bool,
}

/// Face for communicating with other nodes
#[derive(Debug, Clone)]
pub struct Face {
    /// Face ID
    pub id: u32,
    
    /// Remote address
    pub remote: SocketAddr,
    
    /// Local address
    pub local: SocketAddr,
    
    /// Protocol
    pub protocol: Protocol,
    
    /// Associated interface
    pub interface: Option<String>,
    
    /// Face is permanent (not automatically removed)
    pub is_permanent: bool,
    
    /// Face creation time
    pub created_at: std::time::Instant,
    
    /// Last activity time
    pub last_activity: std::time::Instant,
    
    /// Bytes sent
    pub bytes_sent: u64,
    
    /// Bytes received
    pub bytes_received: u64,
    
    /// Interests sent
    pub interests_sent: u64,
    
    /// Interests received
    pub interests_received: u64,
    
    /// Data sent
    pub data_sent: u64,
    
    /// Data received
    pub data_received: u64,
}

impl Face {
    /// Create a new face
    pub fn new(
        id: u32,
        remote: SocketAddr,
        local: SocketAddr,
        protocol: Protocol,
        interface: Option<String>,
        is_permanent: bool,
    ) -> Self {
        let now = std::time::Instant::now();
        
        Self {
            id,
            remote,
            local,
            protocol,
            interface,
            is_permanent,
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            interests_sent: 0,
            interests_received: 0,
            data_sent: 0,
            data_received: 0,
        }
    }
    
    /// Update face activity
    pub fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }
    
    /// Record bytes sent
    pub fn record_bytes_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.update_activity();
    }
    
    /// Record bytes received
    pub fn record_bytes_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.update_activity();
    }
    
    /// Record interest sent
    pub fn record_interest_sent(&mut self) {
        self.interests_sent += 1;
        self.update_activity();
    }
    
    /// Record interest received
    pub fn record_interest_received(&mut self) {
        self.interests_received += 1;
        self.update_activity();
    }
    
    /// Record data sent
    pub fn record_data_sent(&mut self) {
        self.data_sent += 1;
        self.update_activity();
    }
    
    /// Record data received
    pub fn record_data_received(&mut self) {
        self.data_received += 1;
        self.update_activity();
    }
    
    /// Check if the face is idle
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        !self.is_permanent && self.last_activity.elapsed() > idle_timeout
    }
}

/// Interface manager for handling network interfaces and faces
pub struct InterfaceManager {
    /// Network interfaces
    interfaces: Arc<RwLock<HashMap<String, InterfaceInfo>>>,
    
    /// Faces
    faces: Arc<RwLock<HashMap<u32, Face>>>,
    
    /// Next face ID
    next_face_id: Arc<RwLock<u32>>,
    
    /// Idle timeout for faces
    idle_timeout: Duration,
}

impl InterfaceManager {
    /// Create a new interface manager
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            faces: Arc::new(RwLock::new(HashMap::new())),
            next_face_id: Arc::new(RwLock::new(1)),
            idle_timeout,
        }
    }
    
    /// Start the interface manager
    pub async fn start(&self) -> Result<()> {
        // Discover interfaces
        self.discover_interfaces().await?;
        
        // Start the cleanup task
        self.start_cleanup_task().await;
        
        Ok(())
    }
    
    /// Start the face cleanup task
    async fn start_cleanup_task(&self) {
        let idle_timeout = self.idle_timeout;
        
        // Clone the Arc containing the RwLock
        let faces = Arc::clone(&self.faces);
        
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Clean up idle faces
                let mut faces_to_remove = Vec::new();
                
                {
                    let mut faces_lock = faces.write().await;
                    
                    for (id, face) in faces_lock.iter() {
                        if face.is_idle(idle_timeout) {
                            faces_to_remove.push(*id);
                        }
                    }
                    
                    // Remove idle faces
                    for id in &faces_to_remove {
                        if let Some(face) = faces_lock.remove(id) {
                            info!("Removed idle face {} to {}", id, face.remote);
                        }
                    }
                }
                
                // Log cleanup info
                if !faces_to_remove.is_empty() {
                    debug!("Cleaned up {} idle faces", faces_to_remove.len());
                }
            }
        });
    }
    
    /// Discover network interfaces
    pub async fn discover_interfaces(&self) -> Result<()> {
        info!("Discovering network interfaces");
        
        // For this prototype, we'll just add some dummy interfaces
        // In a real implementation, this would discover actual interfaces
        let mut interfaces = self.interfaces.write().await;
        
        // Add loopback interface
        interfaces.insert("lo".to_string(), InterfaceInfo {
            name: "lo".to_string(),
            index: 1,
            mtu: 65535,
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ],
            is_up: true,
            is_multicast: false,
        });
        
        // Add eth0 interface
        interfaces.insert("eth0".to_string(), InterfaceInfo {
            name: "eth0".to_string(),
            index: 2,
            mtu: 1500,
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            ],
            is_up: true,
            is_multicast: true,
        });
        
        info!("Discovered {} interfaces", interfaces.len());
        
        Ok(())
    }
    
    /// Create a new face
    pub async fn create_face(
        &self,
        remote: SocketAddr,
        local: SocketAddr,
        protocol: Protocol,
        interface: Option<String>,
        is_permanent: bool,
    ) -> Result<Arc<RwLock<Face>>> {
        // Get a new face ID
        let id = {
            let mut next_id = self.next_face_id.write().await;
            let id = *next_id;
            *next_id += 1;
            id
        };
        
        // Create the face
        let face = Face::new(id, remote, local, protocol, interface.clone(), is_permanent);
        
        // Log face creation
        info!("Created face {} to {} via {:?}", id, remote, protocol);
        
        // Store the face
        {
            let mut faces = self.faces.write().await;
            faces.insert(id, face.clone());
        }
        
        // Return an Arc-wrapped RwLock containing the face
        Ok(Arc::new(RwLock::new(face)))
    }
    
    /// Get a face by ID
    pub async fn get_face(&self, id: u32) -> Option<Arc<RwLock<Face>>> {
        let faces = self.faces.read().await;
        
        faces.get(&id).map(|face| {
            let face_clone = face.clone();
            Arc::new(RwLock::new(face_clone))
        })
    }
    
    /// Get all faces
    pub async fn get_faces(&self) -> Vec<Arc<RwLock<Face>>> {
        let faces = self.faces.read().await;
        
        faces
            .values()
            .map(|face| {
                let face_clone = face.clone();
                Arc::new(RwLock::new(face_clone))
            })
            .collect()
    }
    
    /// Remove a face
    pub async fn remove_face(&self, id: u32) -> Result<()> {
        let mut faces = self.faces.write().await;
        
        if let Some(face) = faces.remove(&id) {
            info!("Removed face {} to {}", id, face.remote);
            Ok(())
        } else {
            Err(Error::NotFound(format!("Face not found: {}", id)))
        }
    }
    
    /// Get an interface by name
    pub async fn get_interface(&self, name: &str) -> Option<InterfaceInfo> {
        let interfaces = self.interfaces.read().await;
        interfaces.get(name).cloned()
    }
    
    /// Get all interfaces
    pub async fn get_interfaces(&self) -> Vec<InterfaceInfo> {
        let interfaces = self.interfaces.read().await;
        interfaces.values().cloned().collect()
    }
    
    /// Find the best MTU for a face
    pub async fn find_best_mtu(&self, face_id: u32) -> Result<u32> {
        let faces = self.faces.read().await;
        
        if let Some(face) = faces.get(&face_id) {
            if let Some(interface_name) = &face.interface {
                let interfaces = self.interfaces.read().await;
                
                if let Some(interface) = interfaces.get(interface_name) {
                    return Ok(interface.mtu);
                }
            }
            
            // Default MTU
            Ok(1400)
        } else {
            Err(Error::NotFound(format!("Face not found: {}", face_id)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_interface_manager() {
        // Create a manager with a short idle timeout
        let manager = InterfaceManager::new(Duration::from_secs(1));
        
        // Discover interfaces
        let result = manager.discover_interfaces().await;
        assert!(result.is_ok());
        
        // Check that interfaces were discovered
        let interfaces = manager.get_interfaces().await;
        assert!(!interfaces.is_empty());
        
        // Create a face
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6363);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6364);
        
        let face = manager.create_face(
            remote,
            local,
            Protocol::Udp,
            Some("lo".to_string()),
            false, // not permanent
        ).await;
        
        assert!(face.is_ok());
        
        // Get the face
        let face_id = face.unwrap().read().await.id;
        let retrieved_face = manager.get_face(face_id).await;
        
        assert!(retrieved_face.is_some());
    }
}
