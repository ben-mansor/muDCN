//
// μDCN Fragmentation Module
//
// This module implements the fragmentation and reassembly of NDN data objects
// over QUIC streams, allowing efficient handling of large data transfers.
//

// use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use bytes::{Bytes, BytesMut, BufMut, Buf};
use tracing::{debug, error, info};
use prometheus::{register_counter, register_histogram, Counter, Histogram, HistogramOpts};

use crate::ndn::Data;
use crate::name::Name;
use crate::error::Error;
use crate::Result;

/// Fragment header size in bytes
const FRAGMENT_HEADER_SIZE: usize = 8;

/// Default MTU size in bytes
const DEFAULT_MTU: usize = 1400;

/// Fragment header magic value for identification
const FRAGMENT_MAGIC: u16 = 0x4644; 

// Stub for Histogram 
pub struct DummyHistogram;

impl DummyHistogram {
    pub fn observe(&self, _value: f64) {
        // Do nothing, just a stub
    }
}

// Simplified metrics for compatibility
lazy_static! {
    // Placeholder metrics - these won't actually register with Prometheus
    // but allow the code to compile
    static ref FRAGMENTS_SENT: DummyCounter = DummyCounter {};
    static ref FRAGMENTS_RECEIVED: DummyCounter = DummyCounter {};
    static ref REASSEMBLY_COMPLETED: DummyCounter = DummyCounter {};
    static ref REASSEMBLY_ERRORS: DummyCounter = DummyCounter {};
    static ref FRAGMENT_SIZE_HISTOGRAM: DummyHistogram = DummyHistogram {};
    static ref REASSEMBLY_TIME_HISTOGRAM: DummyHistogram = DummyHistogram {};
}

/// Fragment header format
/// 
/// ```
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Magic (FD)   |F|  Reserved |          Fragment ID          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Sequence Number        |         Total Fragments       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy)]
struct FragmentHeader {
    /// Magic value for identification (FD)
    magic: u16,
    
    /// Final fragment flag (1 bit)
    is_final: bool,
    
    /// Reserved bits (7 bits)
    reserved: u8,
    
    /// Fragment ID to identify the data object (16 bits)
    fragment_id: u16,
    
    /// Sequence number of this fragment (16 bits)
    sequence: u16,
    
    /// Total number of fragments for this data object (16 bits)
    total_fragments: u16,
}

impl FragmentHeader {
    /// Create a new fragment header
    fn new(fragment_id: u16, sequence: u16, total_fragments: u16, is_final: bool) -> Self {
        Self {
            magic: FRAGMENT_MAGIC,
            is_final,
            reserved: 0,
            fragment_id,
            sequence,
            total_fragments,
        }
    }
    
    /// Encode the header to bytes
    fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(FRAGMENT_HEADER_SIZE);
        
        // Magic value
        buf.put_u16(self.magic);
        
        // Flags (1 bit for is_final, 7 bits reserved)
        let flags = if self.is_final { 0x80 } else { 0x00 } | (self.reserved & 0x7F);
        buf.put_u8(flags);
        
        // Fragment ID (high byte)
        buf.put_u8((self.fragment_id >> 8) as u8);
        
        // Fragment ID (low byte)
        buf.put_u8(self.fragment_id as u8);
        
        // Sequence number
        buf.put_u16(self.sequence);
        
        // Total fragments
        buf.put_u16(self.total_fragments);
        
        buf
    }
    
    /// Decode the header from bytes
    fn from_bytes(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < FRAGMENT_HEADER_SIZE {
            return Err(Error::Fragmentation("Buffer too short for fragment header".into()));
        }
        
        // Magic value
        let magic = buf.get_u16();
        if magic != FRAGMENT_MAGIC {
            return Err(Error::Fragmentation(format!("Invalid magic value: {:04x}", magic)));
        }
        
        // Flags
        let flags = buf.get_u8();
        let is_final = (flags & 0x80) != 0;
        let reserved = flags & 0x7F;
        
        // Fragment ID
        let fragment_id_high = buf.get_u8() as u16;
        let fragment_id_low = buf.get_u8() as u16;
        let fragment_id = (fragment_id_high << 8) | fragment_id_low;
        
        // Sequence number
        let sequence = buf.get_u16();
        
        // Total fragments
        let total_fragments = buf.get_u16();
        
        Ok(Self {
            magic,
            is_final,
            reserved,
            fragment_id,
            sequence,
            total_fragments,
        })
    }
}

/// A fragment of an NDN data object
struct Fragment {
    /// Fragment header
    header: FragmentHeader,
    
    /// Fragment payload
    payload: Bytes,
}

impl Fragment {
    /// Create a new fragment
    fn new(header: FragmentHeader, payload: Bytes) -> Self {
        Self { header, payload }
    }
    
    /// Encode the fragment to bytes
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(FRAGMENT_HEADER_SIZE + self.payload.len());
        
        // Header
        buf.extend_from_slice(&self.header.to_bytes());
        
        // Payload
        buf.extend_from_slice(&self.payload);
        
        buf.freeze()
    }
    
    /// Decode a fragment from bytes
    fn from_bytes(buf: &mut Bytes) -> Result<Self> {
        // Parse header
        let header = FragmentHeader::from_bytes(buf)?;
        
        // Remaining bytes are the payload
        let payload = buf.clone();
        
        Ok(Self { header, payload })
    }
}

/// Fragment reassembly context for a single data object
#[derive(Debug)]
struct ReassemblyContext {
    /// Name of the data object
    name: Name,
    
    /// Total number of fragments expected
    total_fragments: u16,
    
    /// Received fragments (sequence number -> payload)
    fragments: HashMap<u16, Bytes>,
    
    /// When reassembly started
    start_time: std::time::Instant,
}

impl ReassemblyContext {
    /// Create a new reassembly context
    fn new(name: Name, total_fragments: u16) -> Self {
        Self {
            name,
            total_fragments,
            fragments: HashMap::new(),
            start_time: std::time::Instant::now(),
        }
    }
    
    /// Add a fragment to the context
    pub fn add_fragment(&mut self, sequence: u16, payload: Bytes) {
        self.fragments.insert(sequence, payload);
    }
    
    /// Check if all fragments have been received
    fn is_complete(&self) -> bool {
        self.fragments.len() == self.total_fragments as usize
    }
    
    /// Reassemble the data object
    pub fn reassemble(&self) -> Result<Bytes> {
        // Check if we have all fragments
        if !self.is_complete() {
            return Err(Error::Fragmentation("Missing fragments".into()));
        }
        
        // Calculate total size
        let total_size: usize = self.fragments.values().map(|b| b.len()).sum();
        
        // Create a buffer for the reassembled object
        let mut reassembled = BytesMut::with_capacity(total_size);
        
        // Add fragments in order
        for i in 0..self.total_fragments {
            if let Some(fragment) = self.fragments.get(&i) {
                reassembled.extend_from_slice(fragment);
            } else {
                return Err(Error::Fragmentation(format!("Missing fragment {}", i)));
            }
        }
        
        let start = std::time::Instant::now();
        let elapsed = start.elapsed();
        
        // Track metrics
        REASSEMBLY_TIME_HISTOGRAM.observe(elapsed.as_secs_f64());
        
        Ok(reassembled.freeze())
    }
}

/// Fragmenter for NDN data objects
#[derive(Debug)]
pub struct Fragmenter {
    /// MTU (Maximum Transmission Unit) in bytes
    mtu: Mutex<usize>,
    
    /// Next fragment ID to assign
    next_fragment_id: Mutex<u16>,
    
    /// Reassembly contexts for received fragments
    reassembly: Mutex<HashMap<u16, ReassemblyContext>>,
    
    /// MTU prediction history - keeps track of recent packet sizes for adaptive MTU
    mtu_history: Mutex<Vec<usize>>,
    
    /// Last time the MTU was adjusted
    last_mtu_adjustment: Mutex<std::time::Instant>,
}

impl Fragmenter {
    /// Create a new fragmenter with the given MTU
    pub fn new(mtu: usize) -> Self {
        Self {
            mtu: Mutex::new(std::cmp::max(mtu, FRAGMENT_HEADER_SIZE + 1)), // Ensure minimum viable MTU
            next_fragment_id: Mutex::new(1),
            reassembly: Mutex::new(HashMap::new()),
            mtu_history: Mutex::new(Vec::with_capacity(100)),  // Keep track of last 100 packet sizes
            last_mtu_adjustment: Mutex::new(std::time::Instant::now()),
        }
    }
    
    /// Create a new fragmenter with the default MTU
    pub fn with_default_mtu() -> Self {
        Self::new(DEFAULT_MTU)
    }
    
    /// Update the MTU
    pub async fn update_mtu(&self, new_mtu: usize) {
        let min_mtu = FRAGMENT_HEADER_SIZE + 1;
        let bounded_mtu = std::cmp::max(new_mtu, min_mtu);
        
        let mut mtu = self.mtu.lock().await;
        *mtu = bounded_mtu;
        
        // Reset MTU history when explicitly updated
        let mut history = self.mtu_history.lock().await;
        history.clear();
        
        // Reset last adjustment time
        let mut last_adjustment = self.last_mtu_adjustment.lock().await;
        *last_adjustment = std::time::Instant::now();
        
        info!("Updated MTU to {} (requested: {})", bounded_mtu, new_mtu);
    }
    
    /// Predict optimal MTU based on recent packet sizes
    pub async fn predict_optimal_mtu(&self) -> usize {
        let history = self.mtu_history.lock().await;
        
        if history.is_empty() {
            // No history, return current MTU
            return *self.mtu.lock().await;
        }
        
        // Calculate the 95th percentile of packet sizes
        let mut sizes = history.clone();
        sizes.sort_unstable();
        
        let p95_index = (sizes.len() as f64 * 0.95) as usize;
        let p95_size = sizes.get(p95_index).copied().unwrap_or_else(|| sizes[sizes.len() - 1]);
        
        // Add overhead and round up to nearest 100
        let predicted_mtu = ((p95_size + FRAGMENT_HEADER_SIZE + 50) / 100) * 100;
        
        // Ensure minimum MTU
        std::cmp::max(predicted_mtu, FRAGMENT_HEADER_SIZE + 100)
    }
    
    /// Adapt MTU based on recent traffic patterns
    pub async fn adapt_mtu(&self) {
        let now = std::time::Instant::now();
        let last_adjustment = *self.last_mtu_adjustment.lock().await;
        
        // Only adapt MTU if it's been at least 30 seconds since the last adjustment
        if now.duration_since(last_adjustment).as_secs() < 30 {
            return;
        }
        
        // Get current and predicted MTU
        let current_mtu = *self.mtu.lock().await;
        let predicted_mtu = self.predict_optimal_mtu().await;
        
        // Only update if the difference is significant (>10%)
        if (current_mtu as f64 * 0.9 > predicted_mtu as f64) || 
           (current_mtu as f64 * 1.1 < predicted_mtu as f64) {
            self.update_mtu(predicted_mtu).await;
            debug!("Adapted MTU from {} to {}", current_mtu, predicted_mtu);
        }
    }
    
    /// Get the current MTU
    pub async fn mtu(&self) -> usize {
        *self.mtu.lock().await
    }
    
    /// Fragment a data object into multiple smaller fragments
    pub async fn fragment(&self, data: &Data) -> Vec<Bytes> {
        // Get the name and serialized data
        let name = data.name().clone();
        let data_bytes = data.to_bytes();
        
        // Record original packet size for MTU adaptation
        {
            let mut history = self.mtu_history.lock().await;
            history.push(data_bytes.len());
            
            // Keep history at a reasonable size
            if history.len() > 100 {
                history.remove(0);
            }
        }
        
        // Maybe adapt MTU based on traffic patterns
        self.adapt_mtu().await;
        
        // Get the current MTU
        let mtu = self.mtu().await;
        
        // Calculate the maximum payload size per fragment
        let max_payload = mtu - FRAGMENT_HEADER_SIZE;
        
        // Calculate the number of fragments needed
        let total_fragments = (data_bytes.len() + max_payload - 1) / max_payload;
        
        // Get the next fragment ID
        let fragment_id = {
            let mut next_id = self.next_fragment_id.lock().await;
            let id = *next_id;
            *next_id = next_id.wrapping_add(1);
            id
        };
        
        debug!("Fragmenting data for {} into {} fragments (mtu: {}, id: {}, data size: {})",
            name, total_fragments, mtu, fragment_id, data_bytes.len());
        
        // Create fragments
        let mut fragments = Vec::with_capacity(total_fragments);
        
        for i in 0..total_fragments {
            // Calculate the start and end of this fragment's payload
            let start = i * max_payload;
            let end = std::cmp::min(start + max_payload, data_bytes.len());
            
            // Create the fragment header
            let header = FragmentHeader::new(
                fragment_id,
                i as u16,
                total_fragments as u16,
                i == total_fragments - 1
            );
            
            // Extract the payload for this fragment
            let payload = data_bytes.slice(start..end);
            
            // Record fragment size
            FRAGMENT_SIZE_HISTOGRAM.observe(payload.len() as f64);
            
            // Create the fragment
            let fragment = Fragment::new(header, payload);
            
            // Add to the list of fragments
            fragments.push(fragment.to_bytes());
            
            // Update metrics
            FRAGMENTS_SENT.inc();
        }
        
        fragments
    }
    
    /// Process a received fragment and reassemble if complete
    pub async fn process_fragment(&self, fragment_bytes: Bytes) -> Result<Option<Data>> {
        let mut bytes = fragment_bytes.clone();
        
        // Parse the fragment
        let fragment = match Fragment::from_bytes(&mut bytes) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to parse fragment: {}", e);
                return Err(e);
            }
        };
        
        // Update metrics
        FRAGMENTS_RECEIVED.inc();
        
        let header = fragment.header;
        debug!("Received fragment {}/{} (id: {})", 
            header.sequence, header.total_fragments, header.fragment_id);
        
        // Get or create the reassembly context
        let mut reassembly = self.reassembly.lock().await;
        
        let context = if let Some(ctx) = reassembly.get_mut(&header.fragment_id) {
            ctx
        } else {
            // Create a new context with a dummy name for now
            // We'll update it when we reassemble the data
            let ctx = ReassemblyContext::new(
                Name::from("/tmp"), // Temporary name
                header.total_fragments
            );
            reassembly.insert(header.fragment_id, ctx);
            reassembly.get_mut(&header.fragment_id).unwrap()
        };
        
        // Add the fragment to the context
        context.add_fragment(header.sequence, fragment.payload);
        
        // Check if we have all fragments
        if context.is_complete() {
            debug!("Completed reassembly for fragment id {}", header.fragment_id);
            
            // Reassemble the data
            let data_bytes = match context.reassemble() {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to reassemble data: {}", e);
                    REASSEMBLY_ERRORS.inc();
                    return Err(e);
                }
            };
            
            // Parse the data
            let data = match Data::from_bytes(&data_bytes) {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to parse reassembled data: {}", e);
                    REASSEMBLY_ERRORS.inc();
                    return Err(e);
                }
            };
            
            // Remove the context
            reassembly.remove(&header.fragment_id);
            
            // Update metrics
            REASSEMBLY_COMPLETED.inc();
            
            Ok(Some(data))
        } else {
            // Still waiting for more fragments
            Ok(None)
        }
    }
    
    /// Clean up stale reassembly contexts
    pub async fn cleanup_stale(&self, max_age_secs: u64) -> usize {
        let mut reassembly = self.reassembly.lock().await;
        
        let now = std::time::Instant::now();
        let stale: Vec<u16> = reassembly
            .iter()
            .filter(|(_, ctx)| now.duration_since(ctx.start_time).as_secs() > max_age_secs)
            .map(|(id, _)| *id)
            .collect();
        
        let count = stale.len();
        for id in stale {
            reassembly.remove(&id);
        }
        
        if count > 0 {
            debug!("Cleaned up {} stale reassembly contexts", count);
        }
        
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndn::Data;
    
    #[cfg_attr(feature = "tokio-test", tokio::test)]
    #[cfg_attr(not(feature = "tokio-test"), test)]
    async fn test_fragment_header() {
        // Create a header
        let header = FragmentHeader::new(0x1234, 0x5678, 0x9abc, true);
        
        // Encode to bytes
        let bytes = header.to_bytes();
        
        // Check size
        assert_eq!(bytes.len(), FRAGMENT_HEADER_SIZE);
        
        // Decode back
        let mut buf = bytes.freeze();
        let decoded = FragmentHeader::from_bytes(&mut buf).unwrap();
        
        // Check values
        assert_eq!(decoded.magic, FRAGMENT_MAGIC);
        assert_eq!(decoded.is_final, true);
        assert_eq!(decoded.fragment_id, 0x1234);
        assert_eq!(decoded.sequence, 0x5678);
        assert_eq!(decoded.total_fragments, 0x9abc);
    }
    
    #[cfg_attr(feature = "tokio-test", tokio::test)]
    #[cfg_attr(not(feature = "tokio-test"), test)]
    async fn test_fragmentation_reassembly() {
        // Create a fragmenter
        let fragmenter = Fragmenter::new(100); // Small MTU for testing
        
        // Create test data
        let name = Name::from_uri("/test/data").unwrap();
        let content = vec![0u8; 250]; // Larger than the MTU
        let data = Data::new(name, content);
        
        // Fragment the data
        let fragments = fragmenter.fragment(&data).await;
        
        // Should be at least 3 fragments (250 / (100 - 8) = ~3)
        assert!(fragments.len() >= 3);
        
        // Process the fragments in order
        let mut reassembled_data = None;
        for fragment in fragments {
            let result = fragmenter.process_fragment(fragment).await.unwrap();
            if result.is_some() {
                reassembled_data = result;
            }
        }
        
        // Should have reassembled the data
        assert!(reassembled_data.is_some());
        
        // Check that the data matches
        let reassembled = reassembled_data.unwrap();
        assert_eq!(reassembled.name(), data.name());
        assert_eq!(reassembled.content(), data.content());
    }
}

// Add implementation of methods needed for fragment reassembly
impl Fragmenter {
    /// Create a new reassembly context for receiving fragments
    pub fn new_reassembly_context(&self, fragment_id: u16, total_fragments: u16) -> ReassemblyContext {
        // Create a temporary name for the reassembly context
        // Start with an empty name
        let mut name = Name::new();
        // Add components as needed to identify the fragment
        let fragment_name = format!("/fragment/{}", fragment_id);
        
        // Create the context
        let context = ReassemblyContext::new(name, total_fragments);
        
        // Clone and return the context
        context
    }
}
