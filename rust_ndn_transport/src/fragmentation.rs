//
// μDCN Fragmentation Module
//
// This module implements the fragmentation and reassembly of NDN data objects
// over QUIC streams, allowing efficient handling of large data transfers.
//

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use bytes::{Bytes, BytesMut, BufMut, Buf};
use tracing::{debug, error, info, trace, warn};
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
const FRAGMENT_MAGIC: u16 = 0x4644; // 'FD' in ASCII

// Prometheus metrics
lazy_static::lazy_static! {
    static ref FRAGMENTS_SENT: Counter = register_counter!(
        "udcn_fragments_sent_total", 
        "Total number of fragments sent"
    ).unwrap();
    
    static ref FRAGMENTS_RECEIVED: Counter = register_counter!(
        "udcn_fragments_received_total", 
        "Total number of fragments received"
    ).unwrap();
    
    static ref REASSEMBLY_COMPLETED: Counter = register_counter!(
        "udcn_reassembly_completed_total", 
        "Total number of successful reassemblies"
    ).unwrap();
    
    static ref REASSEMBLY_ERRORS: Counter = register_counter!(
        "udcn_reassembly_errors_total", 
        "Total number of reassembly errors"
    ).unwrap();
    
    static ref FRAGMENT_SIZE_HISTOGRAM: Histogram = register_histogram!(
        HistogramOpts::new(
            "udcn_fragment_size_bytes", 
            "Fragment size distribution in bytes"
        ).buckets(vec![100.0, 500.0, 1000.0, 1400.0, 2000.0, 4000.0, 8000.0])
    ).unwrap();
    
    static ref REASSEMBLY_TIME_HISTOGRAM: Histogram = register_histogram!(
        HistogramOpts::new(
            "udcn_reassembly_time_seconds", 
            "Time taken to reassemble fragments"
        ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
    ).unwrap();
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
    fn add_fragment(&mut self, sequence: u16, payload: Bytes) {
        self.fragments.insert(sequence, payload);
    }
    
    /// Check if all fragments have been received
    fn is_complete(&self) -> bool {
        self.fragments.len() == self.total_fragments as usize
    }
    
    /// Reassemble the data object
    fn reassemble(&self) -> Result<Bytes> {
        if !self.is_complete() {
            return Err(Error::Fragmentation("Incomplete reassembly".into()));
        }
        
        // Calculate total size
        let total_size: usize = self.fragments.values().map(|f| f.len()).sum();
        
        // Allocate buffer for the reassembled data
        let mut buf = BytesMut::with_capacity(total_size);
        
        // Add fragments in order
        for i in 0..self.total_fragments {
            if let Some(fragment) = self.fragments.get(&i) {
                buf.extend_from_slice(fragment);
            } else {
                return Err(Error::Fragmentation(format!("Missing fragment {}", i)));
            }
        }
        
        // Record reassembly time
        let elapsed = self.start_time.elapsed();
        REASSEMBLY_TIME_HISTOGRAM.observe(elapsed.as_secs_f64());
        
        Ok(buf.freeze())
    }
}

/// Fragmenter for NDN data objects
pub struct Fragmenter {
    /// MTU size in bytes
    mtu: Mutex<usize>,
    
    /// Next fragment ID
    next_fragment_id: Mutex<u16>,
    
    /// Reassembly contexts for received fragments
    reassembly: Mutex<HashMap<u16, ReassemblyContext>>,
}

impl Fragmenter {
    /// Create a new fragmenter with the given MTU
    pub fn new(mtu: usize) -> Self {
        Self {
            mtu: Mutex::new(mtu),
            next_fragment_id: Mutex::new(0),
            reassembly: Mutex::new(HashMap::new()),
        }
    }
    
    /// Create a new fragmenter with the default MTU
    pub fn with_default_mtu() -> Self {
        Self::new(DEFAULT_MTU)
    }
    
    /// Update the MTU
    pub async fn update_mtu(&self, new_mtu: usize) {
        let mut mtu = self.mtu.lock().await;
        *mtu = new_mtu;
        info!("Updated MTU to {}", new_mtu);
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
        
        debug!("Fragmenting data for {} into {} fragments (mtu: {}, id: {})",
            name, total_fragments, mtu, fragment_id);
        
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
    
    #[tokio::test]
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
    
    #[tokio::test]
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
