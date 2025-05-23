//
// μDCN NDN Protocol Implementation
//
// This module implements the core NDN protocol types and operations.
//

use std::fmt;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::Error;
use crate::name::Name;
use crate::Result;

/// NDN TLV types
pub mod tlv_type {
    pub const INTEREST: u8 = 0x05;
    pub const DATA: u8 = 0x06;
    pub const NACK: u8 = 0x03;
    pub const NAME: u8 = 0x07;
    pub const NAME_COMPONENT: u8 = 0x08;
    pub const SELECTORS: u8 = 0x09;
    pub const NONCE: u8 = 0x0A;
    pub const INTEREST_LIFETIME: u8 = 0x0C;
    pub const META_INFO: u8 = 0x14;
    pub const CONTENT: u8 = 0x15;
    pub const SIGNATURE_INFO: u8 = 0x16;
    pub const SIGNATURE_VALUE: u8 = 0x17;
    pub const NACK_REASON: u8 = 0x0F;
}

/// An NDN Interest packet
#[derive(Clone)]
pub struct Interest {
    /// The name being requested
    name: Name,
    
    /// Interest lifetime in milliseconds
    lifetime_ms: u64,
    
    /// Random nonce for loop detection
    nonce: u32,
    
    /// Whether the interest can be satisfied from cache
    can_be_prefix: bool,
    
    /// Whether the interest must be forwarded
    must_be_fresh: bool,
}

impl Interest {
    /// Create a new Interest packet for the given name
    pub fn new(name: Name) -> Self {
        Self {
            name,
            lifetime_ms: 4000, // Default 4 seconds
            nonce: rand::random(),
            can_be_prefix: false,
            must_be_fresh: true,
        }
    }
    
    /// Set the Interest lifetime
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime_ms = lifetime.as_millis() as u64;
        self
    }
    
    /// Set the can_be_prefix flag
    pub fn can_be_prefix(mut self, can_be_prefix: bool) -> Self {
        self.can_be_prefix = can_be_prefix;
        self
    }
    
    /// Set the must_be_fresh flag
    pub fn must_be_fresh(mut self, must_be_fresh: bool) -> Self {
        self.must_be_fresh = must_be_fresh;
        self
    }
    
    /// Get the name of the Interest
    pub fn name(&self) -> &Name {
        &self.name
    }
    
    /// Get the Interest lifetime
    pub fn get_lifetime(&self) -> Duration {
        Duration::from_millis(self.lifetime_ms)
    }
    
    /// Get the Interest nonce
    pub fn nonce(&self) -> u32 {
        self.nonce
    }
    
    /// Encode the Interest as TLV
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        // Compute the size of the Interest
        let name_tlv = self.name.to_tlv();
        let name_size = name_tlv.len();
        
        // nonce (4 bytes)
        let nonce_size = 2 + 4; // type + length + value
        
        // lifetime (variable, but we'll use 2 bytes)
        let lifetime_size = 2 + 2; // type + length + value
        
        // Interest TLV
        buf.put_u8(tlv_type::INTEREST);
        buf.put_u8((name_size + nonce_size + lifetime_size) as u8);
        
        // Name
        buf.extend_from_slice(&name_tlv);
        
        // Nonce
        buf.put_u8(tlv_type::NONCE);
        buf.put_u8(4); // 4 bytes
        buf.put_u32(self.nonce);
        
        // Interest lifetime
        buf.put_u8(tlv_type::INTEREST_LIFETIME);
        buf.put_u8(2); // 2 bytes
        buf.put_u16(self.lifetime_ms as u16);
        
        buf.freeze()
    }
    
    /// Decode an Interest from TLV
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut bytes = Bytes::copy_from_slice(buf);
        
        // Check if we have at least 2 bytes (type + length)
        if bytes.len() < 2 {
            return Err(Error::TlvParsing("Buffer too short for Interest TLV".into()));
        }
        
        // Type
        let typ = bytes.get_u8();
        if typ != tlv_type::INTEREST {
            return Err(Error::TlvParsing(format!("Unexpected TLV type: {}", typ)));
        }
        
        // Length
        let len = bytes.get_u8() as usize;
        
        // Check if we have enough bytes for the value
        if bytes.len() < len {
            return Err(Error::TlvParsing("Buffer too short for Interest value".into()));
        }
        
        // Value (Name + Nonce + Lifetime)
        let mut value = bytes.split_to(len);
        
        // Parse name
        let name = Name::from_tlv(&mut value)?;
        
        // Default values
        let mut lifetime_ms = 4000;
        let mut nonce = 0;
        let can_be_prefix = false;
        let must_be_fresh = true;
        
        // Parse remaining TLVs
        while value.has_remaining() {
            // Check if we have at least 2 bytes (type + length)
            if value.len() < 2 {
                break;
            }
            
            let typ = value.get_u8();
            let len = value.get_u8() as usize;
            
            // Check if we have enough bytes for the value
            if value.len() < len {
                break;
            }
            
            match typ {
                tlv_type::NONCE => {
                    if len == 4 {
                        nonce = value.get_u32();
                    } else {
                        value.advance(len);
                    }
                }
                tlv_type::INTEREST_LIFETIME => {
                    if len == 2 {
                        lifetime_ms = value.get_u16() as u64;
                    } else {
                        value.advance(len);
                    }
                }
                _ => {
                    // Skip unknown TLV
                    value.advance(len);
                }
            }
        }
        
        Ok(Self {
            name,
            lifetime_ms,
            nonce,
            can_be_prefix,
            must_be_fresh,
        })
    }
}

impl fmt::Debug for Interest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interest")
            .field("name", &self.name)
            .field("lifetime_ms", &self.lifetime_ms)
            .field("nonce", &format!("{:08x}", self.nonce))
            .field("can_be_prefix", &self.can_be_prefix)
            .field("must_be_fresh", &self.must_be_fresh)
            .finish()
    }
}

impl fmt::Display for Interest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Interest({})", self.name)
    }
}

/// Content type for NDN Data packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    Blob = 0,
    Link = 1, 
    Key = 2,
    Cert = 3,
    Manifest = 4,
    PrefixAnn = 5,
    Custom(u8),
}

impl From<u8> for ContentType {
    fn from(val: u8) -> Self {
        match val {
            0 => ContentType::Blob,
            1 => ContentType::Link,
            2 => ContentType::Key,
            3 => ContentType::Cert,
            4 => ContentType::Manifest,
            5 => ContentType::PrefixAnn,
            n => ContentType::Custom(n),
        }
    }
}

/// An NDN Data packet
#[derive(Clone)]
pub struct Data {
    /// The name of the data
    name: Name,
    
    /// The content type
    content_type: ContentType,
    
    /// The content data
    content: Bytes,
    
    /// Fresh period in milliseconds
    fresh_period_ms: u64,
    
    /// Signature info placeholder
    // In a real implementation, this would be more complex
    signature_info: Vec<u8>,
    
    /// Signature value placeholder
    // In a real implementation, this would use proper crypto
    signature_value: Vec<u8>,
}

impl Data {
    /// Create a new Data packet for the given name and content
    pub fn new(name: Name, content: impl Into<Bytes>) -> Self {
        Self {
            name,
            content_type: ContentType::Blob,
            content: content.into(),
            fresh_period_ms: 3600000, // Default 1 hour
            signature_info: vec![0], // Placeholder
            signature_value: vec![0], // Placeholder
        }
    }
    
    /// Set the content type
    pub fn content_type(mut self, content_type: ContentType) -> Self {
        self.content_type = content_type;
        self
    }
    
    /// Set the fresh period
    pub fn fresh_period(mut self, fresh_period: Duration) -> Self {
        self.fresh_period_ms = fresh_period.as_millis() as u64;
        self
    }
    
    /// Get the name of the Data
    pub fn name(&self) -> &Name {
        &self.name
    }
    
    /// Get the content of the Data
    pub fn content(&self) -> &Bytes {
        &self.content
    }
    
    /// Get the content type
    pub fn get_content_type(&self) -> ContentType {
        self.content_type
    }
    
    /// Get the fresh period
    pub fn get_fresh_period(&self) -> Duration {
        Duration::from_millis(self.fresh_period_ms)
    }
    
    /// Sign the Data packet (placeholder)
    /// In a real implementation, this would use proper crypto
    pub fn sign(mut self, _key: &[u8]) -> Self {
        // Placeholder for signature logic
        self.signature_info = vec![1]; // Dummy value
        self.signature_value = vec![2]; // Dummy value
        self
    }
    
    /// Encode the Data as TLV
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        // Compute the size of the Data
        let name_tlv = self.name.to_tlv();
        let name_size = name_tlv.len();
        
        // MetaInfo (content type + fresh period)
        let meta_info_size = 2 + 3; // type + length + value
        
        // Content
        let content_size = 2 + self.content.len(); // type + length + value
        
        // Signature info
        let sig_info_size = 2 + self.signature_info.len(); // type + length + value
        
        // Signature value
        let sig_value_size = 2 + self.signature_value.len(); // type + length + value
        
        // Data TLV
        buf.put_u8(tlv_type::DATA);
        buf.put_u8((name_size + meta_info_size + content_size + sig_info_size + sig_value_size) as u8);
        
        // Name
        buf.extend_from_slice(&name_tlv);
        
        // MetaInfo
        buf.put_u8(tlv_type::META_INFO);
        buf.put_u8(1); // 1 byte
        // Convert content type to u8 safely\n        let content_type_value = match self.content_type {\n            ContentType::Blob => 0,\n            ContentType::Link => 1,\n            ContentType::Key => 2,\n            ContentType::Cert => 3,\n            ContentType::Manifest => 4,\n            ContentType::PrefixAnn => 5,\n            ContentType::Custom(n) => n,\n        };\n        buf.put_u8(content_type_value);
        
        // Content
        buf.put_u8(tlv_type::CONTENT);
        buf.put_u8(self.content.len() as u8);
        buf.extend_from_slice(&self.content);
        
        // Signature info
        buf.put_u8(tlv_type::SIGNATURE_INFO);
        buf.put_u8(self.signature_info.len() as u8);
        buf.extend_from_slice(&self.signature_info);
        
        // Signature value
        buf.put_u8(tlv_type::SIGNATURE_VALUE);
        buf.put_u8(self.signature_value.len() as u8);
        buf.extend_from_slice(&self.signature_value);
        
        buf.freeze()
    }
    
    /// Decode a Data packet from TLV
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut bytes = Bytes::copy_from_slice(buf);
        
        // Check if we have at least 2 bytes (type + length)
        if bytes.len() < 2 {
            return Err(Error::TlvParsing("Buffer too short for Data TLV".into()));
        }
        
        // Type
        let typ = bytes.get_u8();
        if typ != tlv_type::DATA {
            return Err(Error::TlvParsing(format!("Unexpected TLV type: {}", typ)));
        }
        
        // Length
        let len = bytes.get_u8() as usize;
        
        // Check if we have enough bytes for the value
        if bytes.len() < len {
            return Err(Error::TlvParsing("Buffer too short for Data value".into()));
        }
        
        // Value (Name + MetaInfo + Content + Signature)
        let mut value = bytes.split_to(len);
        
        // Parse name
        let name = Name::from_tlv(&mut value)?;
        
        // Default values
        let mut content_type = ContentType::Blob;
        let mut content = Bytes::new();
        let fresh_period_ms = 3600000; // 1 hour
        let mut signature_info = vec![];
        let mut signature_value = vec![];
        
        // Parse remaining TLVs
        while value.has_remaining() {
            // Check if we have at least 2 bytes (type + length)
            if value.len() < 2 {
                break;
            }
            
            let typ = value.get_u8();
            let len = value.get_u8() as usize;
            
            // Check if we have enough bytes for the value
            if value.len() < len {
                break;
            }
            
            match typ {
                tlv_type::META_INFO => {
                    if len > 0 {
                        content_type = ContentType::from(value.get_u8());
                        value.advance(len - 1);
                    }
                }
                tlv_type::CONTENT => {
                    content = value.split_to(len);
                }
                tlv_type::SIGNATURE_INFO => {
                    signature_info = value.split_to(len).to_vec();
                }
                tlv_type::SIGNATURE_VALUE => {
                    signature_value = value.split_to(len).to_vec();
                }
                _ => {
                    // Skip unknown TLV
                    value.advance(len);
                }
            }
        }
        
        Ok(Self {
            name,
            content_type,
            content,
            fresh_period_ms,
            signature_info,
            signature_value,
        })
    }
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Data")
            .field("name", &self.name)
            .field("content_type", &self.content_type)
            .field("content_size", &self.content.len())
            .field("fresh_period_ms", &self.fresh_period_ms)
            .finish()
    }
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Data({}, {} bytes)", self.name, self.content.len())
    }
}

/// NACK reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NackReason {
    /// No route to destination
    NoRoute = 100,
    /// Congestion
    Congestion = 101,
    /// Duplicate
    Duplicate = 102,
    /// No resource available
    NoResource = 200,
    /// Not authorized
    NotAuth = 300,
    /// Other reason with code
    Other = 900,
}

impl From<u16> for NackReason {
    fn from(val: u16) -> Self {
        match val {
            100 => NackReason::NoRoute,
            101 => NackReason::Congestion,
            102 => NackReason::Duplicate,
            200 => NackReason::NoResource,
            300 => NackReason::NotAuth,
            _ => NackReason::Other,
        }
    }
}

/// An NDN Negative Acknowledgment (NACK) packet
#[derive(Clone)]
pub struct Nack {
    /// The Interest being NACK'd
    interest: Interest,
    
    /// Reason for the NACK
    reason: NackReason,
    
    /// Optional text message
    message: String,
}

impl Nack {
    /// Create a new NACK for the given Interest
    pub fn new(interest: Interest, reason: NackReason) -> Self {
        Self {
            interest,
            reason,
            message: String::new(),
        }
    }
    
    /// Create a NACK from an Interest with a text message
    pub fn from_interest(interest: Interest, message: String) -> Self {
        Self {
            interest,
            reason: NackReason::NoRoute,
            message,
        }
    }
    
    /// Get the Interest that was NACK'd
    pub fn interest(&self) -> &Interest {
        &self.interest
    }
    
    /// Get the NACK reason
    pub fn reason(&self) -> NackReason {
        self.reason
    }
    
    /// Get the NACK message
    pub fn message(&self) -> &str {
        &self.message
    }
    
    /// Encode the NACK as TLV
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        // Interest TLV
        let interest_tlv = self.interest.to_bytes();
        
        // Reason TLV
        let reason_size = 2 + 2; // type + length + value
        
        // Message TLV (if non-empty)
        let message_size = if self.message.is_empty() {
            0
        } else {
            2 + self.message.len() // type + length + value
        };
        
        // NACK TLV
        buf.put_u8(tlv_type::NACK);
        buf.put_u8((interest_tlv.len() + reason_size + message_size) as u8);
        
        // Interest
        buf.extend_from_slice(&interest_tlv);
        
        // Reason
        buf.put_u8(tlv_type::NACK_REASON);
        buf.put_u8(2); // 2 bytes
        buf.put_u16(self.reason as u16);
        
        // Message (if non-empty)
        if !self.message.is_empty() {
            buf.put_u8(0x10); // Custom TLV for message
            buf.put_u8(self.message.len() as u8);
            buf.extend_from_slice(self.message.as_bytes());
        }
        
        buf.freeze()
    }
    
    /// Decode a NACK from TLV
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        // Simplified implementation - in a real system this would be more robust
        
        let mut bytes = Bytes::copy_from_slice(buf);
        
        // Check if we have at least 2 bytes (type + length)
        if bytes.len() < 2 {
            return Err(Error::TlvParsing("Buffer too short for NACK TLV".into()));
        }
        
        // Type
        let typ = bytes.get_u8();
        if typ != tlv_type::NACK {
            return Err(Error::TlvParsing(format!("Unexpected TLV type: {}", typ)));
        }
        
        // Length
        let len = bytes.get_u8() as usize;
        
        // Check if we have enough bytes for the value
        if bytes.len() < len {
            return Err(Error::TlvParsing("Buffer too short for NACK value".into()));
        }
        
        // Value (Interest + Reason + Message)
        let mut value = bytes.split_to(len);
        
        // Parse interest (assuming first TLV is the Interest)
        let interest = Interest::from_bytes(&value)?;
        
        // Advance past the Interest
        let interest_size = 2 + value[1] as usize; // type + length + Interest TLV size
        value.advance(interest_size);
        
        // Default values
        let mut reason = NackReason::NoRoute;
        let mut message = String::new();
        
        // Parse remaining TLVs
        while value.has_remaining() {
            // Check if we have at least 2 bytes (type + length)
            if value.len() < 2 {
                break;
            }
            
            let typ = value.get_u8();
            let len = value.get_u8() as usize;
            
            // Check if we have enough bytes for the value
            if value.len() < len {
                break;
            }
            
            match typ {
                tlv_type::NACK_REASON => {
                    if len == 2 {
                        reason = NackReason::from(value.get_u16());
                    } else {
                        value.advance(len);
                    }
                }
                0x10 => {
                    // Custom TLV for message
                    let msg_bytes = value.split_to(len);
                    message = String::from_utf8_lossy(&msg_bytes).to_string();
                }
                _ => {
                    // Skip unknown TLV
                    value.advance(len);
                }
            }
        }
        
        Ok(Self {
            interest,
            reason,
            message,
        })
    }
}

impl fmt::Debug for Nack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nack")
            .field("interest", &self.interest)
            .field("reason", &self.reason)
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for Nack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nack({}, {:?})", self.interest.name(), self.reason)
    }
}
