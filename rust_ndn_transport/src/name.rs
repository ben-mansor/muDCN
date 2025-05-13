//
// μDCN NDN Name Implementation
//
// This module implements the NDN name type and related functionality.
// Names in NDN are hierarchical and consist of components.
//

use std::fmt;
use std::str::FromStr;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use sha2::{Sha256, Digest};

use crate::error::Error;
use crate::Result;

/// A component in an NDN name
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Component {
    /// The value of the component
    value: Bytes,
}

impl Component {
    /// Create a new component from bytes
    pub fn new(value: impl Into<Bytes>) -> Self {
        Self { value: value.into() }
    }
    
    /// Create a new component from a string
    pub fn from_str(s: &str) -> Self {
        Self::new(Bytes::copy_from_slice(s.as_bytes()))
    }
    
    /// Get the value of the component as bytes
    pub fn value(&self) -> &Bytes {
        &self.value
    }
    
    /// Get the length of the component
    pub fn len(&self) -> usize {
        self.value.len()
    }
    
    /// Check if the component is empty
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
    
    /// Encode the component as TLV
    pub fn to_tlv(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(2 + self.len());
        
        // Type (8 = NameComponent)
        buf.put_u8(8);
        
        // Length
        buf.put_u8(self.len() as u8);
        
        // Value
        buf.extend_from_slice(&self.value);
        
        buf
    }
    
    /// Decode a component from TLV
    pub fn from_tlv(buf: &mut Bytes) -> Result<Self> {
        // Check if we have at least 2 bytes (type + length)
        if buf.len() < 2 {
            return Err(Error::TlvParsing("Buffer too short for component TLV".into()));
        }
        
        // Type
        let typ = buf.get_u8();
        if typ != 8 {
            return Err(Error::TlvParsing(format!("Unexpected component type: {}", typ)));
        }
        
        // Length
        let len = buf.get_u8() as usize;
        
        // Check if we have enough bytes for the value
        if buf.len() < len {
            return Err(Error::TlvParsing("Buffer too short for component value".into()));
        }
        
        // Value
        let value = buf.split_to(len);
        
        Ok(Self::new(value))
    }
}

impl fmt::Debug for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Try to display as UTF-8 if possible
        match std::str::from_utf8(&self.value) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => {
                // Otherwise, display as hex
                write!(f, "0x")?;
                for b in &self.value {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Try to display as UTF-8 if possible
        match std::str::from_utf8(&self.value) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => {
                // Otherwise, display as hex
                write!(f, "0x")?;
                for b in &self.value {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    }
}

/// An NDN name is a sequence of components
#[derive(Clone, PartialEq, Eq)]
pub struct Name {
    /// The components of the name
    components: Vec<Component>,
    
    /// Cached string representation
    cached_string: String,
}

impl Name {
    /// Create a new empty name
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            cached_string: String::new(),
        }
    }
    
    /// Create a name from components
    pub fn from_components(components: Vec<Component>) -> Self {
        let mut name = Self {
            components,
            cached_string: String::new(),
        };
        name.update_cached_string();
        name
    }
    
    /// Parse a name from a URI string
    pub fn from_uri(uri: &str) -> Result<Self> {
        if !uri.starts_with('/') {
            return Err(Error::NameParsing(format!("URI must start with '/': {}", uri)));
        }
        
        // Split the URI into components
        let components: Vec<Component> = uri.split('/')
            .filter(|s| !s.is_empty()) // Skip empty components
            .map(Component::from_str)
            .collect();
        
        let mut name = Self {
            components,
            cached_string: String::new(),
        };
        name.cached_string = uri.to_string();
        Ok(name)
    }
    
    /// Update the cached string representation
    fn update_cached_string(&mut self) {
        let mut s = String::new();
        for comp in &self.components {
            s.push('/');
            s.push_str(&comp.to_string());
        }
        if s.is_empty() {
            s.push('/');
        }
        self.cached_string = s;
    }
    
    /// Add a component to the name
    pub fn push(&mut self, component: Component) {
        self.components.push(component);
        self.update_cached_string();
    }
    
    /// Add a string component to the name
    pub fn push_str(&mut self, s: &str) {
        self.push(Component::from_str(s));
    }
    
    /// Get the components of the name
    pub fn components(&self) -> &[Component] {
        &self.components
    }
    
    /// Get the number of components in the name
    pub fn len(&self) -> usize {
        self.components.len()
    }
    
    /// Check if the name is empty
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }
    
    /// Get a component by index
    pub fn get(&self, index: usize) -> Option<&Component> {
        self.components.get(index)
    }
    
    /// Compute a hash of the name
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for comp in &self.components {
            hasher.update(&comp.value);
        }
        hasher.finalize().into()
    }
    
    /// Check if this name starts with the given prefix
    pub fn starts_with(&self, prefix: &Name) -> bool {
        if prefix.len() > self.len() {
            return false;
        }
        
        for (i, comp) in prefix.components.iter().enumerate() {
            if &self.components[i] != comp {
                return false;
            }
        }
        
        true
    }
    
    /// Check if this name has the given prefix (for matching Interest to Name)
    pub fn has_prefix(&self, other: &Name) -> bool {
        other.starts_with(self)
    }
    
    /// Encode the name as TLV
    pub fn to_tlv(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        
        // Compute the total length of the components
        let mut components_len = 0;
        for comp in &self.components {
            components_len += 2 + comp.len(); // type + length + value
        }
        
        // Type (7 = Name)
        buf.put_u8(7);
        
        // Length
        buf.put_u8(components_len as u8);
        
        // Components
        for comp in &self.components {
            buf.extend_from_slice(&comp.to_tlv());
        }
        
        buf
    }
    
    /// Decode a name from TLV
    pub fn from_tlv(buf: &mut Bytes) -> Result<Self> {
        // Check if we have at least 2 bytes (type + length)
        if buf.len() < 2 {
            return Err(Error::TlvParsing("Buffer too short for name TLV".into()));
        }
        
        // Type
        let typ = buf.get_u8();
        if typ != 7 {
            return Err(Error::TlvParsing(format!("Unexpected name type: {}", typ)));
        }
        
        // Length
        let len = buf.get_u8() as usize;
        
        // Check if we have enough bytes for the value
        if buf.len() < len {
            return Err(Error::TlvParsing("Buffer too short for name value".into()));
        }
        
        // Value (components)
        let mut components_buf = buf.split_to(len);
        let mut components = Vec::new();
        
        while components_buf.has_remaining() {
            components.push(Component::from_tlv(&mut components_buf)?);
        }
        
        let mut name = Self {
            components,
            cached_string: String::new(),
        };
        name.update_cached_string();
        Ok(name)
    }
}

impl Default for Name {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cached_string)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cached_string)
    }
}

impl FromStr for Name {
    type Err = Error;
    
    fn from_str(s: &str) -> Result<Self> {
        Self::from_uri(s)
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for comp in &self.components {
            comp.hash(state);
        }
    }
}

impl From<&str> for Name {
    fn from(s: &str) -> Self {
        Self::from_uri(s).unwrap_or_else(|_| Self::new())
    }
}

impl Deref for Name {
    type Target = [Component];
    
    fn deref(&self) -> &Self::Target {
        &self.components
    }
}
