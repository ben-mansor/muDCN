//
// μDCN Error Types
//
// This module defines the error types used throughout the μDCN transport layer.
//

use thiserror::Error;
use std::io;

/// Error type for the μDCN transport layer
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    /// QUIC error
    #[error("QUIC error: {0}")]
    Quic(#[from] quinn::ConnectionError),
    
    /// TLS error
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    
    /// Name parsing error
    #[error("Name parsing error: {0}")]
    NameParsing(String),
    
    /// TLV parsing error
    #[error("TLV parsing error: {0}")]
    TlvParsing(String),
    
    /// No connections available
    #[error("No connections available")]
    NoConnections,
    
    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    /// Invalid MTU value
    #[error("Invalid MTU value: {0}")]
    InvalidMtu(usize),
    
    /// Timeout error
    #[error("Operation timed out after {0} ms")]
    Timeout(u64),
    
    /// Content store error
    #[error("Content store error: {0}")]
    ContentStore(String),
    
    /// Signature verification error
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),
    
    /// Fragmentation error
    #[error("Fragmentation error: {0}")]
    Fragmentation(String),
    
    /// ML model error
    #[error("ML model error: {0}")]
    MlModel(String),
    
    /// Generic error
    #[error("{0}")]
    Other(String),
}

// Convert from Quinn write error
impl From<quinn::WriteError> for Error {
    fn from(err: quinn::WriteError) -> Self {
        Error::Quic(err.into())
    }
}

// Convert from Quinn read error
impl From<quinn::ReadExactError> for Error {
    fn from(err: quinn::ReadExactError) -> Self {
        match err {
            quinn::ReadExactError::FinishedEarly => Error::Other("Stream finished early".into()),
            quinn::ReadExactError::ReadError(e) => Error::Quic(e.into()),
        }
    }
}

// Convert from Quinn read to end error
impl From<quinn::ReadToEndError> for Error {
    fn from(err: quinn::ReadToEndError) -> Self {
        Error::Quic(err.into())
    }
}

// Convert from Quinn connection creation error
impl From<quinn::ConnectError> for Error {
    fn from(err: quinn::ConnectError) -> Self {
        Error::Quic(err.into())
    }
}

// Convert from Quinn endpoint creation error
impl From<quinn::EndpointError> for Error {
    fn from(err: quinn::EndpointError) -> Self {
        Error::Quic(err.into())
    }
}

// Convert from string
impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

// Convert from static string
impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Other(s.to_string())
    }
}
