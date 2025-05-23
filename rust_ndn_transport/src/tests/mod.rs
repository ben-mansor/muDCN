//
// μDCN Transport Layer Tests
//
// This module contains integration tests for the NDN over QUIC transport
// layer, including end-to-end tests of the entire transport stack.
//

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
use std::collections::HashMap;

use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::ndn::{Interest, Data};
use crate::name::Name;
use crate::quic::{QuicEngine, PrefixHandler};
use crate::{Config, Result, Error};

pub mod quic_tests;
pub mod fragmentation_tests;
pub mod python_binding_tests;

// Helper function to create simple test data
pub fn create_test_data(name: &str, content: &[u8]) -> Data {
    Data::new(Name::from_uri(name).unwrap(), content)
}

// Helper function to create a simple test interest
pub fn create_test_interest(name: &str) -> Interest {
    Interest::new(Name::from_uri(name).unwrap())
}

// Helper function to create a test handler
pub fn create_test_handler(data: Data) -> PrefixHandler {
    Box::new(move |_interest: Interest| -> Result<Data> {
        Ok(data.clone())
    })
}

// Helper function to create an error handler
pub fn create_error_handler(error_msg: String) -> PrefixHandler {
    Box::new(move |_interest: Interest| -> Result<Data> {
        Err(Error::Other(error_msg.clone()))
    })
}
