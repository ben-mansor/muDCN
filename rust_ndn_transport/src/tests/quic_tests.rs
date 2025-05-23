//
// QUIC Transport Tests
//
// This module tests the NDN over QUIC transport implementation
//

use super::*;
use crate::fragmentation::Fragmenter;
use crate::metrics::init_metrics;
use crate::quic::ConnectionState;

use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// Common test config
fn test_config() -> Config {
    Config {
        bind_address: "127.0.0.1".to_string(),
        port: 0, // Let OS assign an ephemeral port
        mtu: 1400,
        idle_timeout: 30,
        cache_capacity: 1000,
        enable_metrics: false,
        metrics_port: 9090,
        max_packet_size: 65535,
        log_level: "debug".to_string(),
        retries: 3,
        retry_interval: 1000,
        ..Default::default()
    }
}

// Test basic connection setup and teardown
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_quic_engine_start_stop() {
    init_metrics();
    
    // Create engine
    let config = test_config();
    let mut engine = QuicEngine::new(&config).await.expect("Failed to create QUIC engine");
    
    // Start the engine
    engine.start().await.expect("Failed to start QUIC engine");
    
    // Wait a moment
    sleep(Duration::from_millis(100)).await;
    
    // Stop the engine
    engine.stop().await.expect("Failed to stop QUIC engine");
}

// Test basic interest-data exchange
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_interest_data_exchange() {
    init_metrics();
    
    // Create server engine
    let config = test_config();
    let mut server = QuicEngine::new(&config).await.expect("Failed to create server");
    server.start().await.expect("Failed to start server");
    
    // Get the server address
    let server_addr = server.local_addr().await.expect("Failed to get local address");
    
    // Register a prefix with test handler
    let test_data = create_test_data("/test/data/1", b"Hello, NDN world!");
    server.register_prefix(
        Name::from_uri("/test").unwrap(),
        create_test_handler(test_data.clone())
    ).await.expect("Failed to register prefix");
    
    // Create client engine
    let mut client = QuicEngine::new(&test_config()).await.expect("Failed to create client");
    client.start().await.expect("Failed to start client");
    
    // Send an interest and get data
    let interest = create_test_interest("/test/data/1");
    let result = client.send_interest(server_addr, interest).await;
    
    // Check the result
    assert!(result.is_ok(), "Failed to get data: {:?}", result.err());
    let data = result.unwrap();
    assert_eq!(data.name().to_string(), "/test/data/1");
    assert_eq!(data.content(), b"Hello, NDN world!");
    
    // Clean up
    client.stop().await.expect("Failed to stop client");
    server.stop().await.expect("Failed to stop server");
}

// Test error handling with NACK responses
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_error_handling() {
    init_metrics();
    
    // Create server engine
    let config = test_config();
    let mut server = QuicEngine::new(&config).await.expect("Failed to create server");
    server.start().await.expect("Failed to start server");
    
    // Get the server address
    let server_addr = server.local_addr().await.expect("Failed to get local address");
    
    // Register a prefix with error handler
    server.register_prefix(
        Name::from_uri("/error").unwrap(),
        create_error_handler("Test error".to_string())
    ).await.expect("Failed to register prefix");
    
    // Create client engine
    let mut client = QuicEngine::new(&test_config()).await.expect("Failed to create client");
    client.start().await.expect("Failed to start client");
    
    // Send an interest that should get a NACK
    let interest = create_test_interest("/error/test");
    let result = client.send_interest(server_addr, interest).await;
    
    // Check the result is an error with the expected message
    assert!(result.is_err(), "Expected an error but got: {:?}", result.ok());
    match result {
        Err(Error::Other(msg)) => {
            assert_eq!(msg, "Test error", "Unexpected error message: {}", msg);
        },
        Err(e) => {
            panic!("Unexpected error type: {:?}", e);
        },
        Ok(_) => {
            panic!("Expected an error but got Ok");
        }
    }
    
    // Clean up
    client.stop().await.expect("Failed to stop client");
    server.stop().await.expect("Failed to stop server");
}

// Test connection tracker
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_connection_tracker() {
    init_metrics();
    
    // Create server engine
    let config = test_config();
    let mut server = QuicEngine::new(&config).await.expect("Failed to create server");
    server.start().await.expect("Failed to start server");
    
    // Get the server address
    let server_addr = server.local_addr().await.expect("Failed to get local address");
    
    // Register a prefix with test handler
    let call_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = call_counter.clone();
    
    let handler: PrefixHandler = Box::new(move |interest: Interest| -> Result<Data> {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        let name = interest.name().clone();
        let data = Data::new(name, b"Test data");
        Ok(data)
    });
    
    server.register_prefix(
        Name::from_uri("/counter").unwrap(),
        handler
    ).await.expect("Failed to register prefix");
    
    // Create client engine
    let mut client = QuicEngine::new(&test_config()).await.expect("Failed to create client");
    client.start().await.expect("Failed to start client");
    
    // Send multiple interests
    for i in 0..5 {
        let interest = create_test_interest(&format!("/counter/{}", i));
        let result = client.send_interest(server_addr, interest).await;
        assert!(result.is_ok(), "Failed to get data: {:?}", result.err());
    }
    
    // Check connection state
    let conn_state = client.get_connection_state(server_addr).await;
    assert!(conn_state.is_some(), "Connection state not found");
    assert!(matches!(conn_state.unwrap(), ConnectionState::Connected), "Connection not in Connected state");
    
    // Check connection stats
    let stats = client.get_connection_stats(server_addr).await;
    assert!(stats.is_some(), "Connection stats not found");
    let stats = stats.unwrap();
    assert_eq!(stats.interests_sent, 5, "Unexpected interest count");
    assert_eq!(stats.data_received, 5, "Unexpected data count");
    assert_eq!(stats.nacks_received, 0, "Unexpected NACK count");
    
    // Check the handler call counter
    assert_eq!(call_counter.load(Ordering::SeqCst), 5, "Handler not called expected number of times");
    
    // Clean up
    client.stop().await.expect("Failed to stop client");
    server.stop().await.expect("Failed to stop server");
}

// Test congestion control and backoff
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_congestion_control() {
    init_metrics();
    
    // Create server engine with a handler that simulates delays
    let config = test_config();
    let mut server = QuicEngine::new(&config).await.expect("Failed to create server");
    
    // Handler that introduces delays based on sequence number
    let handler: PrefixHandler = Box::new(move |interest: Interest| -> Result<Data> {
        // Get the sequence number from the name
        let name = interest.name().to_string();
        let parts: Vec<&str> = name.split('/').collect();
        if let Ok(seq) = parts.last().unwrap_or(&"0").parse::<u32>() {
            // Introduce delay for even numbers to simulate congestion
            if seq % 2 == 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        
        // Return data for all odd numbers, error for even
        let name = interest.name().clone();
        if name.to_string().ends_with("0") {
            Err(Error::Other("Simulated congestion".to_string()))
        } else {
            let data = Data::new(name, b"Test data");
            Ok(data)
        }
    });
    
    server.register_prefix(
        Name::from_uri("/congestion").unwrap(),
        handler
    ).await.expect("Failed to register prefix");
    
    server.start().await.expect("Failed to start server");
    
    // Get the server address
    let server_addr = server.local_addr().await.expect("Failed to get local address");
    
    // Create client engine
    let mut client = QuicEngine::new(&test_config()).await.expect("Failed to create client");
    client.start().await.expect("Failed to start client");
    
    // Send interests that will cause congestion
    for i in 0..10 {
        let interest = create_test_interest(&format!("/congestion/{}", i));
        let _ = client.send_interest(server_addr, interest).await;
        
        // Check connection state periodically
        if i == 5 {
            let window = client.get_congestion_window(server_addr).await;
            assert!(window.is_some(), "Missing congestion window");
            // Window should have been reduced due to errors on even numbers
            assert!(window.unwrap() < 10, "Window not reduced by congestion: {}", window.unwrap());
        }
    }
    
    // Check final congestion window
    let window = client.get_congestion_window(server_addr).await;
    assert!(window.is_some(), "Missing congestion window");
    // Due to the pattern of errors (even numbers), window should be reduced
    assert!(window.unwrap() < 10, "Window not properly reduced: {}", window.unwrap());
    
    // Clean up
    client.stop().await.expect("Failed to stop client");
    server.stop().await.expect("Failed to stop server");
}
