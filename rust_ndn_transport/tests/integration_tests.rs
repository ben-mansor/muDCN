//
// μDCN Integration Tests
//
// This file contains integration tests for the Rust NDN transport layer.
//

use std::time::Duration;
use tokio::time::sleep;

use udcn_transport::{Config, UdcnTransport};
use udcn_transport::name::Name;
use udcn_transport::ndn::{Interest, Data};

// Test parameters
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_INTEREST_LIFETIME: Duration = Duration::from_secs(1);

#[tokio::test]
async fn test_transport_initialization() {
    // Create a configuration for testing
    let config = Config {
        mtu: 1400,
        cache_capacity: 1000,
        idle_timeout: 30,
        bind_address: "127.0.0.1:6363".to_string(),
        enable_metrics: false,
        metrics_port: 0,
    };
    
    // Initialize the transport
    let transport = UdcnTransport::new(config).await;
    assert!(transport.is_ok(), "Failed to initialize transport: {:?}", transport.err());
    
    // Shutdown the transport
    let transport = transport.unwrap();
    let shutdown = transport.shutdown().await;
    assert!(shutdown.is_ok(), "Failed to shutdown transport: {:?}", shutdown.err());
}

#[tokio::test]
async fn test_interest_data_exchange() {
    // Create configurations for two nodes
    let producer_config = Config {
        mtu: 1400,
        cache_capacity: 1000,
        idle_timeout: 30,
        bind_address: "127.0.0.1:6364".to_string(),
        enable_metrics: false,
        metrics_port: 0,
    };
    
    let consumer_config = Config {
        mtu: 1400,
        cache_capacity: 1000,
        idle_timeout: 30,
        bind_address: "127.0.0.1:6365".to_string(),
        enable_metrics: false,
        metrics_port: 0,
    };
    
    // Initialize the transports
    let producer = UdcnTransport::new(producer_config).await.expect("Failed to initialize producer");
    let consumer = UdcnTransport::new(consumer_config).await.expect("Failed to initialize consumer");
    
    // Register a prefix handler on the producer
    let test_prefix = Name::from("/test/data");
    let test_content = b"Hello, NDN!".to_vec();
    let content_clone = test_content.clone();
    
    producer.register_prefix(
        test_prefix.clone(),
        Box::new(move |interest| {
            let name = interest.name().clone();
            let data = Data::new(name, content_clone.clone());
            Ok(data)
        }),
    ).await.expect("Failed to register prefix");
    
    // Start the transports
    producer.start().await.expect("Failed to start producer");
    consumer.start().await.expect("Failed to start consumer");
    
    // Allow some time for the transports to start
    sleep(Duration::from_millis(100)).await;
    
    // Create an interest
    let interest = Interest::new(Name::from("/test/data/123"))
        .lifetime(TEST_INTEREST_LIFETIME);
    
    // Send the interest and get the data
    let data_future = consumer.send_interest(interest);
    let data = tokio::time::timeout(TEST_TIMEOUT, data_future).await;
    
    // Check if we got a response
    assert!(data.is_ok(), "Interest timed out");
    let data = data.unwrap();
    assert!(data.is_ok(), "Failed to get data: {:?}", data.err());
    
    // Check the data content
    let data = data.unwrap();
    assert_eq!(data.name().to_string(), "/test/data/123");
    assert_eq!(data.content().as_ref(), test_content.as_slice());
    
    // Shutdown the transports
    producer.shutdown().await.expect("Failed to shutdown producer");
    consumer.shutdown().await.expect("Failed to shutdown consumer");
}

#[tokio::test]
async fn test_content_store() {
    // Create a configuration
    let config = Config {
        mtu: 1400,
        cache_capacity: 1000,
        idle_timeout: 30,
        bind_address: "127.0.0.1:6366".to_string(),
        enable_metrics: false,
        metrics_port: 0,
    };
    
    // Initialize the transport
    let transport = UdcnTransport::new(config).await.expect("Failed to initialize transport");
    
    // Register a prefix handler that counts the number of invocations
    let test_prefix = Name::from("/test/cache");
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_clone = counter.clone();
    
    transport.register_prefix(
        test_prefix.clone(),
        Box::new(move |interest| {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let name = interest.name().clone();
            let data = Data::new(name, b"Cached data".to_vec());
            Ok(data)
        }),
    ).await.expect("Failed to register prefix");
    
    // Start the transport
    transport.start().await.expect("Failed to start transport");
    
    // Allow some time for the transport to start
    sleep(Duration::from_millis(100)).await;
    
    // Create an interest
    let interest = Interest::new(Name::from("/test/cache/item"))
        .lifetime(TEST_INTEREST_LIFETIME);
    
    // Send the interest twice - first should hit the handler, second should hit the cache
    let data1_future = transport.send_interest(interest.clone());
    let data1 = tokio::time::timeout(TEST_TIMEOUT, data1_future).await;
    assert!(data1.is_ok(), "First interest timed out");
    let data1 = data1.unwrap();
    assert!(data1.is_ok(), "Failed to get data for first interest: {:?}", data1.err());
    
    // Send the second interest
    let data2_future = transport.send_interest(interest.clone());
    let data2 = tokio::time::timeout(TEST_TIMEOUT, data2_future).await;
    assert!(data2.is_ok(), "Second interest timed out");
    let data2 = data2.unwrap();
    assert!(data2.is_ok(), "Failed to get data for second interest: {:?}", data2.err());
    
    // Check that the handler was only called once
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1, 
               "Handler should have been called exactly once");
    
    // Shutdown the transport
    transport.shutdown().await.expect("Failed to shutdown transport");
}

#[tokio::test]
async fn test_mtu_update() {
    // Create a configuration
    let config = Config {
        mtu: 1400,
        cache_capacity: 1000,
        idle_timeout: 30,
        bind_address: "127.0.0.1:6367".to_string(),
        enable_metrics: false,
        metrics_port: 0,
    };
    
    // Initialize the transport
    let transport = UdcnTransport::new(config).await.expect("Failed to initialize transport");
    
    // Check the initial MTU
    assert_eq!(transport.mtu(), 1400);
    
    // Update the MTU
    let new_mtu = 9000;
    let result = transport.update_mtu(new_mtu).await;
    assert!(result.is_ok(), "Failed to update MTU: {:?}", result.err());
    
    // Check the new MTU
    assert_eq!(transport.mtu(), new_mtu);
    
    // Test with an invalid MTU (too small)
    let result = transport.update_mtu(50).await;
    assert!(result.is_err(), "Should have failed with small MTU");
    
    // Test with an invalid MTU (too large)
    let result = transport.update_mtu(10000).await;
    assert!(result.is_err(), "Should have failed with large MTU");
    
    // Shutdown the transport
    transport.shutdown().await.expect("Failed to shutdown transport");
}

#[tokio::test]
async fn test_multiple_prefix_registrations() {
    // Create a configuration
    let config = Config {
        mtu: 1400,
        cache_capacity: 1000,
        idle_timeout: 30,
        bind_address: "127.0.0.1:6368".to_string(),
        enable_metrics: false,
        metrics_port: 0,
    };
    
    // Initialize the transport
    let transport = UdcnTransport::new(config).await.expect("Failed to initialize transport");
    
    // Register multiple prefixes
    let prefixes = [
        ("/prefix/a", "Data A"),
        ("/prefix/b", "Data B"),
        ("/prefix/c", "Data C"),
    ];
    
    for (prefix, data) in prefixes.iter() {
        let prefix = Name::from(*prefix);
        let data_content = data.to_string().into_bytes();
        
        transport.register_prefix(
            prefix.clone(),
            Box::new(move |interest| {
                let name = interest.name().clone();
                let data = Data::new(name, data_content.clone());
                Ok(data)
            }),
        ).await.expect("Failed to register prefix");
    }
    
    // Start the transport
    transport.start().await.expect("Failed to start transport");
    
    // Allow some time for the transport to start
    sleep(Duration::from_millis(100)).await;
    
    // Test each prefix
    for (prefix, expected_data) in prefixes.iter() {
        // Create an interest with a specific prefix
        let interest = Interest::new(Name::from(format!("{}/test", prefix)))
            .lifetime(TEST_INTEREST_LIFETIME);
        
        // Send the interest and get the data
        let data_future = transport.send_interest(interest);
        let data = tokio::time::timeout(TEST_TIMEOUT, data_future).await;
        
        // Check if we got a response
        assert!(data.is_ok(), "Interest for {} timed out", prefix);
        let data = data.unwrap();
        assert!(data.is_ok(), "Failed to get data for {}: {:?}", prefix, data.err());
        
        // Check the data content
        let data = data.unwrap();
        assert_eq!(
            data.content().as_ref(), 
            expected_data.as_bytes(),
            "Content for {} doesn't match expected data", 
            prefix
        );
    }
    
    // Shutdown the transport
    transport.shutdown().await.expect("Failed to shutdown transport");
}

// Test for handling large data objects that need to be fragmented
#[tokio::test]
async fn test_fragmentation_reassembly() {
    // Create configurations for two nodes
    let producer_config = Config {
        mtu: 1400,
        cache_capacity: 1000,
        idle_timeout: 30,
        bind_address: "127.0.0.1:6369".to_string(),
        enable_metrics: false,
        metrics_port: 0,
    };
    
    let consumer_config = Config {
        mtu: 1400,
        cache_capacity: 1000,
        idle_timeout: 30,
        bind_address: "127.0.0.1:6370".to_string(),
        enable_metrics: false,
        metrics_port: 0,
    };
    
    // Initialize the transports
    let producer = UdcnTransport::new(producer_config).await.expect("Failed to initialize producer");
    let consumer = UdcnTransport::new(consumer_config).await.expect("Failed to initialize consumer");
    
    // Register a prefix handler that returns a large data object
    let test_prefix = Name::from("/test/large");
    let large_content = vec![0u8; 10000]; // 10KB of data
    
    producer.register_prefix(
        test_prefix.clone(),
        Box::new(move |interest| {
            let name = interest.name().clone();
            let data = Data::new(name, large_content.clone());
            Ok(data)
        }),
    ).await.expect("Failed to register prefix");
    
    // Start the transports
    producer.start().await.expect("Failed to start producer");
    consumer.start().await.expect("Failed to start consumer");
    
    // Allow some time for the transports to start
    sleep(Duration::from_millis(100)).await;
    
    // Create an interest
    let interest = Interest::new(Name::from("/test/large/data"))
        .lifetime(Duration::from_secs(5)); // Longer timeout for large data
    
    // Send the interest and get the data
    let data_future = consumer.send_interest(interest);
    let data = tokio::time::timeout(Duration::from_secs(10), data_future).await;
    
    // Check if we got a response
    assert!(data.is_ok(), "Interest timed out for large data");
    let data = data.unwrap();
    assert!(data.is_ok(), "Failed to get large data: {:?}", data.err());
    
    // Check the data size
    let data = data.unwrap();
    assert_eq!(data.content().len(), 10000, "Large data size doesn't match");
    
    // Shutdown the transports
    producer.shutdown().await.expect("Failed to shutdown producer");
    consumer.shutdown().await.expect("Failed to shutdown consumer");
}
