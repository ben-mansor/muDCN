//
// μDCN NDN Packet Unit Tests
//
// This file contains unit tests for the NDN packet implementation.
//

use std::time::Duration;
use udcn_transport::name::Name;
use udcn_transport::ndn::{Interest, Data, Nack, NackReason};

#[test]
fn test_interest_creation() {
    let name = Name::from("/test/interest");
    
    // Create a basic interest
    let interest = Interest::new(name.clone());
    assert_eq!(interest.name(), &name);
    assert!(interest.can_be_prefix() == false); // Default value
    assert!(interest.must_be_fresh() == false); // Default value
    
    // Create an interest with all options
    let lifetime = Duration::from_secs(10);
    let interest = Interest::new(name.clone())
        .can_be_prefix(true)
        .must_be_fresh(true)
        .lifetime(lifetime)
        .nonce(42);
    
    assert_eq!(interest.name(), &name);
    assert!(interest.can_be_prefix());
    assert!(interest.must_be_fresh());
    assert_eq!(interest.lifetime(), lifetime);
    assert_eq!(interest.nonce(), 42);
}

#[test]
fn test_interest_builder() {
    let name = Name::from("/test/interest");
    
    // Test the builder pattern
    let interest = Interest::builder()
        .name(name.clone())
        .can_be_prefix(true)
        .must_be_fresh(true)
        .lifetime(Duration::from_secs(5))
        .nonce(123)
        .build();
    
    assert_eq!(interest.name(), &name);
    assert!(interest.can_be_prefix());
    assert!(interest.must_be_fresh());
    assert_eq!(interest.lifetime(), Duration::from_secs(5));
    assert_eq!(interest.nonce(), 123);
}

#[test]
fn test_interest_wire_format() {
    let name = Name::from("/test/interest");
    let interest = Interest::new(name.clone())
        .can_be_prefix(true)
        .must_be_fresh(true)
        .lifetime(Duration::from_secs(5))
        .nonce(123);
    
    // Encode the interest to wire format
    let wire_data = interest.to_wire();
    assert!(!wire_data.is_empty());
    
    // Decode from wire format
    let decoded_interest = Interest::from_wire(&wire_data).expect("Failed to decode interest");
    
    // Verify the decoded interest
    assert_eq!(decoded_interest.name(), &name);
    assert_eq!(decoded_interest.can_be_prefix(), interest.can_be_prefix());
    assert_eq!(decoded_interest.must_be_fresh(), interest.must_be_fresh());
    assert_eq!(decoded_interest.lifetime(), interest.lifetime());
    assert_eq!(decoded_interest.nonce(), interest.nonce());
}

#[test]
fn test_interest_matching() {
    let prefix = Name::from("/test/prefix");
    let exact_name = Name::from("/test/prefix");
    let longer_name = Name::from("/test/prefix/suffix");
    let different_name = Name::from("/test/different");
    
    // Test exact match
    let interest = Interest::new(exact_name.clone());
    assert!(interest.matches(&exact_name));
    assert!(!interest.matches(&longer_name)); // Different without CanBePrefix
    assert!(!interest.matches(&different_name));
    
    // Test prefix match
    let interest = Interest::new(prefix.clone()).can_be_prefix(true);
    assert!(interest.matches(&exact_name));
    assert!(interest.matches(&longer_name)); // Matches with CanBePrefix
    assert!(!interest.matches(&different_name));
}

#[test]
fn test_data_creation() {
    let name = Name::from("/test/data");
    let content = b"Hello, NDN!".to_vec();
    
    // Create a basic data packet
    let data = Data::new(name.clone(), content.clone());
    assert_eq!(data.name(), &name);
    assert_eq!(data.content().as_ref(), content.as_slice());
    assert_eq!(data.freshness_period(), None); // Default value
    
    // Create a data packet with freshness period
    let freshness = Duration::from_secs(60);
    let data = Data::new(name.clone(), content.clone())
        .freshness_period(freshness);
    
    assert_eq!(data.name(), &name);
    assert_eq!(data.content().as_ref(), content.as_slice());
    assert_eq!(data.freshness_period(), Some(freshness));
}

#[test]
fn test_data_builder() {
    let name = Name::from("/test/data");
    let content = b"Hello, NDN!".to_vec();
    
    // Test the builder pattern
    let data = Data::builder()
        .name(name.clone())
        .content(content.clone())
        .freshness_period(Duration::from_secs(60))
        .build();
    
    assert_eq!(data.name(), &name);
    assert_eq!(data.content().as_ref(), content.as_slice());
    assert_eq!(data.freshness_period(), Some(Duration::from_secs(60)));
}

#[test]
fn test_data_wire_format() {
    let name = Name::from("/test/data");
    let content = b"Hello, NDN!".to_vec();
    let data = Data::new(name.clone(), content.clone())
        .freshness_period(Duration::from_secs(60));
    
    // Encode the data to wire format
    let wire_data = data.to_wire();
    assert!(!wire_data.is_empty());
    
    // Decode from wire format
    let decoded_data = Data::from_wire(&wire_data).expect("Failed to decode data");
    
    // Verify the decoded data
    assert_eq!(decoded_data.name(), &name);
    assert_eq!(decoded_data.content().as_ref(), content.as_slice());
    assert_eq!(decoded_data.freshness_period(), data.freshness_period());
}

#[test]
fn test_data_signature() {
    let name = Name::from("/test/signed-data");
    let content = b"Secure content".to_vec();
    
    // Create a signed data packet
    let key_pair = udcn_transport::security::generate_key_pair().expect("Failed to generate key pair");
    let data = Data::new(name.clone(), content.clone())
        .sign(&key_pair.private_key).expect("Failed to sign data");
    
    // Verify that the data is signed
    assert!(data.has_signature());
    
    // Verify the signature
    let verified = data.verify(&key_pair.public_key).expect("Failed to verify signature");
    assert!(verified, "Signature verification failed");
    
    // Test with invalid key
    let bad_key_pair = udcn_transport::security::generate_key_pair().expect("Failed to generate key pair");
    let verified = data.verify(&bad_key_pair.public_key).expect("Failed to verify signature");
    assert!(!verified, "Signature should not verify with wrong key");
}

#[test]
fn test_nack_creation() {
    let interest = Interest::new(Name::from("/test/nack"));
    
    // Create a Nack with a reason
    let nack = Nack::new(interest.clone(), NackReason::Congestion);
    
    assert_eq!(nack.interest(), &interest);
    assert_eq!(nack.reason(), NackReason::Congestion);
    
    // Test other reasons
    let nack = Nack::new(interest.clone(), NackReason::NoRoute);
    assert_eq!(nack.reason(), NackReason::NoRoute);
    
    let nack = Nack::new(interest.clone(), NackReason::NoData);
    assert_eq!(nack.reason(), NackReason::NoData);
}

#[test]
fn test_nack_wire_format() {
    let interest = Interest::new(Name::from("/test/nack"));
    let nack = Nack::new(interest.clone(), NackReason::Congestion);
    
    // Encode the nack to wire format
    let wire_data = nack.to_wire();
    assert!(!wire_data.is_empty());
    
    // Decode from wire format
    let decoded_nack = Nack::from_wire(&wire_data).expect("Failed to decode nack");
    
    // Verify the decoded nack
    assert_eq!(decoded_nack.interest().name(), interest.name());
    assert_eq!(decoded_nack.reason(), NackReason::Congestion);
}

#[test]
fn test_interest_selectors() {
    let name = Name::from("/test/selectors");
    
    // Create an interest with selectors
    let interest = Interest::new(name.clone())
        .selector("exclude", Name::from("/excluded").to_string())
        .selector("childSelector", "1");
    
    // Check selectors
    assert!(interest.has_selector("exclude"));
    assert!(interest.has_selector("childSelector"));
    assert!(!interest.has_selector("nonexistent"));
    
    assert_eq!(interest.get_selector("exclude"), Some("/excluded"));
    assert_eq!(interest.get_selector("childSelector"), Some("1"));
    assert_eq!(interest.get_selector("nonexistent"), None);
    
    // Test wire format with selectors
    let wire_data = interest.to_wire();
    let decoded = Interest::from_wire(&wire_data).expect("Failed to decode interest");
    
    assert!(decoded.has_selector("exclude"));
    assert!(decoded.has_selector("childSelector"));
    assert_eq!(decoded.get_selector("exclude"), Some("/excluded"));
    assert_eq!(decoded.get_selector("childSelector"), Some("1"));
}

#[test]
fn test_data_meta_info() {
    let name = Name::from("/test/meta-info");
    let content = b"Content with meta-info".to_vec();
    
    // Create data with meta-info
    let data = Data::new(name.clone(), content.clone())
        .meta_info("contentType", "application/json")
        .meta_info("finalBlockId", "10");
    
    // Check meta-info
    assert!(data.has_meta_info("contentType"));
    assert!(data.has_meta_info("finalBlockId"));
    assert!(!data.has_meta_info("nonexistent"));
    
    assert_eq!(data.get_meta_info("contentType"), Some("application/json"));
    assert_eq!(data.get_meta_info("finalBlockId"), Some("10"));
    assert_eq!(data.get_meta_info("nonexistent"), None);
    
    // Test wire format with meta-info
    let wire_data = data.to_wire();
    let decoded = Data::from_wire(&wire_data).expect("Failed to decode data");
    
    assert!(decoded.has_meta_info("contentType"));
    assert!(decoded.has_meta_info("finalBlockId"));
    assert_eq!(decoded.get_meta_info("contentType"), Some("application/json"));
    assert_eq!(decoded.get_meta_info("finalBlockId"), Some("10"));
}

#[test]
fn test_interest_application_parameters() {
    let name = Name::from("/test/parameters");
    let params = b"application-specific parameters".to_vec();
    
    // Create an interest with application parameters
    let interest = Interest::new(name.clone())
        .application_parameters(params.clone());
    
    // Check parameters
    assert!(interest.has_application_parameters());
    assert_eq!(interest.application_parameters().as_ref(), params.as_slice());
    
    // Test wire format with parameters
    let wire_data = interest.to_wire();
    let decoded = Interest::from_wire(&wire_data).expect("Failed to decode interest");
    
    assert!(decoded.has_application_parameters());
    assert_eq!(decoded.application_parameters().as_ref(), params.as_slice());
    
    // Test without parameters
    let interest = Interest::new(name.clone());
    assert!(!interest.has_application_parameters());
    assert!(interest.application_parameters().is_empty());
}
