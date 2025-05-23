//
// Fragmentation Tests
//
// This module tests the fragmentation and reassembly mechanisms
//

use super::*;
use crate::fragmentation::{Fragmenter, Fragment, FRAGMENT_HEADER_SIZE};
use crate::metrics::init_metrics;
use bytes::Bytes;

// Test basic fragmentation and reassembly
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_basic_fragmentation_reassembly() {
    init_metrics();
    
    // Create a fragmenter with a small MTU
    let mtu = 100;
    let fragmenter = Fragmenter::new(mtu);
    
    // Create test data larger than MTU
    let test_name = "/test/large/data";
    let content = vec![0u8; 1000]; // 1000 bytes
    let data = create_test_data(test_name, &content);
    
    // Fragment the data
    let fragments = fragmenter.fragment(&data).await;
    
    // Check that fragmentation produced expected number of fragments
    let expected_fragments = (content.len() + mtu - FRAGMENT_HEADER_SIZE - 1) / (mtu - FRAGMENT_HEADER_SIZE);
    assert_eq!(fragments.len(), expected_fragments, "Unexpected number of fragments");
    
    // Create a reassembly context
    let fragment_obj = Fragment::from_bytes(&fragments[0]).expect("Failed to parse fragment");
    let fragment_id = fragment_obj.header().fragment_id();
    let total_fragments = fragment_obj.header().total_fragments();
    
    let reassembly_ctx = fragmenter.new_reassembly_context(fragment_id, total_fragments).await;
    
    // Add all fragments to the context
    for fragment_bytes in &fragments {
        let fragment = Fragment::from_bytes(fragment_bytes).expect("Failed to parse fragment");
        reassembly_ctx.add_fragment(fragment).await;
    }
    
    // Try to reassemble
    let reassembled_bytes = reassembly_ctx.reassemble().await;
    assert!(reassembled_bytes.is_some(), "Failed to reassemble fragments");
    
    // Parse the reassembled data
    let reassembled_data = Data::from_bytes(&reassembled_bytes.unwrap()).expect("Failed to parse reassembled data");
    
    // Verify the reassembled data
    assert_eq!(reassembled_data.name().to_string(), test_name, "Name mismatch after reassembly");
    assert_eq!(reassembled_data.content().len(), content.len(), "Content length mismatch after reassembly");
    assert_eq!(reassembled_data.content(), &content, "Content mismatch after reassembly");
}

// Test MTU adaptation
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_mtu_adaptation() {
    init_metrics();
    
    // Create a fragmenter with initial MTU
    let initial_mtu = 1400;
    let fragmenter = Fragmenter::new(initial_mtu);
    
    // Check initial MTU
    assert_eq!(fragmenter.mtu().await, initial_mtu, "Initial MTU mismatch");
    
    // Explicitly update MTU
    let new_mtu = 1200;
    fragmenter.update_mtu(new_mtu).await;
    assert_eq!(fragmenter.mtu().await, new_mtu, "Updated MTU mismatch");
    
    // Add packet sizes to history by fragmenting data of various sizes
    for size in [500, 700, 900, 1100, 1300] {
        let content = vec![0u8; size];
        let data = create_test_data("/test/mtu/adapt", &content);
        let _ = fragmenter.fragment(&data).await;
    }
    
    // Trigger MTU adaptation
    fragmenter.adapt_mtu().await;
    
    // MTU should have been adapted based on the 95th percentile of packet sizes
    let adapted_mtu = fragmenter.mtu().await;
    assert!(adapted_mtu >= FRAGMENT_HEADER_SIZE + 100, "MTU too small after adaptation");
    assert!(adapted_mtu <= 1400, "MTU increased unexpectedly after adaptation");
}

// Test fragment reconstruction with out-of-order delivery
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_out_of_order_reassembly() {
    init_metrics();
    
    // Create a fragmenter with a small MTU
    let mtu = 100;
    let fragmenter = Fragmenter::new(mtu);
    
    // Create test data
    let test_name = "/test/out-of-order";
    let content = vec![1u8; 500]; // 500 bytes of 1's
    let data = create_test_data(test_name, &content);
    
    // Fragment the data
    let mut fragments = fragmenter.fragment(&data).await;
    
    // Reverse the order of fragments to simulate out-of-order delivery
    fragments.reverse();
    
    // Create a reassembly context from the last fragment (which is now first)
    let fragment_obj = Fragment::from_bytes(&fragments[0]).expect("Failed to parse fragment");
    let fragment_id = fragment_obj.header().fragment_id();
    let total_fragments = fragment_obj.header().total_fragments();
    
    let reassembly_ctx = fragmenter.new_reassembly_context(fragment_id, total_fragments).await;
    
    // Add fragments in reversed order
    for fragment_bytes in &fragments {
        let fragment = Fragment::from_bytes(fragment_bytes).expect("Failed to parse fragment");
        reassembly_ctx.add_fragment(fragment).await;
    }
    
    // Try to reassemble
    let reassembled_bytes = reassembly_ctx.reassemble().await;
    assert!(reassembled_bytes.is_some(), "Failed to reassemble out-of-order fragments");
    
    // Parse the reassembled data
    let reassembled_data = Data::from_bytes(&reassembled_bytes.unwrap()).expect("Failed to parse reassembled data");
    
    // Verify the reassembled data
    assert_eq!(reassembled_data.name().to_string(), test_name, "Name mismatch after out-of-order reassembly");
    assert_eq!(reassembled_data.content().len(), content.len(), "Content length mismatch after out-of-order reassembly");
    assert_eq!(reassembled_data.content(), &content, "Content mismatch after out-of-order reassembly");
}

// Test incomplete reassembly
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_incomplete_reassembly() {
    init_metrics();
    
    // Create a fragmenter with a small MTU
    let mtu = 100;
    let fragmenter = Fragmenter::new(mtu);
    
    // Create test data
    let test_name = "/test/incomplete";
    let content = vec![2u8; 500]; // 500 bytes of 2's
    let data = create_test_data(test_name, &content);
    
    // Fragment the data
    let fragments = fragmenter.fragment(&data).await;
    
    // Make sure we have multiple fragments
    assert!(fragments.len() > 1, "Need multiple fragments for test");
    
    // Create a reassembly context
    let fragment_obj = Fragment::from_bytes(&fragments[0]).expect("Failed to parse fragment");
    let fragment_id = fragment_obj.header().fragment_id();
    let total_fragments = fragment_obj.header().total_fragments();
    
    let reassembly_ctx = fragmenter.new_reassembly_context(fragment_id, total_fragments).await;
    
    // Add only the first fragment to the context, simulating packet loss
    let first_fragment = Fragment::from_bytes(&fragments[0]).expect("Failed to parse fragment");
    reassembly_ctx.add_fragment(first_fragment).await;
    
    // Try to reassemble - should fail because we only added one fragment
    let reassembled_bytes = reassembly_ctx.reassemble().await;
    assert!(reassembled_bytes.is_none(), "Reassembly unexpectedly succeeded with incomplete fragments");
}

// Test with minimum viable MTU
#[cfg_attr(feature = "tokio-test", tokio::test)]
#[cfg_attr(not(feature = "tokio-test"), test)]
async fn test_minimum_viable_mtu() {
    init_metrics();
    
    // Create a fragmenter with MTU smaller than minimum viable
    let too_small_mtu = FRAGMENT_HEADER_SIZE / 2;
    let fragmenter = Fragmenter::new(too_small_mtu);
    
    // Check that MTU is increased to minimum viable
    let actual_mtu = fragmenter.mtu().await;
    assert!(actual_mtu > too_small_mtu, "MTU not increased to minimum viable");
    assert!(actual_mtu >= FRAGMENT_HEADER_SIZE + 1, "MTU too small to be viable");
    
    // Create test data
    let test_name = "/test/min-mtu";
    let content = vec![3u8; 100]; // Small payload
    let data = create_test_data(test_name, &content);
    
    // Fragment the data
    let fragments = fragmenter.fragment(&data).await;
    
    // Should have at least one fragment
    assert!(!fragments.is_empty(), "No fragments produced");
    
    // Each fragment should be at least FRAGMENT_HEADER_SIZE in length
    for fragment_bytes in &fragments {
        assert!(fragment_bytes.len() >= FRAGMENT_HEADER_SIZE, "Fragment too small");
    }
}
