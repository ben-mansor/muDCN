//
// μDCN Fragmentation Unit Tests
//
// This file contains unit tests for the fragmentation and reassembly module.
//

use udcn_transport::name::Name;
use udcn_transport::ndn::Data;
use udcn_transport::fragmentation::{Fragmenter, Fragment, Reassembler};

#[test]
fn test_basic_fragmentation() {
    // Create a large data packet
    let name = Name::from("/test/large-data");
    let content = vec![0u8; 5000]; // 5KB of data
    let data = Data::new(name, content.clone());
    
    // Create a fragmenter with MTU of 1400
    let mtu = 1400;
    let fragmenter = Fragmenter::new(mtu);
    
    // Fragment the data
    let fragments = fragmenter.fragment(&data).expect("Failed to fragment data");
    
    // Check that we have the right number of fragments
    // Each fragment will have some overhead for headers, so we need more than just content.len() / mtu
    assert!(fragments.len() > 1, "Data should be split into multiple fragments");
    assert!(fragments.len() <= (content.len() / (mtu - 100) + 1), 
            "Should not create more fragments than necessary");
    
    // Check fragment properties
    for (i, fragment) in fragments.iter().enumerate() {
        // All fragments except the last should be close to MTU size
        if i < fragments.len() - 1 {
            assert!(fragment.data().len() <= mtu, "Fragment exceeds MTU");
            assert!(fragment.data().len() > mtu - 100, "Fragment is too small");
        }
        
        // Check fragment metadata
        assert_eq!(fragment.sequence(), i);
        assert_eq!(fragment.total_fragments(), fragments.len());
        assert_eq!(fragment.original_name().to_string(), "/test/large-data");
    }
}

#[test]
fn test_reassembly() {
    // Create a large data packet
    let name = Name::from("/test/reassembly");
    let content = vec![1u8; 10000]; // 10KB of data with all bytes set to 1
    let original_data = Data::new(name.clone(), content);
    
    // Fragment the data
    let fragmenter = Fragmenter::new(1400);
    let fragments = fragmenter.fragment(&original_data).expect("Failed to fragment data");
    
    // Ensure we have multiple fragments
    assert!(fragments.len() > 1);
    
    // Create a reassembler
    let mut reassembler = Reassembler::new();
    
    // Add fragments one by one
    let mut reassembly_complete = false;
    for fragment in &fragments {
        let result = reassembler.add_fragment(fragment.clone());
        
        // Only the last fragment should complete the reassembly
        if fragment.sequence() == fragments.len() - 1 {
            assert!(result.is_some(), "Reassembly should complete with the last fragment");
            reassembly_complete = true;
            
            // Check the reassembled data
            let reassembled_data = result.unwrap();
            assert_eq!(reassembled_data.name(), &name);
            assert_eq!(reassembled_data.content().len(), content.len());
            assert_eq!(reassembled_data.content().as_ref(), original_data.content().as_ref());
        } else {
            assert!(result.is_none(), "Reassembly should not complete before the last fragment");
        }
    }
    
    assert!(reassembly_complete, "Reassembly should have completed");
}

#[test]
fn test_out_of_order_reassembly() {
    // Create a data packet
    let name = Name::from("/test/out-of-order");
    let content = vec![2u8; 8000]; // 8KB of data with all bytes set to 2
    let original_data = Data::new(name.clone(), content);
    
    // Fragment the data
    let fragmenter = Fragmenter::new(1400);
    let fragments = fragmenter.fragment(&original_data).expect("Failed to fragment data");
    
    // Ensure we have multiple fragments
    assert!(fragments.len() > 1);
    
    // Create a reassembler
    let mut reassembler = Reassembler::new();
    
    // Add fragments in reverse order (except the last one)
    for i in (0..fragments.len()-1).rev() {
        let result = reassembler.add_fragment(fragments[i].clone());
        assert!(result.is_none(), "Reassembly should not complete with missing fragments");
    }
    
    // Add the last fragment, which should complete the reassembly
    let result = reassembler.add_fragment(fragments[fragments.len()-1].clone());
    assert!(result.is_some(), "Reassembly should complete with all fragments");
    
    // Check the reassembled data
    let reassembled_data = result.unwrap();
    assert_eq!(reassembled_data.name(), &name);
    assert_eq!(reassembled_data.content().len(), content.len());
    assert_eq!(reassembled_data.content().as_ref(), original_data.content().as_ref());
}

#[test]
fn test_duplicate_fragments() {
    // Create a data packet
    let name = Name::from("/test/duplicates");
    let content = vec![3u8; 5000]; // 5KB of data with all bytes set to 3
    let original_data = Data::new(name.clone(), content);
    
    // Fragment the data
    let fragmenter = Fragmenter::new(1400);
    let fragments = fragmenter.fragment(&original_data).expect("Failed to fragment data");
    
    // Create a reassembler
    let mut reassembler = Reassembler::new();
    
    // Add each fragment twice
    for fragment in &fragments {
        // First addition
        let result1 = reassembler.add_fragment(fragment.clone());
        
        // Second addition (duplicate)
        let result2 = reassembler.add_fragment(fragment.clone());
        
        // For all fragments except the last, both additions should return None
        if fragment.sequence() < fragments.len() - 1 {
            assert!(result1.is_none());
            assert!(result2.is_none(), "Duplicate fragment should be ignored");
        } else {
            // For the last fragment, the first addition should complete reassembly
            // and the second should be ignored
            assert!(result1.is_some(), "Reassembly should complete with the last fragment");
            assert!(result2.is_none(), "Duplicate of last fragment should be ignored");
            
            // Check the reassembled data
            let reassembled_data = result1.unwrap();
            assert_eq!(reassembled_data.content().as_ref(), original_data.content().as_ref());
        }
    }
}

#[test]
fn test_partial_reassembly_timeout() {
    // Create a data packet
    let name = Name::from("/test/timeout");
    let content = vec![4u8; 5000]; // 5KB of data with all bytes set to 4
    let original_data = Data::new(name.clone(), content);
    
    // Fragment the data
    let fragmenter = Fragmenter::new(1400);
    let fragments = fragmenter.fragment(&original_data).expect("Failed to fragment data");
    
    // Create a reassembler with a short timeout
    let mut reassembler = Reassembler::with_timeout(std::time::Duration::from_millis(100));
    
    // Add some but not all fragments
    for i in 0..fragments.len()-1 {
        let result = reassembler.add_fragment(fragments[i].clone());
        assert!(result.is_none());
    }
    
    // Wait for the timeout
    std::thread::sleep(std::time::Duration::from_millis(150));
    
    // Try to add the last fragment, should fail due to timeout
    let result = reassembler.add_fragment(fragments[fragments.len()-1].clone());
    assert!(result.is_none(), "Reassembly should fail after timeout");
    
    // Check that the reassembler has cleared the expired state
    assert_eq!(reassembler.pending_reassemblies(), 0);
}

#[test]
fn test_multiple_data_reassembly() {
    // Create two different data packets
    let name1 = Name::from("/test/multiple/1");
    let content1 = vec![5u8; 3000]; // 3KB of data with all bytes set to 5
    let data1 = Data::new(name1.clone(), content1.clone());
    
    let name2 = Name::from("/test/multiple/2");
    let content2 = vec![6u8; 4000]; // 4KB of data with all bytes set to 6
    let data2 = Data::new(name2.clone(), content2.clone());
    
    // Fragment both data packets
    let fragmenter = Fragmenter::new(1400);
    let fragments1 = fragmenter.fragment(&data1).expect("Failed to fragment data1");
    let fragments2 = fragmenter.fragment(&data2).expect("Failed to fragment data2");
    
    // Create a reassembler
    let mut reassembler = Reassembler::new();
    
    // Interleave the fragments
    let mut interleaved = Vec::new();
    for i in 0..std::cmp::max(fragments1.len(), fragments2.len()) {
        if i < fragments1.len() {
            interleaved.push(fragments1[i].clone());
        }
        if i < fragments2.len() {
            interleaved.push(fragments2[i].clone());
        }
    }
    
    // Add the interleaved fragments
    let mut reassembled1 = false;
    let mut reassembled2 = false;
    
    for fragment in interleaved {
        let result = reassembler.add_fragment(fragment);
        
        if result.is_some() {
            let reassembled = result.unwrap();
            if reassembled.name() == &name1 {
                assert!(!reassembled1, "Should only reassemble data1 once");
                assert_eq!(reassembled.content().as_ref(), content1.as_slice());
                reassembled1 = true;
            } else if reassembled.name() == &name2 {
                assert!(!reassembled2, "Should only reassemble data2 once");
                assert_eq!(reassembled.content().as_ref(), content2.as_slice());
                reassembled2 = true;
            } else {
                panic!("Reassembled unexpected data");
            }
        }
    }
    
    assert!(reassembled1, "Should have reassembled data1");
    assert!(reassembled2, "Should have reassembled data2");
}

#[test]
fn test_fragment_serialization() {
    // Create a fragment
    let name = Name::from("/test/serialize");
    let original_data = Data::new(name.clone(), vec![7u8; 100]);
    let fragmenter = Fragmenter::new(1400);
    let fragments = fragmenter.fragment(&original_data).expect("Failed to fragment data");
    let fragment = fragments[0].clone();
    
    // Serialize the fragment
    let wire_data = fragment.to_wire();
    assert!(!wire_data.is_empty());
    
    // Deserialize the fragment
    let deserialized = Fragment::from_wire(&wire_data).expect("Failed to deserialize fragment");
    
    // Check that the deserialized fragment matches the original
    assert_eq!(deserialized.sequence(), fragment.sequence());
    assert_eq!(deserialized.total_fragments(), fragment.total_fragments());
    assert_eq!(deserialized.original_name().to_string(), fragment.original_name().to_string());
    assert_eq!(deserialized.data(), fragment.data());
}

#[test]
fn test_fragment_limits() {
    // Create a very large data packet
    let name = Name::from("/test/limits");
    let content = vec![8u8; 100_000]; // 100KB of data
    let data = Data::new(name.clone(), content);
    
    // Try to fragment with a very small MTU (should fail)
    let small_fragmenter = Fragmenter::new(100);
    let result = small_fragmenter.fragment(&data);
    assert!(result.is_err(), "Fragmentation with tiny MTU should fail");
    
    // Try to fragment with a reasonable MTU
    let normal_fragmenter = Fragmenter::new(1400);
    let result = normal_fragmenter.fragment(&data);
    assert!(result.is_ok(), "Fragmentation with normal MTU should succeed");
    
    // Check that we don't create too many fragments
    let fragments = result.unwrap();
    assert!(fragments.len() < 1000, "Should not create an excessive number of fragments");
}

#[test]
fn test_reassembler_capacity() {
    // Create a reassembler with limited capacity
    let mut reassembler = Reassembler::with_capacity(2);
    
    // Create three different data packets and fragment them
    let fragmenter = Fragmenter::new(1400);
    
    let data1 = Data::new(Name::from("/test/capacity/1"), vec![1u8; 3000]);
    let fragments1 = fragmenter.fragment(&data1).expect("Failed to fragment data1");
    
    let data2 = Data::new(Name::from("/test/capacity/2"), vec![2u8; 3000]);
    let fragments2 = fragmenter.fragment(&data2).expect("Failed to fragment data2");
    
    let data3 = Data::new(Name::from("/test/capacity/3"), vec![3u8; 3000]);
    let fragments3 = fragmenter.fragment(&data3).expect("Failed to fragment data3");
    
    // Add one fragment from each data packet
    reassembler.add_fragment(fragments1[0].clone());
    reassembler.add_fragment(fragments2[0].clone());
    
    // Adding a fragment from the third data packet should evict the oldest one
    reassembler.add_fragment(fragments3[0].clone());
    
    // Now complete the reassembly of data1, should fail because it was evicted
    let mut all_failed = true;
    for i in 1..fragments1.len() {
        let result = reassembler.add_fragment(fragments1[i].clone());
        if result.is_some() {
            all_failed = false;
        }
    }
    assert!(all_failed, "Reassembly of data1 should fail after eviction");
    
    // Complete the reassembly of data3, should succeed
    let mut reassembled = false;
    for i in 1..fragments3.len() {
        let result = reassembler.add_fragment(fragments3[i].clone());
        if result.is_some() {
            reassembled = true;
            let reassembled_data = result.unwrap();
            assert_eq!(reassembled_data.name().to_string(), "/test/capacity/3");
        }
    }
    assert!(reassembled, "Reassembly of data3 should succeed");
}

#[test]
fn test_fragment_identification() {
    // Create two data packets with the same name but different content
    let name = Name::from("/test/id");
    let data1 = Data::new(name.clone(), vec![1u8; 3000]);
    let data2 = Data::new(name.clone(), vec![2u8; 3000]);
    
    // Fragment them
    let fragmenter = Fragmenter::new(1400);
    let fragments1 = fragmenter.fragment(&data1).expect("Failed to fragment data1");
    let fragments2 = fragmenter.fragment(&data2).expect("Failed to fragment data2");
    
    // Create a reassembler
    let mut reassembler = Reassembler::new();
    
    // Add fragments from the first data packet
    for fragment in &fragments1[0..fragments1.len()-1] {
        reassembler.add_fragment(fragment.clone());
    }
    
    // Try to add the last fragment from the second data packet
    // This should be ignored because it has a different content hash
    let result = reassembler.add_fragment(fragments2[fragments2.len()-1].clone());
    assert!(result.is_none(), "Fragment from different content should be ignored");
    
    // Now add the correct last fragment
    let result = reassembler.add_fragment(fragments1[fragments1.len()-1].clone());
    assert!(result.is_some(), "Reassembly should complete with the correct last fragment");
    
    // Verify the reassembled data
    let reassembled = result.unwrap();
    assert_eq!(reassembled.content().as_ref(), data1.content().as_ref());
}

#[test]
fn test_variable_mtu() {
    // Create a large data packet
    let name = Name::from("/test/variable-mtu");
    let content = vec![9u8; 10000]; // 10KB of data
    let data = Data::new(name.clone(), content.clone());
    
    // Fragment with one MTU
    let fragmenter1 = Fragmenter::new(1400);
    let fragments1 = fragmenter1.fragment(&data).expect("Failed to fragment with MTU 1400");
    
    // Fragment with a larger MTU
    let fragmenter2 = Fragmenter::new(4000);
    let fragments2 = fragmenter2.fragment(&data).expect("Failed to fragment with MTU 4000");
    
    // The larger MTU should result in fewer fragments
    assert!(fragments2.len() < fragments1.len(), 
            "Larger MTU should produce fewer fragments");
    
    // Both sets of fragments should reassemble correctly
    let mut reassembler = Reassembler::new();
    
    // Test first set
    for fragment in &fragments1 {
        let result = reassembler.add_fragment(fragment.clone());
        if fragment.sequence() == fragments1.len() - 1 {
            assert!(result.is_some());
            let reassembled = result.unwrap();
            assert_eq!(reassembled.content().as_ref(), content.as_slice());
        } else {
            assert!(result.is_none());
        }
    }
    
    // Reset reassembler
    reassembler = Reassembler::new();
    
    // Test second set
    for fragment in &fragments2 {
        let result = reassembler.add_fragment(fragment.clone());
        if fragment.sequence() == fragments2.len() - 1 {
            assert!(result.is_some());
            let reassembled = result.unwrap();
            assert_eq!(reassembled.content().as_ref(), content.as_slice());
        } else {
            assert!(result.is_none());
        }
    }
}

#[test]
fn test_fragment_name_encoding() {
    // Create a data packet with a complex name
    let name = Name::from("/test/fragment/with/many/components");
    let content = vec![10u8; 3000];
    let data = Data::new(name.clone(), content);
    
    // Fragment the data
    let fragmenter = Fragmenter::new(1400);
    let fragments = fragmenter.fragment(&data).expect("Failed to fragment data");
    
    // Check that all fragments correctly encode the original name
    for fragment in &fragments {
        assert_eq!(fragment.original_name().to_string(), name.to_string());
    }
    
    // Check that a fragment can be properly serialized and deserialized
    let wire_data = fragments[0].to_wire();
    let deserialized = Fragment::from_wire(&wire_data).expect("Failed to deserialize fragment");
    assert_eq!(deserialized.original_name().to_string(), name.to_string());
}
