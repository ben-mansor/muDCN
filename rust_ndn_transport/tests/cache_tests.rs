//
// μDCN Cache Unit Tests
//
// This file contains unit tests for the Content Store implementation.
//

use std::time::{Duration, Instant};
use udcn_transport::cache::ContentStore;
use udcn_transport::name::Name;
use udcn_transport::ndn::Data;

#[test]
fn test_cache_insertion_and_retrieval() {
    // Create a cache with capacity 10
    let mut cache = ContentStore::new(10);
    
    // Create some test data
    let name1 = Name::from("/test/a");
    let content1 = b"content a".to_vec();
    let data1 = Data::new(name1.clone(), content1.clone());
    
    let name2 = Name::from("/test/b");
    let content2 = b"content b".to_vec();
    let data2 = Data::new(name2.clone(), content2.clone());
    
    // Insert data into the cache
    cache.insert(data1.clone());
    cache.insert(data2.clone());
    
    // Test retrieval
    let retrieved1 = cache.get(&name1);
    assert!(retrieved1.is_some(), "Data should be in the cache");
    let retrieved1 = retrieved1.unwrap();
    assert_eq!(retrieved1.name(), &name1);
    assert_eq!(retrieved1.content().as_ref(), content1.as_slice());
    
    let retrieved2 = cache.get(&name2);
    assert!(retrieved2.is_some(), "Data should be in the cache");
    let retrieved2 = retrieved2.unwrap();
    assert_eq!(retrieved2.name(), &name2);
    assert_eq!(retrieved2.content().as_ref(), content2.as_slice());
    
    // Test non-existent entry
    let name3 = Name::from("/test/c");
    let retrieved3 = cache.get(&name3);
    assert!(retrieved3.is_none(), "Data should not be in the cache");
}

#[test]
fn test_cache_eviction() {
    // Create a cache with capacity 2
    let mut cache = ContentStore::new(2);
    
    // Create three data objects
    let name1 = Name::from("/test/a");
    let data1 = Data::new(name1.clone(), b"content a".to_vec());
    
    let name2 = Name::from("/test/b");
    let data2 = Data::new(name2.clone(), b"content b".to_vec());
    
    let name3 = Name::from("/test/c");
    let data3 = Data::new(name3.clone(), b"content c".to_vec());
    
    // Insert all three into the cache - this should cause the first one to be evicted
    cache.insert(data1.clone());
    cache.insert(data2.clone());
    cache.insert(data3.clone());
    
    // Check that name1 was evicted (LRU policy)
    assert!(cache.get(&name1).is_none(), "First entry should have been evicted");
    assert!(cache.get(&name2).is_some(), "Second entry should still be in cache");
    assert!(cache.get(&name3).is_some(), "Third entry should be in cache");
}

#[test]
fn test_cache_update_access_time() {
    // Create a cache with capacity 2
    let mut cache = ContentStore::new(2);
    
    // Create three data objects
    let name1 = Name::from("/test/a");
    let data1 = Data::new(name1.clone(), b"content a".to_vec());
    
    let name2 = Name::from("/test/b");
    let data2 = Data::new(name2.clone(), b"content b".to_vec());
    
    let name3 = Name::from("/test/c");
    let data3 = Data::new(name3.clone(), b"content c".to_vec());
    
    // Insert first two entries
    cache.insert(data1.clone());
    cache.insert(data2.clone());
    
    // Access name1 to update its access time, making name2 the least recently used
    let _ = cache.get(&name1);
    
    // Insert third entry - should evict name2 instead of name1
    cache.insert(data3.clone());
    
    // Check eviction
    assert!(cache.get(&name1).is_some(), "First entry should still be in cache after access");
    assert!(cache.get(&name2).is_none(), "Second entry should have been evicted");
    assert!(cache.get(&name3).is_some(), "Third entry should be in cache");
}

#[test]
fn test_cache_size() {
    // Create a cache with capacity 5
    let mut cache = ContentStore::new(5);
    
    // Test initial size
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
    
    // Add a few entries
    for i in 0..3 {
        let name = Name::from(format!("/test/{}", i));
        let data = Data::new(name, format!("content {}", i).into_bytes());
        cache.insert(data);
    }
    
    // Test updated size
    assert_eq!(cache.len(), 3);
    assert!(!cache.is_empty());
    
    // Add more entries to reach capacity
    for i in 3..5 {
        let name = Name::from(format!("/test/{}", i));
        let data = Data::new(name, format!("content {}", i).into_bytes());
        cache.insert(data);
    }
    
    // Test size at capacity
    assert_eq!(cache.len(), 5);
    
    // Add one more to trigger eviction
    let name = Name::from("/test/5");
    let data = Data::new(name, b"content 5".to_vec());
    cache.insert(data);
    
    // Size should still be at capacity
    assert_eq!(cache.len(), 5);
}

#[test]
fn test_cache_clear() {
    // Create a cache and add some entries
    let mut cache = ContentStore::new(10);
    
    for i in 0..5 {
        let name = Name::from(format!("/test/{}", i));
        let data = Data::new(name, format!("content {}", i).into_bytes());
        cache.insert(data);
    }
    
    assert_eq!(cache.len(), 5);
    
    // Clear the cache
    cache.clear();
    
    // Test that cache is empty
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
    
    // Test that we can't retrieve any entries
    let name = Name::from("/test/0");
    assert!(cache.get(&name).is_none());
}

#[test]
fn test_cache_remove() {
    // Create a cache and add some entries
    let mut cache = ContentStore::new(10);
    
    for i in 0..5 {
        let name = Name::from(format!("/test/{}", i));
        let data = Data::new(name, format!("content {}", i).into_bytes());
        cache.insert(data);
    }
    
    // Remove a specific entry
    let name = Name::from("/test/2");
    let removed = cache.remove(&name);
    
    // Test that removal was successful
    assert!(removed, "Entry should have been removed");
    assert_eq!(cache.len(), 4);
    assert!(cache.get(&name).is_none());
    
    // Test removing a non-existent entry
    let name = Name::from("/test/nonexistent");
    let removed = cache.remove(&name);
    assert!(!removed, "Non-existent entry should not report removal");
    assert_eq!(cache.len(), 4);
}

#[test]
fn test_cache_expiration() {
    // Create a cache with a short expiration time
    let expiry = Duration::from_millis(100);
    let mut cache = ContentStore::with_expiry(10, Some(expiry));
    
    // Add an entry
    let name = Name::from("/test/expiring");
    let data = Data::new(name.clone(), b"expiring content".to_vec());
    cache.insert(data);
    
    // Verify it's in the cache
    assert!(cache.get(&name).is_some());
    
    // Wait for expiration
    std::thread::sleep(Duration::from_millis(150));
    
    // Verify it's no longer in the cache
    assert!(cache.get(&name).is_none(), "Entry should have expired");
    
    // Test that newly added entries are not expired
    let name = Name::from("/test/fresh");
    let data = Data::new(name.clone(), b"fresh content".to_vec());
    cache.insert(data);
    
    assert!(cache.get(&name).is_some(), "Fresh entry should be retrievable");
}

#[test]
fn test_cache_prefetch() {
    // Create a cache
    let mut cache = ContentStore::new(10);
    
    // Create a prefix and some matching data
    let prefix = Name::from("/test/prefix");
    
    let name1 = Name::from("/test/prefix/a");
    let data1 = Data::new(name1.clone(), b"content a".to_vec());
    
    let name2 = Name::from("/test/prefix/b");
    let data2 = Data::new(name2.clone(), b"content b".to_vec());
    
    let name3 = Name::from("/test/other/c");  // Different prefix
    let data3 = Data::new(name3.clone(), b"content c".to_vec());
    
    // Insert all data
    cache.insert(data1);
    cache.insert(data2);
    cache.insert(data3);
    
    // Get all data matching the prefix
    let prefetch_results = cache.prefetch(&prefix);
    
    // Verify the results
    assert_eq!(prefetch_results.len(), 2, "Should have found 2 matching entries");
    
    // Check that the correct entries were retrieved
    let names: Vec<String> = prefetch_results.iter()
        .map(|data| data.name().to_string())
        .collect();
    
    assert!(names.contains(&name1.to_string()));
    assert!(names.contains(&name2.to_string()));
    assert!(!names.contains(&name3.to_string()));
}

#[test]
fn test_cache_metrics() {
    // Create a cache with metrics tracking
    let mut cache = ContentStore::with_metrics(5);
    
    // Initial metrics should be zero
    assert_eq!(cache.hits(), 0);
    assert_eq!(cache.misses(), 0);
    assert_eq!(cache.hit_ratio(), 0.0);
    
    // Add an entry
    let name1 = Name::from("/test/a");
    let data1 = Data::new(name1.clone(), b"content a".to_vec());
    cache.insert(data1);
    
    // Hit the cache
    let _ = cache.get(&name1);
    assert_eq!(cache.hits(), 1);
    assert_eq!(cache.misses(), 0);
    assert_eq!(cache.hit_ratio(), 1.0);
    
    // Miss the cache
    let name2 = Name::from("/test/b");
    let _ = cache.get(&name2);
    assert_eq!(cache.hits(), 1);
    assert_eq!(cache.misses(), 1);
    assert_eq!(cache.hit_ratio(), 0.5);
    
    // Reset metrics
    cache.reset_metrics();
    assert_eq!(cache.hits(), 0);
    assert_eq!(cache.misses(), 0);
    assert_eq!(cache.hit_ratio(), 0.0);
}
