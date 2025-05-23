//
// μDCN Content Store Implementation
//
// This module implements a high-performance content store for caching NDN data.
// It uses an LRU cache with TTL support for efficient caching.
//

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use tracing::{debug, info, trace};

// use crate::error::Error;
use crate::name::Name;
use crate::ndn::Data;
// use crate::Result;

/// Default content store capacity
const DEFAULT_CAPACITY: usize = 10_000;

/// Default content TTL in seconds
const DEFAULT_TTL_SECONDS: u64 = 3600;

// Simplified metrics for compatibility
pub struct DummyCounter;
pub struct DummyGauge;

// Mock implementation of Counter
impl DummyCounter {
    pub fn inc(&self) {
        // Do nothing, just a stub
    }
}

// Mock implementation of Gauge
impl DummyGauge {
    pub fn set(&self, _value: f64) {
        // Do nothing, just a stub
    }
}

lazy_static! {
    // Placeholder metrics - these won't actually register with Prometheus
    // but allow the code to compile
    static ref CACHE_SIZE: DummyGauge = DummyGauge {};
    static ref CACHE_CAPACITY: DummyGauge = DummyGauge {};
    static ref CACHE_HITS: DummyCounter = DummyCounter {};
    static ref CACHE_MISSES: DummyCounter = DummyCounter {};
    static ref CACHE_INSERTS: DummyCounter = DummyCounter {};
    static ref CACHE_EVICTIONS: DummyCounter = DummyCounter {};
    static ref CACHE_EXPIRATIONS: DummyCounter = DummyCounter {};
}

/// A cached data entry with expiration time
struct CacheEntry {
    /// The cached data
    data: Data,
    
    /// When this entry was created
    created_at: Instant,
    
    /// Time-to-live in seconds
    ttl: u64,
}

impl CacheEntry {
    /// Create a new cache entry
    fn new(data: Data, ttl: u64) -> Self {
        Self {
            data,
            created_at: Instant::now(),
            ttl,
        }
    }
    
    /// Check if the entry has expired
    fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() > self.ttl
    }
    
    /// Get the remaining TTL in seconds
    fn remaining_ttl(&self) -> u64 {
        let elapsed = self.created_at.elapsed().as_secs();
        if elapsed >= self.ttl {
            0
        } else {
            self.ttl - elapsed
        }
    }
}

/// Content store for caching NDN data
///
/// This implementation uses a two-level caching strategy:
/// 1. An LRU cache for fast access to the most recently used items
/// 2. A DashMap for concurrent access to all cached items
///
/// The LRU cache acts as a fast path for the most frequently accessed items,
/// while the DashMap provides concurrent access to all cached items.
pub struct ContentStore {
    /// LRU cache for fast access to the most recently used items
    lru: Mutex<LruCache<Name, Arc<CacheEntry>>>,
    
    /// Map of all cached items for concurrent access
    map: DashMap<Name, Arc<CacheEntry>>,
    
    /// Maximum capacity of the cache
    capacity: usize,
    
    /// Default TTL for cached items
    default_ttl: u64,
}

impl ContentStore {
    /// Create a new content store with the given capacity
    pub fn new(capacity: usize) -> Self {
        // Initialize the LRU cache with 1/10 of the total capacity
        // This represents the "hot" items that are accessed most frequently
        let lru_capacity = std::cmp::max(1, capacity / 10);
        
        // Set the Prometheus gauge for capacity
        CACHE_CAPACITY.set(capacity as f64);
        
        info!("Creating content store with capacity {}", capacity);
        
        Self {
            lru: Mutex::new(LruCache::new(std::num::NonZeroUsize::new(lru_capacity).unwrap())),
            map: DashMap::with_capacity(capacity),
            capacity,
            default_ttl: DEFAULT_TTL_SECONDS,
        }
    }
    
    /// Create a new content store with default capacity
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
    
    /// Set the default TTL for cached items
    pub fn set_default_ttl(&mut self, ttl: Duration) {
        self.default_ttl = ttl.as_secs();
    }
    
    /// Get the current default TTL
    pub fn default_ttl(&self) -> Duration {
        Duration::from_secs(self.default_ttl)
    }
    
    /// Insert a data item into the cache
    ///
    /// If the cache is full, the least recently used item will be evicted.
    pub fn insert(&mut self, name: Name, data: Data) {
        self.insert_with_ttl(name, data, self.default_ttl);
    }
    
    /// Insert a data item with a specific TTL
    pub fn insert_with_ttl(&mut self, name: Name, data: Data, ttl: u64) {
        // Check if we need to evict items to make room
        if self.map.len() >= self.capacity && !self.map.contains_key(&name) {
            self.evict_one();
        }
        
        // Create the cache entry
        let entry = Arc::new(CacheEntry::new(data, ttl));
        
        // Insert into both caches
        self.map.insert(name.clone(), Arc::clone(&entry));
        self.lru.lock().put(name.clone(), entry);
        
        // Update metrics
        CACHE_SIZE.set(self.map.len() as f64);
        CACHE_INSERTS.inc();
        
        trace!("Inserted data for {}", name);
    }
    
    /// Get a data item from the cache
    ///
    /// Returns None if the item is not in the cache or has expired.
    pub fn get(&self, name: &Name) -> Option<Data> {
        // First check the LRU cache (fast path)
        let mut lru = self.lru.lock();
        if let Some(entry) = lru.get(name) {
            if entry.is_expired() {
                // Entry has expired, remove it from both caches
                lru.pop(name);
                self.map.remove(name);
                CACHE_EXPIRATIONS.inc();
                CACHE_SIZE.set(self.map.len() as f64);
                debug!("Expired entry for {}", name);
                CACHE_MISSES.inc();
                return None;
            }
            
            // Entry is valid, return a clone of the data
            trace!("LRU cache hit for {}", name);
            CACHE_HITS.inc();
            return Some(entry.data.clone());
        }
        
        // Check the main map
        if let Some(entry) = self.map.get(name) {
            if entry.is_expired() {
                // Entry has expired, remove it
                self.map.remove(name);
                CACHE_EXPIRATIONS.inc();
                CACHE_SIZE.set(self.map.len() as f64);
                debug!("Expired entry for {}", name);
                CACHE_MISSES.inc();
                return None;
            }
            
            // Entry is valid, promote it to the LRU cache and return a clone
            lru.put(name.clone(), Arc::clone(&entry));
            trace!("Map cache hit for {}", name);
            CACHE_HITS.inc();
            return Some(entry.data.clone());
        }
        
        // Not found in either cache
        trace!("Cache miss for {}", name);
        CACHE_MISSES.inc();
        None
    }
    
    /// Check if the cache contains an item
    ///
    /// This does not update the LRU order.
    pub fn contains(&self, name: &Name) -> bool {
        // First check the LRU cache (fast path)
        let lru = self.lru.lock();
        if lru.contains(name) {
            return true;
        }
        
        // Check the main map
        self.map.contains_key(name)
    }
    
    /// Remove an item from the cache
    ///
    /// Returns true if the item was removed, false if it wasn't in the cache.
    pub fn remove(&mut self, name: &Name) -> bool {
        // Remove from the LRU cache
        let mut lru = self.lru.lock();
        let in_lru = lru.pop(name).is_some();
        
        // Remove from the main map
        let in_map = self.map.remove(name).is_some();
        
        if in_lru || in_map {
            CACHE_SIZE.set(self.map.len() as f64);
        }
        
        in_lru || in_map
    }
    
    /// Clear the cache
    pub fn clear(&mut self) {
        let mut lru = self.lru.lock();
        lru.clear();
        self.map.clear();
        CACHE_SIZE.set(0.0);
        info!("Cleared content store");
    }
    
    /// Get the number of items in the cache
    pub fn len(&self) -> usize {
        self.map.len()
    }
    
    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    
    /// Evict one item from the cache
    ///
    /// This uses the LRU policy to decide which item to evict.
    /// If the LRU cache is empty, it evicts a random item from the main map.
    fn evict_one(&mut self) {
        // Try to evict from the LRU cache
        let mut lru = self.lru.lock();
        if let Some((name, _)) = lru.pop_lru() {
            // Also remove from the main map
            self.map.remove(&name);
            CACHE_EVICTIONS.inc();
            trace!("Evicted LRU entry for {}", name);
            return;
        }
        
        // If the LRU cache is empty, evict a random item from the main map
        if let Some(entry) = self.map.iter().next() {
            let name = entry.key().clone();
            self.map.remove(&name);
            CACHE_EVICTIONS.inc();
            trace!("Evicted random entry for {}", name);
        }
    }
    
    /// Expire all entries that have exceeded their TTL
    ///
    /// This is an expensive operation and should be called periodically,
    /// not on every cache access.
    pub fn expire_old_entries(&mut self) -> usize {
        let mut expired = 0;
        
        // Collect all expired keys
        let expired_keys: Vec<Name> = self.map
            .iter()
            .filter(|entry| entry.value().is_expired())
            .map(|entry| entry.key().clone())
            .collect();
        
        // Remove expired entries
        for name in expired_keys {
            self.remove(&name);
            expired += 1;
        }
        
        if expired > 0 {
            CACHE_EXPIRATIONS.inc_by(expired as f64);
            debug!("Expired {} old entries", expired);
        }
        
        expired
    }
    
    /// Get the remaining TTL for a cached item
    ///
    /// Returns None if the item is not in the cache or has expired.
    pub fn get_ttl(&self, name: &Name) -> Option<Duration> {
        // Check the main map
        if let Some(entry) = self.map.get(name) {
            if entry.is_expired() {
                None
            } else {
                Some(Duration::from_secs(entry.remaining_ttl()))
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndn::{Data, Interest};
    
    #[test]
    fn test_content_store_basic() {
        let mut cs = ContentStore::new(10);
        
        // Create test data
        let name = Name::from_uri("/test/data").unwrap();
        let data = Data::new(name.clone(), vec![1, 2, 3, 4]);
        
        // Insert and retrieve
        cs.insert(name.clone(), data.clone());
        
        let retrieved = cs.get(&name);
        assert!(retrieved.is_some());
        
        // Check content equality
        let retrieved_data = retrieved.unwrap();
        assert_eq!(retrieved_data.name(), data.name());
        assert_eq!(retrieved_data.content(), data.content());
    }
    
    #[test]
    fn test_content_store_expiration() {
        let mut cs = ContentStore::new(10);
        
        // Create test data
        let name = Name::from_uri("/test/data").unwrap();
        let data = Data::new(name.clone(), vec![1, 2, 3, 4]);
        
        // Insert with a very short TTL (1 second)
        cs.insert_with_ttl(name.clone(), data.clone(), 1);
        
        // Should be available immediately
        assert!(cs.get(&name).is_some());
        
        // Wait for expiration
        std::thread::sleep(Duration::from_secs(2));
        
        // Should be expired now
        assert!(cs.get(&name).is_none());
    }
    
    #[test]
    fn test_content_store_eviction() {
        let mut cs = ContentStore::new(3);
        
        // Create test data
        let names = vec![
            Name::from_uri("/test/data1").unwrap(),
            Name::from_uri("/test/data2").unwrap(),
            Name::from_uri("/test/data3").unwrap(),
            Name::from_uri("/test/data4").unwrap(),
        ];
        
        // Insert 3 items
        for i in 0..3 {
            let data = Data::new(names[i].clone(), vec![i as u8]);
            cs.insert(names[i].clone(), data);
        }
        
        // All 3 should be in the cache
        for i in 0..3 {
            assert!(cs.get(&names[i]).is_some());
        }
        
        // Insert a 4th item, which should evict the least recently used
        let data = Data::new(names[3].clone(), vec![3]);
        cs.insert(names[3].clone(), data);
        
        // The 4th item should be in the cache
        assert!(cs.get(&names[3]).is_some());
        
        // One of the previous items should have been evicted,
        // but we can't know which one in this test
        assert!(cs.len() == 3);
    }
}
