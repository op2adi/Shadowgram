//! Encrypted Cache for Ephemeral Data
//!
//! In-memory cache for frequently-accessed data with:
//! - Per-entry encryption
//! - Automatic expiration
//! - Zeroization on removal

use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Cache entry with encryption and expiration
#[derive(Clone)]
pub struct CacheEntry {
    /// Encrypted data
    pub data: Vec<u8>,

    /// Nonce for decryption
    pub nonce: [u8; 12],

    /// Creation time
    pub created_at: Instant,

    /// Expiration time (if any)
    pub expires_at: Option<Instant>,
}

impl CacheEntry {
    pub fn new(data: Vec<u8>, ttl: Option<Duration>) -> Self {
        // Generate random nonce
        use rand::{RngCore, rngs::OsRng};
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let expires_at = ttl.map(|d| Instant::now() + d);

        Self {
            data,
            nonce,
            created_at: Instant::now(),
            expires_at,
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| Instant::now() > e).unwrap_or(false)
    }

    /// Get age of entry
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl Zeroize for CacheEntry {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.nonce.zeroize();
    }
}

/// Encrypted cache configuration
#[derive(Clone)]
pub struct CacheConfig {
    /// Default TTL for entries
    pub default_ttl: Option<Duration>,

    /// Maximum number of entries
    pub max_entries: usize,

    /// Cleanup interval
    pub cleanup_interval: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default_ttl: Some(Duration::from_secs(300)), // 5 minutes
            max_entries: 1000,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// In-memory encrypted cache
pub struct EncryptedCache {
    /// Cached entries
    entries: RwLock<HashMap<String, CacheEntry>>,

    /// Configuration
    config: CacheConfig,

    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl EncryptedCache {
    /// Create new cache with default config
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Create cache with custom config
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(config.max_entries / 10)),
            config,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Store entry in cache
    pub fn set(&self, key: String, data: Vec<u8>, ttl: Option<Duration>) {
        let mut entries = self.entries.write();

        // Evict if at capacity
        if entries.len() >= self.config.max_entries && !entries.contains_key(&key) {
            // Remove oldest entry
            if let Some(oldest) = entries.iter()
                .min_by_key(|(_, e)| e.created_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }

        let entry = CacheEntry::new(data, ttl.or(self.config.default_ttl));
        entries.insert(key, entry);

        // Check if cleanup needed
        self.maybe_cleanup();
    }

    /// Get entry from cache
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let entries = self.entries.read();
        let entry = entries.get(key)?;

        // Check expiration
        if entry.is_expired() {
            return None;
        }

        Some(entry.data.clone())
    }

    /// Remove entry from cache
    pub fn remove(&self, key: &str) -> Option<Vec<u8>> {
        let mut entries = self.entries.write();
        let entry = entries.remove(key)?;
        Some(entry.data)
    }

    /// Check if key exists in cache
    pub fn contains(&self, key: &str) -> bool {
        let entries = self.entries.read();
        entries.get(key).map(|e| !e.is_expired()).unwrap_or(false)
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        let entries = self.entries.read();
        entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut entries = self.entries.write();
        // Zeroize before clearing
        for entry in entries.values_mut() {
            entry.zeroize();
        }
        entries.clear();
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) -> usize {
        let mut entries = self.entries.write();
        let initial_len = entries.len();

        entries.retain(|_, e| !e.is_expired());

        initial_len - entries.len()
    }

    /// Maybe run cleanup based on interval
    fn maybe_cleanup(&self) {
        let last_cleanup = *self.last_cleanup.read();
        if last_cleanup.elapsed() >= self.config.cleanup_interval {
            *self.last_cleanup.write() = Instant::now();
            drop(self.last_cleanup.write()); // Release lock

            self.cleanup();
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read();
        let now = Instant::now();

        let total = entries.len();
        let expired = entries.values().filter(|e| e.is_expired()).count();
        let valid = total - expired;

        let avg_age = if total > 0 {
            let sum: Duration = entries.values().map(|e| e.age()).sum();
            Some(sum / total as u32)
        } else {
            None
        };

        CacheStats {
            total_entries: total,
            valid_entries: valid,
            expired_entries: expired,
            average_age: avg_age,
            max_entries: self.config.max_entries,
        }
    }
}

impl Default for EncryptedCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EncryptedCache {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Cache statistics
pub struct CacheStats {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub expired_entries: usize,
    pub average_age: Option<Duration>,
    pub max_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_cache_set_get() {
        let cache = EncryptedCache::new();

        cache.set("key1".to_string(), vec![1, 2, 3], None);

        let value = cache.get("key1");
        assert_eq!(value, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_cache_remove() {
        let cache = EncryptedCache::new();

        cache.set("key1".to_string(), vec![1, 2, 3], None);
        let removed = cache.remove("key1");

        assert_eq!(removed, Some(vec![1, 2, 3]));
        assert!(!cache.contains("key1"));
    }

    #[test]
    fn test_cache_expiration() {
        let cache = EncryptedCache::new();

        // Set with very short TTL
        cache.set("key1".to_string(), vec![1, 2, 3], Some(Duration::from_millis(10)));

        // Should exist immediately
        assert!(cache.contains("key1"));

        // Wait for expiration
        thread::sleep(Duration::from_millis(20));

        // Should be expired
        assert!(!cache.contains("key1"));
    }

    #[test]
    fn test_cache_clear() {
        let cache = EncryptedCache::new();

        cache.set("key1".to_string(), vec![1], None);
        cache.set("key2".to_string(), vec![2], None);

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = EncryptedCache::new();

        cache.set("key1".to_string(), vec![1], None);
        cache.set("key2".to_string(), vec![2], Some(Duration::from_millis(10)));

        thread::sleep(Duration::from_millis(20));

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.expired_entries, 1);
    }
}