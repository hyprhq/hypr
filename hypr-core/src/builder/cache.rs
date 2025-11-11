//! Build cache manager for HYPR.
//!
//! Manages cached build layers to speed up subsequent builds.
//! Each layer is stored as a tarball with metadata, indexed by cache key.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Default cache directory: `~/.hypr/cache/layers/`
const DEFAULT_CACHE_DIR: &str = ".hypr/cache/layers";

/// Default cache size limit: 50GB
const DEFAULT_CACHE_SIZE_LIMIT: u64 = 50 * 1024 * 1024 * 1024; // 50GB in bytes

/// Manages cached build layers.
#[derive(Debug)]
pub struct CacheManager {
    /// Root directory for layer storage
    cache_dir: PathBuf,
    /// Maximum cache size in bytes
    size_limit: u64,
}

/// Metadata for a cached layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerMetadata {
    /// Cache key (SHA256 hash)
    pub cache_key: String,
    /// Size of the layer tarball in bytes
    pub size_bytes: u64,
    /// When this layer was created
    pub created_at: u64, // Unix timestamp
    /// Last time this layer was accessed (for LRU)
    pub last_accessed: u64, // Unix timestamp
    /// Build step description (for debugging)
    pub step_description: String,
    /// Stage index this layer belongs to
    pub stage_index: usize,
}

/// Result of a cache lookup.
#[derive(Debug)]
pub enum CacheLookupResult {
    /// Layer found in cache
    Hit {
        /// Path to the layer tarball
        layer_path: PathBuf,
        /// Layer metadata
        metadata: LayerMetadata,
    },
    /// Layer not found in cache
    Miss,
}

/// Error type for cache operations.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Failed to serialize/deserialize metadata: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid cache key: {0}")]
    InvalidKey(String),

    #[error("Cache directory not accessible: {0}")]
    CacheDirectoryError(String),
}

impl CacheManager {
    /// Creates a new cache manager with default settings.
    ///
    /// Cache directory: `~/.hypr/cache/layers/`
    /// Size limit: 50GB
    pub fn new() -> Result<Self, CacheError> {
        let cache_dir = Self::default_cache_dir()?;
        Self::with_config(cache_dir, DEFAULT_CACHE_SIZE_LIMIT)
    }

    /// Creates a cache manager with custom configuration.
    pub fn with_config(cache_dir: PathBuf, size_limit: u64) -> Result<Self, CacheError> {
        // Create cache directory if it doesn't exist
        fs::create_dir_all(&cache_dir).map_err(|e| {
            CacheError::CacheDirectoryError(format!(
                "Failed to create {}: {}",
                cache_dir.display(),
                e
            ))
        })?;

        Ok(Self {
            cache_dir,
            size_limit,
        })
    }

    /// Looks up a layer by cache key.
    ///
    /// Returns CacheLookupResult::Hit if found, CacheLookupResult::Miss otherwise.
    pub fn lookup(&mut self, cache_key: &str) -> Result<CacheLookupResult, CacheError> {
        let layer_path = self.layer_path(cache_key);
        let metadata_path = self.metadata_path(cache_key);

        // Check if both layer and metadata exist
        if !layer_path.exists() || !metadata_path.exists() {
            debug!("Cache miss for key: {}", cache_key);
            return Ok(CacheLookupResult::Miss);
        }

        // Load metadata
        let mut metadata = self.load_metadata(cache_key)?;

        // Update last accessed time (for LRU)
        metadata.last_accessed = Self::current_timestamp();
        self.save_metadata(&metadata)?;

        info!("Cache hit for key: {} ({})", cache_key, metadata.step_description);

        Ok(CacheLookupResult::Hit {
            layer_path,
            metadata,
        })
    }

    /// Inserts a new layer into the cache.
    ///
    /// # Arguments
    /// * `cache_key` - The cache key (SHA256 hash)
    /// * `layer_data` - The layer tarball data
    /// * `step_description` - Human-readable description of the build step
    /// * `stage_index` - Which stage this layer belongs to
    pub fn insert(
        &mut self,
        cache_key: &str,
        layer_data: &[u8],
        step_description: String,
        stage_index: usize,
    ) -> Result<(), CacheError> {
        // Validate cache key (should be hex string)
        if !cache_key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CacheError::InvalidKey(cache_key.to_string()));
        }

        let layer_path = self.layer_path(cache_key);
        let size_bytes = layer_data.len() as u64;

        // Write layer tarball
        let mut file = fs::File::create(&layer_path)?;
        file.write_all(layer_data)?;

        // Create metadata
        let now = Self::current_timestamp();
        let metadata = LayerMetadata {
            cache_key: cache_key.to_string(),
            size_bytes,
            created_at: now,
            last_accessed: now,
            step_description,
            stage_index,
        };

        // Save metadata
        self.save_metadata(&metadata)?;

        info!(
            "Cached layer {} ({} bytes): {}",
            cache_key, size_bytes, metadata.step_description
        );

        // Check if we need to evict old layers
        self.evict_if_needed()?;

        Ok(())
    }

    /// Removes a layer from the cache.
    pub fn remove(&self, cache_key: &str) -> Result<(), CacheError> {
        let layer_path = self.layer_path(cache_key);
        let metadata_path = self.metadata_path(cache_key);

        if layer_path.exists() {
            fs::remove_file(&layer_path)?;
        }

        if metadata_path.exists() {
            fs::remove_file(&metadata_path)?;
        }

        debug!("Removed layer from cache: {}", cache_key);
        Ok(())
    }

    /// Clears all cached layers.
    pub fn clear(&self) -> Result<(), CacheError> {
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                fs::remove_file(path)?;
            }
        }

        info!("Cleared all cached layers");
        Ok(())
    }

    /// Returns the total size of cached layers in bytes.
    pub fn total_size(&self) -> Result<u64, CacheError> {
        let mut total = 0u64;

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map(|e| e == "tar").unwrap_or(false) {
                if let Ok(metadata) = fs::metadata(&path) {
                    total += metadata.len();
                }
            }
        }

        Ok(total)
    }

    /// Returns the number of cached layers.
    pub fn layer_count(&self) -> Result<usize, CacheError> {
        let mut count = 0;

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map(|e| e == "tar").unwrap_or(false) {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Lists all cached layers sorted by last accessed time (oldest first).
    fn list_layers_by_lru(&self) -> Result<Vec<LayerMetadata>, CacheError> {
        let mut layers = Vec::new();

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Only process .json metadata files
            if path.is_file() && path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(cache_key) = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.strip_prefix("layer-"))
                {
                    if let Ok(metadata) = self.load_metadata(cache_key) {
                        layers.push(metadata);
                    }
                }
            }
        }

        // Sort by last_accessed (oldest first)
        layers.sort_by_key(|m| m.last_accessed);

        Ok(layers)
    }

    /// Evicts old layers if cache size exceeds limit.
    ///
    /// Uses LRU (Least Recently Used) eviction policy.
    fn evict_if_needed(&mut self) -> Result<(), CacheError> {
        let total_size = self.total_size()?;

        if total_size <= self.size_limit {
            return Ok(()); // No eviction needed
        }

        warn!(
            "Cache size ({} bytes) exceeds limit ({} bytes), evicting old layers",
            total_size, self.size_limit
        );

        let layers = self.list_layers_by_lru()?;
        let mut current_size = total_size;

        // Evict oldest layers until we're under the limit
        for layer in layers {
            if current_size <= self.size_limit {
                break;
            }

            info!(
                "Evicting layer {} ({} bytes, last accessed: {})",
                layer.cache_key, layer.size_bytes, layer.last_accessed
            );

            self.remove(&layer.cache_key)?;
            current_size = current_size.saturating_sub(layer.size_bytes);
        }

        let final_size = self.total_size()?;
        info!("Cache eviction complete. New size: {} bytes", final_size);

        Ok(())
    }

    /// Returns the path to a layer tarball.
    fn layer_path(&self, cache_key: &str) -> PathBuf {
        self.cache_dir.join(format!("layer-{}.tar", cache_key))
    }

    /// Returns the path to a layer's metadata file.
    fn metadata_path(&self, cache_key: &str) -> PathBuf {
        self.cache_dir.join(format!("layer-{}.json", cache_key))
    }

    /// Loads metadata for a cached layer.
    fn load_metadata(&self, cache_key: &str) -> Result<LayerMetadata, CacheError> {
        let metadata_path = self.metadata_path(cache_key);
        let mut file = fs::File::open(metadata_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let metadata: LayerMetadata = serde_json::from_str(&contents)?;
        Ok(metadata)
    }

    /// Saves metadata for a cached layer.
    fn save_metadata(&self, metadata: &LayerMetadata) -> Result<(), CacheError> {
        let metadata_path = self.metadata_path(&metadata.cache_key);
        let json = serde_json::to_string_pretty(metadata)?;
        let mut file = fs::File::create(metadata_path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    /// Returns the default cache directory.
    fn default_cache_dir() -> Result<PathBuf, CacheError> {
        let home = dirs::home_dir().ok_or_else(|| {
            CacheError::CacheDirectoryError("Could not determine home directory".into())
        })?;

        Ok(home.join(DEFAULT_CACHE_DIR))
    }

    /// Returns the current Unix timestamp.
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch")
            .as_secs()
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default CacheManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn temp_cache_dir() -> PathBuf {
        let temp = std::env::temp_dir();
        temp.join(format!("hypr-cache-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn test_cache_manager_creation() {
        let cache_dir = temp_cache_dir();
        let _manager = CacheManager::with_config(cache_dir.clone(), 1024 * 1024).unwrap();

        assert!(cache_dir.exists());
        assert!(cache_dir.is_dir());

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_cache_miss() {
        let cache_dir = temp_cache_dir();
        let mut manager = CacheManager::with_config(cache_dir.clone(), 1024 * 1024).unwrap();

        let result = manager.lookup("abc123def456").unwrap();
        assert!(matches!(result, CacheLookupResult::Miss));

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_cache_hit() {
        let cache_dir = temp_cache_dir();
        let mut manager = CacheManager::with_config(cache_dir.clone(), 1024 * 1024).unwrap();

        let cache_key = "abc123def456";
        let layer_data = b"fake layer data";

        // Insert layer
        manager
            .insert(cache_key, layer_data, "test layer".into(), 0)
            .unwrap();

        // Lookup should hit
        let result = manager.lookup(cache_key).unwrap();
        match result {
            CacheLookupResult::Hit { metadata, .. } => {
                assert_eq!(metadata.cache_key, cache_key);
                assert_eq!(metadata.size_bytes, layer_data.len() as u64);
                assert_eq!(metadata.step_description, "test layer");
            }
            CacheLookupResult::Miss => panic!("Expected cache hit"),
        }

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_cache_removal() {
        let cache_dir = temp_cache_dir();
        let mut manager = CacheManager::with_config(cache_dir.clone(), 1024 * 1024).unwrap();

        let cache_key = "abc789def012";
        let layer_data = b"some data";

        manager
            .insert(cache_key, layer_data, "test".into(), 0)
            .unwrap();

        // Should hit
        assert!(matches!(
            manager.lookup(cache_key).unwrap(),
            CacheLookupResult::Hit { .. }
        ));

        // Remove
        manager.remove(cache_key).unwrap();

        // Should miss
        assert!(matches!(
            manager.lookup(cache_key).unwrap(),
            CacheLookupResult::Miss
        ));

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_total_size() {
        let cache_dir = temp_cache_dir();
        let mut manager = CacheManager::with_config(cache_dir.clone(), 1024 * 1024).unwrap();

        let data1 = vec![0u8; 1024]; // 1KB
        let data2 = vec![0u8; 2048]; // 2KB

        manager.insert("aaa111", &data1, "layer1".into(), 0).unwrap();
        manager.insert("bbb222", &data2, "layer2".into(), 0).unwrap();

        let total = manager.total_size().unwrap();
        assert_eq!(total, 3072); // 1KB + 2KB

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_layer_count() {
        let cache_dir = temp_cache_dir();
        let mut manager = CacheManager::with_config(cache_dir.clone(), 1024 * 1024).unwrap();

        assert_eq!(manager.layer_count().unwrap(), 0);

        manager.insert("aaa111", b"data1", "l1".into(), 0).unwrap();
        assert_eq!(manager.layer_count().unwrap(), 1);

        manager.insert("bbb222", b"data2", "l2".into(), 0).unwrap();
        assert_eq!(manager.layer_count().unwrap(), 2);

        manager.remove("aaa111").unwrap();
        assert_eq!(manager.layer_count().unwrap(), 1);

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_lru_eviction() {
        let cache_dir = temp_cache_dir();
        let size_limit = 2048; // 2KB limit
        let mut manager = CacheManager::with_config(cache_dir.clone(), size_limit).unwrap();

        let data1 = vec![0u8; 1024]; // 1KB
        let data2 = vec![0u8; 1024]; // 1KB
        let data3 = vec![0u8; 1024]; // 1KB

        // Insert 3 layers (total 3KB, exceeds 2KB limit)
        manager.insert("aaa111", &data1, "layer1".into(), 0).unwrap();
        thread::sleep(Duration::from_millis(10));

        manager.insert("bbb222", &data2, "layer2".into(), 0).unwrap();
        thread::sleep(Duration::from_millis(10));

        manager.insert("ccc333", &data3, "layer3".into(), 0).unwrap();

        // After eviction, should have <= 2KB
        let total = manager.total_size().unwrap();
        assert!(total <= size_limit, "Total size {} exceeds limit {}", total, size_limit);

        // aaa111 (oldest) should have been evicted
        assert!(matches!(
            manager.lookup("aaa111").unwrap(),
            CacheLookupResult::Miss
        ));

        // bbb222 and ccc333 should still exist
        assert!(matches!(
            manager.lookup("bbb222").unwrap(),
            CacheLookupResult::Hit { .. }
        ));
        assert!(matches!(
            manager.lookup("ccc333").unwrap(),
            CacheLookupResult::Hit { .. }
        ));

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_cache_respects_size_limit() {
        let cache_dir = temp_cache_dir();
        let size_limit = 5 * 1024; // 5KB limit
        let mut manager = CacheManager::with_config(cache_dir.clone(), size_limit).unwrap();

        // Insert 10 layers of 1KB each (total 10KB)
        for i in 0..10 {
            let data = vec![0u8; 1024];
            let key = format!("{:06x}", i); // hex keys: 000000, 000001, etc.
            manager.insert(&key, &data, format!("layer{}", i), 0).unwrap();
            thread::sleep(Duration::from_millis(10));
        }

        // Total size should be <= 5KB (eviction should have happened)
        let total = manager.total_size().unwrap();
        assert!(
            total <= size_limit,
            "Cache size {} exceeds limit {}",
            total,
            size_limit
        );

        // Should have ~5 layers remaining (5KB / 1KB per layer)
        let count = manager.layer_count().unwrap();
        assert!(count <= 6, "Too many layers after eviction: {}", count);

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_clear_cache() {
        let cache_dir = temp_cache_dir();
        let mut manager = CacheManager::with_config(cache_dir.clone(), 1024 * 1024).unwrap();

        manager.insert("aaa111", b"data1", "l1".into(), 0).unwrap();
        manager.insert("bbb222", b"data2", "l2".into(), 0).unwrap();

        assert_eq!(manager.layer_count().unwrap(), 2);

        manager.clear().unwrap();

        assert_eq!(manager.layer_count().unwrap(), 0);
        assert_eq!(manager.total_size().unwrap(), 0);

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn test_invalid_cache_key() {
        let cache_dir = temp_cache_dir();
        let mut manager = CacheManager::with_config(cache_dir.clone(), 1024 * 1024).unwrap();

        // Non-hex characters should fail
        let result = manager.insert("invalid key!", b"data", "test".into(), 0);
        assert!(result.is_err());

        // Cleanup
        let _ = fs::remove_dir_all(cache_dir);
    }
}
