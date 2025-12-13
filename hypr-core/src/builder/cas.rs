//! Content-Addressable Storage (CAS) for build layer deduplication.
//!
//! Files are stored by their SHA256 digest, automatically deduplicating
//! identical content across different layers.
//!
//! # Architecture
//!
//! ```text
//! blobs/
//! └── sha256/
//!     ├── a1b2c3...  # File content (named by digest)
//!     ├── d4e5f6...
//!     └── ...
//! manifests/
//! └── layer-abc123.json  # Layer manifest (list of files -> blobs)
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Entry for a file in a layer manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path in the layer
    pub path: String,
    /// SHA256 digest of the file content
    pub blob_digest: String,
    /// File size in bytes
    pub size: u64,
    /// Unix file mode (permissions)
    pub mode: u32,
    /// Modification time (Unix timestamp)
    pub mtime: i64,
    /// True if this is a directory
    pub is_dir: bool,
    /// True if this is a symlink
    pub is_symlink: bool,
    /// Symlink target (if is_symlink)
    #[serde(default)]
    pub symlink_target: Option<String>,
}

/// Manifest describing all files in a layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerManifest {
    /// Layer ID (cache key)
    pub id: String,
    /// All file entries in this layer
    pub entries: Vec<FileEntry>,
    /// Total uncompressed size of all files
    pub total_size: u64,
    /// When this manifest was created
    pub created_at: i64,
    /// Build step that created this layer
    pub created_by: String,
}

/// Content-Addressable Storage manager.
pub struct CasStore {
    /// Root directory for blob storage
    blobs_dir: PathBuf,
    /// Directory for layer manifests
    manifests_dir: PathBuf,
    /// In-memory cache of blob existence (digest -> exists)
    blob_cache: HashMap<String, bool>,
}

impl CasStore {
    /// Create a new CAS store.
    pub fn new(base_dir: &Path) -> io::Result<Self> {
        let blobs_dir = base_dir.join("blobs").join("sha256");
        let manifests_dir = base_dir.join("manifests");

        fs::create_dir_all(&blobs_dir)?;
        fs::create_dir_all(&manifests_dir)?;

        Ok(Self { blobs_dir, manifests_dir, blob_cache: HashMap::new() })
    }

    /// Store a blob and return its digest.
    ///
    /// If the blob already exists, this is a no-op and just returns the digest.
    pub fn store_blob(&mut self, data: &[u8]) -> io::Result<String> {
        let digest = self.compute_digest(data);

        // Check cache first
        if self.blob_cache.get(&digest).copied().unwrap_or(false) {
            debug!(digest = %digest, "Blob already exists (cached)");
            return Ok(digest);
        }

        let blob_path = self.blob_path(&digest);

        // Check disk
        if blob_path.exists() {
            self.blob_cache.insert(digest.clone(), true);
            debug!(digest = %digest, "Blob already exists (on disk)");
            return Ok(digest);
        }

        // Store new blob
        let mut file = File::create(&blob_path)?;
        file.write_all(data)?;

        self.blob_cache.insert(digest.clone(), true);
        debug!(digest = %digest, size = data.len(), "Stored new blob");

        Ok(digest)
    }

    /// Retrieve a blob by digest.
    pub fn get_blob(&self, digest: &str) -> io::Result<Vec<u8>> {
        let blob_path = self.blob_path(digest);
        fs::read(blob_path)
    }

    /// Check if a blob exists.
    pub fn blob_exists(&mut self, digest: &str) -> bool {
        if let Some(&exists) = self.blob_cache.get(digest) {
            return exists;
        }

        let exists = self.blob_path(digest).exists();
        self.blob_cache.insert(digest.to_string(), exists);
        exists
    }

    /// Store a layer manifest.
    pub fn store_manifest(&self, manifest: &LayerManifest) -> io::Result<()> {
        let path = self.manifest_path(&manifest.id);
        let json = serde_json::to_string_pretty(manifest)?;
        fs::write(path, json)?;
        info!(id = %manifest.id, entries = manifest.entries.len(), "Stored layer manifest");
        Ok(())
    }

    /// Load a layer manifest by ID.
    pub fn get_manifest(&self, id: &str) -> io::Result<LayerManifest> {
        let path = self.manifest_path(id);
        let json = fs::read_to_string(path)?;
        let manifest: LayerManifest = serde_json::from_str(&json)?;
        Ok(manifest)
    }

    /// Check if a manifest exists.
    pub fn manifest_exists(&self, id: &str) -> bool {
        self.manifest_path(id).exists()
    }

    /// Get the total size of all blobs.
    pub fn total_blob_size(&self) -> io::Result<u64> {
        let mut total = 0u64;

        for entry in fs::read_dir(&self.blobs_dir)? {
            let entry = entry?;
            if entry.path().is_file() {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            }
        }

        Ok(total)
    }

    /// Get the number of unique blobs.
    pub fn blob_count(&self) -> io::Result<usize> {
        Ok(fs::read_dir(&self.blobs_dir)?.filter(|e| e.is_ok()).count())
    }

    /// Compute SHA256 digest of data.
    fn compute_digest(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Get the path for a blob.
    fn blob_path(&self, digest: &str) -> PathBuf {
        // Use first 2 chars as subdirectory for better filesystem performance
        let subdir = &digest[..2.min(digest.len())];
        let path = self.blobs_dir.join(subdir);
        let _ = fs::create_dir_all(&path);
        path.join(digest)
    }

    /// Get the path for a manifest.
    fn manifest_path(&self, id: &str) -> PathBuf {
        self.manifests_dir.join(format!("{}.json", id))
    }

    /// Garbage collect unreferenced blobs.
    ///
    /// Returns the number of blobs removed.
    pub fn gc(&mut self) -> io::Result<usize> {
        // Collect all blob digests referenced by manifests
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();

        for entry in fs::read_dir(&self.manifests_dir)? {
            let entry = entry?;
            if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(manifest) = self
                    .get_manifest(entry.path().file_stem().and_then(|s| s.to_str()).unwrap_or(""))
                {
                    for file_entry in &manifest.entries {
                        referenced.insert(file_entry.blob_digest.clone());
                    }
                }
            }
        }

        // Remove unreferenced blobs
        let mut removed = 0;

        // Walk the blob subdirectories
        for subdir_entry in fs::read_dir(&self.blobs_dir)? {
            let subdir_entry = subdir_entry?;
            if subdir_entry.path().is_dir() {
                for blob_entry in fs::read_dir(subdir_entry.path())? {
                    let blob_entry = blob_entry?;
                    let path = blob_entry.path();

                    if let Some(digest) = path.file_name().and_then(|n| n.to_str()) {
                        if !referenced.contains(digest) {
                            fs::remove_file(&path)?;
                            self.blob_cache.remove(digest);
                            removed += 1;
                        }
                    }
                }
            }
        }

        if removed > 0 {
            info!(removed, "Garbage collected unreferenced blobs");
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_store_and_retrieve_blob() {
        let temp = TempDir::new().unwrap();
        let mut store = CasStore::new(temp.path()).unwrap();

        let data = b"Hello, World!";
        let digest = store.store_blob(data).unwrap();

        // Same data should return same digest
        let digest2 = store.store_blob(data).unwrap();
        assert_eq!(digest, digest2);

        // Should be able to retrieve
        let retrieved = store.get_blob(&digest).unwrap();
        assert_eq!(data.as_slice(), retrieved.as_slice());
    }

    #[test]
    fn test_deduplication() {
        let temp = TempDir::new().unwrap();
        let mut store = CasStore::new(temp.path()).unwrap();

        // Store same content multiple times
        let data = b"Duplicate content";
        store.store_blob(data).unwrap();
        store.store_blob(data).unwrap();
        store.store_blob(data).unwrap();

        // Should only have 1 blob
        assert_eq!(store.blob_count().unwrap(), 1);
    }

    #[test]
    fn test_manifest_storage() {
        let temp = TempDir::new().unwrap();
        let store = CasStore::new(temp.path()).unwrap();

        let manifest = LayerManifest {
            id: "test-layer-123".to_string(),
            entries: vec![FileEntry {
                path: "/etc/passwd".to_string(),
                blob_digest: "abc123".to_string(),
                size: 1234,
                mode: 0o644,
                mtime: 1234567890,
                is_dir: false,
                is_symlink: false,
                symlink_target: None,
            }],
            total_size: 1234,
            created_at: 1234567890,
            created_by: "RUN echo hello".to_string(),
        };

        store.store_manifest(&manifest).unwrap();
        assert!(store.manifest_exists("test-layer-123"));

        let loaded = store.get_manifest("test-layer-123").unwrap();
        assert_eq!(loaded.id, manifest.id);
        assert_eq!(loaded.entries.len(), 1);
    }
}
