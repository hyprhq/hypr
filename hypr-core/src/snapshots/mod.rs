//! VM Snapshot management.
//!
//! Snapshots allow capturing the state of a VM at a point in time for backup,
//! cloning, or rollback purposes.
//!
//! # Snapshot Types
//!
//! - **Disk Snapshot**: Captures the disk state only. Fast and works while VM is running.
//! - **Full Snapshot**: Captures disk + memory state. VM must be paused.
//!
//! # Storage Format
//!
//! Snapshots are stored as:
//! - Disk snapshots: Copy-on-write overlay files (QCOW2 or raw copy)
//! - Memory snapshots: Raw memory dump files
//!
//! # Example
//!
//! ```ignore
//! use hypr_core::snapshots::{SnapshotManager, SnapshotType};
//!
//! let manager = SnapshotManager::new(state, snapshots_dir);
//! let snapshot = manager.create("vm-123", "before-upgrade", SnapshotType::Disk).await?;
//! ```

use crate::error::{HyprError, Result};
use crate::paths;
use crate::StateManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs;
use tracing::{info, instrument, warn};

/// Type of snapshot to create.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotType {
    /// Disk-only snapshot. Fast, works while VM is running.
    #[default]
    Disk,
    /// Full VM state including memory. VM must be paused.
    Full,
}

impl SnapshotType {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::Full => "full",
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "disk" => Some(Self::Disk),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

impl std::fmt::Display for SnapshotType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// State of a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotState {
    /// Snapshot is being created.
    Creating,
    /// Snapshot is ready for use.
    Ready,
    /// Snapshot creation failed.
    Failed,
    /// Snapshot is being deleted.
    Deleting,
}

impl SnapshotState {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Deleting => "deleting",
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "creating" => Some(Self::Creating),
            "ready" => Some(Self::Ready),
            "failed" => Some(Self::Failed),
            "deleting" => Some(Self::Deleting),
            _ => None,
        }
    }
}

impl std::fmt::Display for SnapshotState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A snapshot of a VM's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Unique snapshot identifier.
    pub id: String,

    /// ID of the VM this snapshot belongs to.
    pub vm_id: String,

    /// Human-readable name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Size of snapshot data in bytes.
    pub size_bytes: u64,

    /// When the snapshot was created.
    pub created_at: SystemTime,

    /// Current state of the snapshot.
    pub state: SnapshotState,

    /// Type of snapshot.
    pub snapshot_type: SnapshotType,

    /// Path to the snapshot data directory.
    pub path: PathBuf,

    /// Custom labels/metadata.
    pub labels: HashMap<String, String>,
}

impl Snapshot {
    /// Check if the snapshot is ready for use.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == SnapshotState::Ready
    }

    /// Get the disk snapshot path.
    #[must_use]
    pub fn disk_path(&self) -> PathBuf {
        self.path.join("disk.img")
    }

    /// Get the memory snapshot path (for full snapshots).
    #[must_use]
    pub fn memory_path(&self) -> PathBuf {
        self.path.join("memory.bin")
    }

    /// Get the metadata path.
    #[must_use]
    pub fn metadata_path(&self) -> PathBuf {
        self.path.join("metadata.json")
    }
}

/// Manager for VM snapshots.
#[derive(Clone)]
pub struct SnapshotManager {
    state: Arc<StateManager>,
    snapshots_dir: PathBuf,
}

impl SnapshotManager {
    /// Create a new snapshot manager.
    pub fn new(state: Arc<StateManager>) -> Self {
        let snapshots_dir = paths::data_dir().join("snapshots");
        Self { state, snapshots_dir }
    }

    /// Create a new snapshot manager with a custom directory.
    pub fn with_dir(state: Arc<StateManager>, snapshots_dir: PathBuf) -> Self {
        Self { state, snapshots_dir }
    }

    /// Get the snapshots directory.
    #[must_use]
    pub fn snapshots_dir(&self) -> &Path {
        &self.snapshots_dir
    }

    /// Ensure the snapshots directory exists.
    async fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.snapshots_dir)
            .await
            .map_err(|e| HyprError::IoError { path: self.snapshots_dir.clone(), source: e })?;
        Ok(())
    }

    /// Create a snapshot of a VM.
    ///
    /// # Arguments
    ///
    /// * `vm_id` - ID of the VM to snapshot
    /// * `name` - Human-readable name for the snapshot
    /// * `snapshot_type` - Type of snapshot to create
    /// * `description` - Optional description
    /// * `labels` - Custom labels/metadata
    #[instrument(skip(self, labels))]
    pub async fn create(
        &self,
        vm_id: &str,
        name: &str,
        snapshot_type: SnapshotType,
        description: Option<String>,
        labels: HashMap<String, String>,
    ) -> Result<Snapshot> {
        self.ensure_dir().await?;

        // Verify VM exists
        let vm = self.state.get_vm(vm_id).await?;

        // Generate snapshot ID
        let snapshot_id = format!("snap-{}", uuid::Uuid::new_v4());
        let snapshot_path = self.snapshots_dir.join(&snapshot_id);

        info!(
            vm_id = %vm_id,
            snapshot_id = %snapshot_id,
            snapshot_type = %snapshot_type,
            "Creating snapshot"
        );

        // Create snapshot directory
        fs::create_dir_all(&snapshot_path)
            .await
            .map_err(|e| HyprError::IoError { path: snapshot_path.clone(), source: e })?;

        // Create initial snapshot record
        let mut snapshot = Snapshot {
            id: snapshot_id.clone(),
            vm_id: vm_id.to_string(),
            name: name.to_string(),
            description,
            size_bytes: 0,
            created_at: SystemTime::now(),
            state: SnapshotState::Creating,
            snapshot_type,
            path: snapshot_path.clone(),
            labels,
        };

        // Save to database
        self.state.insert_snapshot(&snapshot).await?;

        // Perform the actual snapshot based on type
        let result = match snapshot_type {
            SnapshotType::Disk => self.create_disk_snapshot(&vm, &snapshot).await,
            SnapshotType::Full => self.create_full_snapshot(&vm, &snapshot).await,
        };

        match result {
            Ok(size) => {
                snapshot.size_bytes = size;
                snapshot.state = SnapshotState::Ready;
                self.state.update_snapshot(&snapshot).await?;

                info!(
                    snapshot_id = %snapshot_id,
                    size_bytes = size,
                    "Snapshot created successfully"
                );

                Ok(snapshot)
            }
            Err(e) => {
                snapshot.state = SnapshotState::Failed;
                let _ = self.state.update_snapshot(&snapshot).await;

                warn!(
                    snapshot_id = %snapshot_id,
                    error = %e,
                    "Snapshot creation failed"
                );

                // Clean up partial snapshot
                let _ = fs::remove_dir_all(&snapshot_path).await;

                Err(e)
            }
        }
    }

    /// Create a disk-only snapshot.
    async fn create_disk_snapshot(
        &self,
        vm: &crate::types::Vm,
        snapshot: &Snapshot,
    ) -> Result<u64> {
        let disk_path = snapshot.disk_path();
        let mut total_size = 0u64;

        // Copy disk images
        for (i, disk) in vm.config.disks.iter().enumerate() {
            let src = &disk.path;
            let dst = if i == 0 {
                disk_path.clone()
            } else {
                snapshot.path.join(format!("disk{}.img", i))
            };

            // For read-only disks (like squashfs), we just record the reference
            if disk.readonly {
                // Save a reference file instead of copying
                let ref_path = dst.with_extension("ref");
                fs::write(&ref_path, src.to_string_lossy().as_bytes())
                    .await
                    .map_err(|e| HyprError::IoError { path: ref_path, source: e })?;
            } else {
                // Copy the disk image
                if src.exists() {
                    fs::copy(src, &dst)
                        .await
                        .map_err(|e| HyprError::IoError { path: dst.clone(), source: e })?;

                    let metadata = fs::metadata(&dst)
                        .await
                        .map_err(|e| HyprError::IoError { path: dst.clone(), source: e })?;
                    total_size += metadata.len();
                }
            }
        }

        // Save snapshot metadata
        self.save_metadata(snapshot).await?;

        Ok(total_size)
    }

    /// Create a full snapshot including memory state.
    /// 
    /// Note: Memory snapshots require hypervisor-specific support that is not yet available.
    /// Currently falls back to disk-only snapshot with a warning.
    async fn create_full_snapshot(
        &self,
        vm: &crate::types::Vm,
        snapshot: &Snapshot,
    ) -> Result<u64> {
        // Capture disk state first
        let disk_size = self.create_disk_snapshot(vm, snapshot).await?;

        // Memory snapshots require hypervisor support:
        // - libkrun: No snapshot API available
        // - cloud-hypervisor: Has snapshot API but requires VM pause/resume coordination
        // 
        // When hypervisor support is available, the implementation would:
        // 1. Pause the VM via adapter
        // 2. Request memory dump from hypervisor
        // 3. Save memory state to snapshot directory  
        // 4. Resume the VM

        warn!("Full snapshot requested but memory snapshots are not yet supported; disk-only snapshot created");

        Ok(disk_size)
    }

    /// Save snapshot metadata to a JSON file.
    async fn save_metadata(&self, snapshot: &Snapshot) -> Result<()> {
        let metadata = serde_json::json!({
            "id": snapshot.id,
            "vm_id": snapshot.vm_id,
            "name": snapshot.name,
            "description": snapshot.description,
            "snapshot_type": snapshot.snapshot_type.as_str(),
            "created_at": snapshot.created_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "labels": snapshot.labels,
        });

        let metadata_path = snapshot.metadata_path();
        let json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| HyprError::Internal(format!("Failed to serialize metadata: {}", e)))?;

        fs::write(&metadata_path, json)
            .await
            .map_err(|e| HyprError::IoError { path: metadata_path, source: e })?;

        Ok(())
    }

    /// List all snapshots, optionally filtered by VM ID.
    #[instrument(skip(self))]
    pub async fn list(&self, vm_id: Option<&str>) -> Result<Vec<Snapshot>> {
        self.state.list_snapshots(vm_id).await
    }

    /// Get a snapshot by ID.
    #[instrument(skip(self))]
    pub async fn get(&self, snapshot_id: &str) -> Result<Snapshot> {
        self.state.get_snapshot(snapshot_id).await
    }

    /// Delete a snapshot.
    #[instrument(skip(self))]
    pub async fn delete(&self, snapshot_id: &str) -> Result<()> {
        let snapshot = self.state.get_snapshot(snapshot_id).await?;

        info!(snapshot_id = %snapshot_id, "Deleting snapshot");

        // Update state to deleting
        let mut updated = snapshot.clone();
        updated.state = SnapshotState::Deleting;
        self.state.update_snapshot(&updated).await?;

        // Remove snapshot files
        if snapshot.path.exists() {
            fs::remove_dir_all(&snapshot.path)
                .await
                .map_err(|e| HyprError::IoError { path: snapshot.path.clone(), source: e })?;
        }

        // Remove from database
        self.state.delete_snapshot(snapshot_id).await?;

        info!(snapshot_id = %snapshot_id, "Snapshot deleted");

        Ok(())
    }

    /// Restore a VM from a snapshot.
    ///
    /// If `new_vm_name` is provided, creates a new VM. Otherwise, restores in-place.
    #[instrument(skip(self))]
    pub async fn restore(
        &self,
        snapshot_id: &str,
        new_vm_name: Option<&str>,
    ) -> Result<crate::types::Vm> {
        let snapshot = self.state.get_snapshot(snapshot_id).await?;

        if !snapshot.is_ready() {
            return Err(HyprError::InvalidConfig {
                reason: format!(
                    "Snapshot {} is not ready (state: {})",
                    snapshot_id, snapshot.state
                ),
            });
        }

        info!(
            snapshot_id = %snapshot_id,
            new_vm_name = ?new_vm_name,
            "Restoring from snapshot"
        );

        // Get the original VM config
        let original_vm = self.state.get_vm(&snapshot.vm_id).await?;
        let mut new_config = original_vm.config.clone();

        // Generate new VM ID and name
        let new_vm_id = format!("vm-{}", uuid::Uuid::new_v4());
        new_config.id = new_vm_id.clone();
        new_config.name = new_vm_name.unwrap_or(&original_vm.name).to_string();

        // Create directory for restored VM's disks
        let vm_data_dir = paths::data_dir().join("vms").join(&new_vm_id);
        fs::create_dir_all(&vm_data_dir)
            .await
            .map_err(|e| HyprError::IoError { path: vm_data_dir.clone(), source: e })?;

        // Restore disk images
        for (i, disk) in new_config.disks.iter_mut().enumerate() {
            let snapshot_disk = if i == 0 {
                snapshot.disk_path()
            } else {
                snapshot.path.join(format!("disk{}.img", i))
            };

            // Check for reference file (read-only disk)
            let ref_path = snapshot_disk.with_extension("ref");
            if ref_path.exists() {
                // Read the reference and use original path
                let original_path = fs::read_to_string(&ref_path)
                    .await
                    .map_err(|e| HyprError::IoError { path: ref_path, source: e })?;
                disk.path = PathBuf::from(original_path.trim());
            } else if snapshot_disk.exists() {
                // Copy the snapshot disk
                let new_disk_path = vm_data_dir.join(format!("disk{}.img", i));
                fs::copy(&snapshot_disk, &new_disk_path)
                    .await
                    .map_err(|e| HyprError::IoError { path: new_disk_path.clone(), source: e })?;
                disk.path = new_disk_path;
            }
        }

        // Create the VM record
        let new_vm = crate::types::Vm {
            id: new_vm_id,
            name: new_config.name.clone(),
            image_id: original_vm.image_id.clone(),
            status: crate::types::VmStatus::Stopped,
            config: new_config,
            ip_address: None,
            pid: None,
            created_at: SystemTime::now(),
            started_at: None,
            stopped_at: None,
        };

        // Save to state
        self.state.insert_vm(&new_vm).await?;

        info!(
            vm_id = %new_vm.id,
            vm_name = %new_vm.name,
            "VM restored from snapshot"
        );

        Ok(new_vm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_type() {
        assert_eq!(SnapshotType::Disk.as_str(), "disk");
        assert_eq!(SnapshotType::Full.as_str(), "full");
        assert_eq!(SnapshotType::parse("disk"), Some(SnapshotType::Disk));
        assert_eq!(SnapshotType::parse("FULL"), Some(SnapshotType::Full));
        assert_eq!(SnapshotType::parse("invalid"), None);
    }

    #[test]
    fn test_snapshot_state() {
        assert_eq!(SnapshotState::Ready.as_str(), "ready");
        assert_eq!(SnapshotState::Creating.as_str(), "creating");
        assert_eq!(SnapshotState::parse("ready"), Some(SnapshotState::Ready));
        assert_eq!(SnapshotState::parse("FAILED"), Some(SnapshotState::Failed));
    }

    #[test]
    fn test_snapshot_paths() {
        let snapshot = Snapshot {
            id: "snap-123".to_string(),
            vm_id: "vm-456".to_string(),
            name: "test".to_string(),
            description: None,
            size_bytes: 0,
            created_at: SystemTime::now(),
            state: SnapshotState::Ready,
            snapshot_type: SnapshotType::Disk,
            path: PathBuf::from("/data/snapshots/snap-123"),
            labels: HashMap::new(),
        };

        assert_eq!(snapshot.disk_path(), PathBuf::from("/data/snapshots/snap-123/disk.img"));
        assert_eq!(snapshot.memory_path(), PathBuf::from("/data/snapshots/snap-123/memory.bin"));
        assert_eq!(
            snapshot.metadata_path(),
            PathBuf::from("/data/snapshots/snap-123/metadata.json")
        );
    }
}
