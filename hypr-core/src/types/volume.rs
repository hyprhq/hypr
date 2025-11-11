//! Volume domain types.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

/// Persistent volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// Volume ID
    pub id: String,

    /// Volume name
    pub name: String,

    /// Volume type
    pub volume_type: VolumeType,

    /// Host path to volume
    pub path: PathBuf,

    /// Size in bytes
    pub size_bytes: u64,

    /// Creation timestamp
    pub created_at: SystemTime,
}

/// Volume type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VolumeType {
    Ext4,
    Xfs,
    Bind,
}

/// Volume mount in VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    /// Volume name or host path
    pub source: String,

    /// Mount path in VM
    pub target: String,

    /// Read-only mount
    pub readonly: bool,
}
