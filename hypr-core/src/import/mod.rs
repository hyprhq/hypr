//! Docker import types and utilities.
//!
//! This module provides types for importing Docker containers and images into HYPR.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Stage of the import process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ImportStage {
    /// Discovering containers/images.
    #[default]
    Discovering,
    /// Exporting from Docker.
    Exporting,
    /// Converting to HYPR format.
    Converting,
    /// Importing into HYPR.
    Importing,
    /// Copying volume data.
    CopyingVolumes,
    /// Creating networks.
    CreatingNetworks,
    /// Starting VM.
    Starting,
}

impl ImportStage {
    /// Parse stage from string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "discovering" => ImportStage::Discovering,
            "exporting" => ImportStage::Exporting,
            "converting" => ImportStage::Converting,
            "importing" => ImportStage::Importing,
            "copying_volumes" => ImportStage::CopyingVolumes,
            "creating_networks" => ImportStage::CreatingNetworks,
            "starting" => ImportStage::Starting,
            _ => ImportStage::Discovering,
        }
    }

    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ImportStage::Discovering => "discovering",
            ImportStage::Exporting => "exporting",
            ImportStage::Converting => "converting",
            ImportStage::Importing => "importing",
            ImportStage::CopyingVolumes => "copying_volumes",
            ImportStage::CreatingNetworks => "creating_networks",
            ImportStage::Starting => "starting",
        }
    }

    /// Convert to proto enum value.
    pub fn to_proto(&self) -> i32 {
        match self {
            ImportStage::Discovering => 1,
            ImportStage::Exporting => 2,
            ImportStage::Converting => 3,
            ImportStage::Importing => 4,
            ImportStage::CopyingVolumes => 5,
            ImportStage::CreatingNetworks => 6,
            ImportStage::Starting => 7,
        }
    }

    /// Create from proto enum value.
    pub fn from_proto(value: i32) -> Self {
        match value {
            1 => ImportStage::Discovering,
            2 => ImportStage::Exporting,
            3 => ImportStage::Converting,
            4 => ImportStage::Importing,
            5 => ImportStage::CopyingVolumes,
            6 => ImportStage::CreatingNetworks,
            7 => ImportStage::Starting,
            _ => ImportStage::Discovering,
        }
    }
}

impl std::fmt::Display for ImportStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Options for importing Docker containers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportContainersOptions {
    /// Include container volumes.
    pub include_volumes: bool,
    /// Include container networks.
    pub include_networks: bool,
    /// Specific container IDs to import (empty = all running).
    pub container_ids: Vec<String>,
    /// Stop Docker containers after import.
    pub stop_containers: bool,
    /// Preserve original container names.
    pub preserve_names: bool,
}

impl Default for ImportContainersOptions {
    fn default() -> Self {
        Self {
            include_volumes: true,
            include_networks: true,
            container_ids: Vec::new(),
            stop_containers: false,
            preserve_names: false,
        }
    }
}

/// Options for importing a Docker image.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportImageOptions {
    /// Docker image name:tag or ID.
    pub image: String,
    /// Custom name for HYPR image.
    pub new_name: Option<String>,
    /// Custom tag for HYPR image.
    pub new_tag: Option<String>,
}

/// Information about a Docker container discovered for import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerContainerInfo {
    /// Container ID.
    pub id: String,
    /// Container name.
    pub name: String,
    /// Image used by the container.
    pub image: String,
    /// Container status (running, stopped, etc).
    pub status: String,
    /// Container ports.
    pub ports: Vec<DockerPortMapping>,
    /// Container mounts/volumes.
    pub mounts: Vec<DockerMount>,
    /// Container environment variables.
    pub env: HashMap<String, String>,
    /// Container command.
    pub command: Vec<String>,
    /// Container labels.
    pub labels: HashMap<String, String>,
    /// Networks container is connected to.
    pub networks: Vec<String>,
}

/// Docker port mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerPortMapping {
    /// Host port.
    pub host_port: u16,
    /// Container port.
    pub container_port: u16,
    /// Protocol (tcp/udp).
    pub protocol: String,
    /// Host IP (0.0.0.0 for all).
    pub host_ip: String,
}

/// Docker mount/volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerMount {
    /// Mount type (bind, volume, tmpfs).
    pub mount_type: String,
    /// Source path or volume name.
    pub source: String,
    /// Destination path in container.
    pub destination: String,
    /// Read-only flag.
    pub read_only: bool,
}

/// Information about a Docker image discovered for import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerImageInfo {
    /// Image ID.
    pub id: String,
    /// Repository tags.
    pub tags: Vec<String>,
    /// Image size in bytes.
    pub size_bytes: u64,
    /// Creation timestamp.
    pub created_at: i64,
    /// Image architecture.
    pub architecture: String,
    /// Image OS.
    pub os: String,
    /// Entrypoint.
    pub entrypoint: Vec<String>,
    /// Default command.
    pub cmd: Vec<String>,
    /// Environment variables.
    pub env: HashMap<String, String>,
    /// Working directory.
    pub workdir: String,
    /// Exposed ports.
    pub exposed_ports: Vec<u16>,
    /// User to run as.
    pub user: Option<String>,
}

/// Progress update during import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportProgress {
    /// Resource name being processed.
    pub resource_name: String,
    /// Current stage.
    pub stage: ImportStage,
    /// Human-readable message.
    pub message: String,
    /// Progress percentage (0-100).
    pub percent: u32,
    /// Current item index.
    pub current: u32,
    /// Total items to process.
    pub total: u32,
}

/// Result of importing a single container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedContainer {
    /// Original Docker container ID.
    pub docker_container_id: String,
    /// Original Docker container name.
    pub docker_container_name: String,
    /// Created HYPR VM ID.
    pub vm_id: String,
    /// Created HYPR VM name.
    pub vm_name: String,
}

/// Result of importing a single image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedImage {
    /// Original Docker image ID.
    pub docker_image_id: String,
    /// Original Docker image name:tag.
    pub docker_image_name: String,
    /// Created HYPR image ID.
    pub image_id: String,
    /// Created HYPR image name.
    pub image_name: String,
}

/// Summary of import operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportSummary {
    /// Number of containers imported.
    pub containers_imported: u32,
    /// Number of images imported.
    pub images_imported: u32,
    /// Number of volumes created.
    pub volumes_created: u32,
    /// Number of networks created.
    pub networks_created: u32,
    /// Total duration in seconds.
    pub duration_sec: u32,
    /// List of imported containers.
    pub containers: Vec<ImportedContainer>,
    /// List of imported images.
    pub images: Vec<ImportedImage>,
}

/// Docker importer for discovering and importing Docker resources.
pub struct DockerImporter {
    /// Docker socket path.
    socket_path: std::path::PathBuf,
}

impl DockerImporter {
    /// Create a new Docker importer with the default socket.
    pub fn new() -> Self {
        Self { socket_path: std::path::PathBuf::from("/var/run/docker.sock") }
    }

    /// Create a new Docker importer with a custom socket path.
    pub fn with_socket(socket_path: std::path::PathBuf) -> Self {
        Self { socket_path }
    }

    /// Check if Docker is available.
    pub fn is_available(&self) -> bool {
        self.socket_path.exists()
    }

    /// Get the Docker socket path.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }
}

impl Default for DockerImporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_stage_parse() {
        assert_eq!(ImportStage::parse("discovering"), ImportStage::Discovering);
        assert_eq!(ImportStage::parse("EXPORTING"), ImportStage::Exporting);
        assert_eq!(ImportStage::parse("converting"), ImportStage::Converting);
        assert_eq!(ImportStage::parse("importing"), ImportStage::Importing);
        assert_eq!(ImportStage::parse("copying_volumes"), ImportStage::CopyingVolumes);
        assert_eq!(ImportStage::parse("unknown"), ImportStage::Discovering);
    }

    #[test]
    fn test_import_stage_proto() {
        assert_eq!(ImportStage::Discovering.to_proto(), 1);
        assert_eq!(ImportStage::from_proto(1), ImportStage::Discovering);
        assert_eq!(ImportStage::Exporting.to_proto(), 2);
        assert_eq!(ImportStage::from_proto(2), ImportStage::Exporting);
    }

    #[test]
    fn test_import_containers_options_default() {
        let opts = ImportContainersOptions::default();
        assert!(opts.include_volumes);
        assert!(opts.include_networks);
        assert!(opts.container_ids.is_empty());
        assert!(!opts.stop_containers);
        assert!(!opts.preserve_names);
    }

    #[test]
    fn test_docker_importer() {
        let importer = DockerImporter::new();
        assert_eq!(importer.socket_path(), std::path::Path::new("/var/run/docker.sock"));
    }
}
