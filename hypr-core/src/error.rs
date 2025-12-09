//! Error types for HYPR.
//!
//! All errors use `thiserror` for ergonomic error handling and proper error chains.

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias for HYPR operations.
pub type Result<T> = std::result::Result<T, HyprError>;

/// Main error type for HYPR.
#[derive(Error, Debug)]
pub enum HyprError {
    // VM lifecycle errors
    #[error("Failed to start VM {vm_id}: {reason}")]
    VmStartFailed { vm_id: String, reason: String },

    #[error("Failed to stop VM {vm_id}: {reason}")]
    VmStopFailed { vm_id: String, reason: String },

    #[error("VM not found: {vm_id}")]
    VmNotFound { vm_id: String },

    #[error("VM already exists: {vm_id}")]
    VmAlreadyExists { vm_id: String },

    #[error("VM health check timeout: {vm_id}")]
    VmHealthTimeout { vm_id: String },

    // Image errors
    #[error("Image not found: {image}")]
    ImageNotFound { image: String },

    #[error("Invalid image manifest: {reason}")]
    InvalidManifest { reason: String },

    // Build errors
    #[error("Build failed: {reason}")]
    BuildFailed { reason: String },

    #[error("Invalid Dockerfile at {path:?}: {reason}")]
    InvalidDockerfile { path: PathBuf, reason: String },

    #[error("Compression failed: {reason}")]
    CompressionFailed { reason: String },

    // Platform errors
    #[error("Unsupported architecture: {arch}")]
    UnsupportedArchitecture { arch: String },

    // Compose errors
    #[error("Invalid compose file at {path:?}: {reason}")]
    InvalidCompose { path: PathBuf, line: Option<usize>, message: String, reason: String },

    #[error("Compose parse error: {reason}")]
    ComposeParseError { reason: String },

    #[error("Unsupported compose version: {version}")]
    UnsupportedComposeVersion { version: String },

    #[error("File read error: {path}: {source}")]
    FileReadError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Circular dependency detected in service: {service}")]
    CircularDependency { service: String },

    #[error(
        "Missing dependency: service '{service}' depends on '{dependency}' which does not exist"
    )]
    MissingDependency { service: String, dependency: String },

    // Network errors
    #[error("Port {port} already in use")]
    PortConflict { port: u16 },

    #[error("Network bridge setup failed: {reason}")]
    NetworkSetupFailed { reason: String },

    #[error("Failed to create TAP device: {reason}")]
    TapDeviceError { reason: String },

    #[error("IP address pool exhausted: no more IP addresses available")]
    IpPoolExhausted,

    // eBPF errors
    #[error("eBPF not available: {reason}")]
    EbpfNotAvailable { reason: String },

    #[error("Failed to load eBPF program: {0}")]
    EbpfLoadError(String),

    #[error("Failed to attach eBPF program: {0}")]
    EbpfAttachError(String),

    #[error("eBPF map operation failed: {0}")]
    EbpfMapError(String),

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    // GPU errors
    #[error("GPU not available: {reason}")]
    GpuUnavailable { reason: String },

    #[error("GPU {pci_address} not bound to vfio-pci driver. {hint}")]
    GpuNotBound { pci_address: String, hint: String },

    // File system errors
    #[error("File not found: {path:?}. {hint}")]
    FileNotFound { path: PathBuf, hint: String },

    #[error("I/O error at {path:?}: {source}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    // Platform errors
    #[error("Feature {feature} not supported on {platform}")]
    PlatformUnsupported { feature: String, platform: String },

    #[error("Hypervisor not found: {hypervisor}")]
    HypervisorNotFound { hypervisor: String },

    // Database errors
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Database migration failed: {reason}")]
    MigrationFailed { reason: String },

    // API errors
    #[error("API error: {message}")]
    ApiError { message: String },

    // Configuration errors
    #[error("Invalid configuration: {reason}")]
    InvalidConfig { reason: String },

    // Resource errors
    #[error("Insufficient resources: {reason}")]
    InsufficientResources { reason: String },

    // Feature availability errors
    #[error("Feature not implemented: {feature}")]
    NotImplemented { feature: String },

    #[error("Unsupported operation: {operation}. {reason}")]
    UnsupportedOperation { operation: String, reason: String },

    // Generic errors
    #[error("Internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl HyprError {
    /// Create an Internal error from any error type.
    pub fn internal(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Internal(err.to_string())
    }
}
