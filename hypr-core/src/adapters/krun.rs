//! libkrun-efi adapter for macOS (stub for future implementation).
//!
//! This adapter will provide GPU-accelerated VMs on macOS via Metal.
//! Current status: Phase 1 stub - full implementation in Phase 4.

use crate::adapters::{AdapterCapabilities, VmmAdapter};
use crate::error::{HyprError, Result};
use crate::types::network::NetworkConfig;
use crate::types::vm::{DiskConfig, GpuConfig, VmConfig, VmHandle};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, instrument, warn};

/// libkrun-efi adapter (stub).
///
/// **Status:** Phase 1 stub only. Full implementation planned for Phase 4.
///
/// This adapter will provide:
/// - Metal GPU acceleration on macOS
/// - 60-80% bare-metal GPU performance
/// - Native Metal API integration
/// - Sub-second boot times
pub struct KrunAdapter {
    /// Path to libkrun-efi.dylib
    _library_path: PathBuf,
}

impl KrunAdapter {
    /// Create a new libkrun-efi adapter.
    ///
    /// **Note:** This is a stub implementation. Actual libkrun-efi integration
    /// will be implemented in Phase 4.
    pub fn new() -> Result<Self> {
        warn!("KrunAdapter is a Phase 1 stub - full implementation in Phase 4");

        // Check if library exists (but don't load it yet)
        let library_path = Self::find_library()?;

        Ok(Self { _library_path: library_path })
    }

    /// Find libkrun-efi library.
    fn find_library() -> Result<PathBuf> {
        let candidates = vec![
            PathBuf::from("/usr/local/lib/libkrun-efi.dylib"),
            PathBuf::from("/opt/homebrew/lib/libkrun-efi.dylib"),
        ];

        for path in candidates {
            if path.exists() {
                return Ok(path);
            }
        }

        // Return error with helpful message
        Err(HyprError::HypervisorNotFound {
            hypervisor: "libkrun-efi (install: brew install hypr-libkrun)".to_string(),
        })
    }
}

impl Default for KrunAdapter {
    fn default() -> Self {
        Self::new().expect("Failed to create libkrun-efi adapter")
    }
}

#[async_trait]
impl VmmAdapter for KrunAdapter {
    #[instrument(skip(self))]
    async fn create(&self, _config: &VmConfig) -> Result<VmHandle> {
        info!("Creating VM with libkrun-efi (stub)");

        // Phase 1: Return error with helpful message
        Err(HyprError::PlatformUnsupported {
            feature: "libkrun-efi adapter".to_string(),
            platform: "Phase 1 (full implementation in Phase 4)".to_string(),
        })
    }

    async fn start(&self, _handle: &VmHandle) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "libkrun-efi adapter".to_string(),
            platform: "Phase 1 stub".to_string(),
        })
    }

    async fn stop(&self, _handle: &VmHandle, _timeout: Duration) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "libkrun-efi adapter".to_string(),
            platform: "Phase 1 stub".to_string(),
        })
    }

    async fn kill(&self, _handle: &VmHandle) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "libkrun-efi adapter".to_string(),
            platform: "Phase 1 stub".to_string(),
        })
    }

    async fn delete(&self, _handle: &VmHandle) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "libkrun-efi adapter".to_string(),
            platform: "Phase 1 stub".to_string(),
        })
    }

    async fn attach_disk(&self, _handle: &VmHandle, _disk: &DiskConfig) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "libkrun-efi adapter".to_string(),
            platform: "Phase 1 stub".to_string(),
        })
    }

    async fn attach_network(&self, _handle: &VmHandle, _net: &NetworkConfig) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "libkrun-efi adapter".to_string(),
            platform: "Phase 1 stub".to_string(),
        })
    }

    async fn attach_gpu(&self, _handle: &VmHandle, _gpu: &GpuConfig) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "libkrun-efi GPU (Metal)".to_string(),
            platform: "Phase 1 stub - Metal support in Phase 4".to_string(),
        })
    }

    fn vsock_path(&self, handle: &VmHandle) -> PathBuf {
        PathBuf::from(format!("/tmp/hypr-krun-{}.vsock", handle.id))
    }

    fn capabilities(&self) -> AdapterCapabilities {
        // Future capabilities (Phase 4)
        AdapterCapabilities {
            gpu_passthrough: true, // Metal in Phase 4
            virtio_fs: true,
            hotplug_devices: false,
            metadata: HashMap::from([
                ("adapter".to_string(), "libkrun-efi".to_string()),
                ("status".to_string(), "stub".to_string()),
                ("gpu_backend".to_string(), "metal".to_string()),
                ("phase".to_string(), "4".to_string()),
            ]),
        }
    }

    fn name(&self) -> &str {
        "libkrun-efi"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_krun_adapter_stub() {
        // Should compile and construct
        let result = KrunAdapter::new();

        // May succeed or fail depending on whether libkrun-efi is installed
        // This is expected for a stub
        match result {
            Ok(_adapter) => {
                // Library found (user has it installed early)
                // This is fine for testing
            }
            Err(HyprError::HypervisorNotFound { .. }) => {
                // Library not found (expected in Phase 1)
                // This is the normal case
            }
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }
}
