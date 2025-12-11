//! Adapter factory for platform-specific VMM selection.
//!
//! The factory automatically detects the platform and creates the appropriate
//! adapter, with support for configuration overrides and capability validation.

use crate::adapters::{AdapterCapabilities, VmmAdapter};
use crate::error::{HyprError, Result};
use std::sync::Arc;
use tracing::{info, instrument};

/// Configuration for adapter selection.
#[derive(Debug, Clone, Default)]
pub struct AdapterConfig {
    /// Override automatic platform detection.
    /// Values: "cloudhypervisor" (Linux), "virtualization" (macOS)
    pub adapter_override: Option<String>,

    /// Required capabilities for the adapter.
    pub required_capabilities: Option<AdapterCapabilities>,
}

/// Factory for creating VMM adapters.
///
/// The factory handles:
/// - Platform auto-detection (Linux → CloudHypervisor, macOS → Virtualization.framework)
/// - Configuration overrides
/// - Capability validation
/// - Helpful error messages when adapters are unavailable
pub struct AdapterFactory;

impl AdapterFactory {
    /// Create a new adapter based on platform and configuration.
    ///
    /// # Platform Selection
    ///
    /// - **Linux**: CloudHypervisorAdapter
    /// - **macOS**: VirtualizationAdapter (native Virtualization.framework, with GPU support on Apple Silicon)
    ///
    /// # Configuration Override
    ///
    /// Use `config.adapter_override` to specify a particular adapter:
    /// - `"cloudhypervisor"` → CloudHypervisorAdapter (Linux only)
    /// - `"virtualization"` → VirtualizationAdapter (macOS only)
    ///
    /// # Capability Checking
    ///
    /// If `config.required_capabilities` is set, the factory validates that
    /// the selected adapter can satisfy those requirements.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - No adapter available for the current platform
    /// - Requested adapter is not available (e.g., wrong platform)
    /// - Adapter doesn't satisfy required capabilities
    /// - Hypervisor library not found
    #[instrument(skip(config))]
    pub fn create(config: Option<AdapterConfig>) -> Result<Arc<dyn VmmAdapter>> {
        let config = config.unwrap_or_default();

        // Check for explicit override first
        if let Some(ref override_name) = config.adapter_override {
            info!(adapter = %override_name, "Using adapter override from configuration");
            return Self::create_by_name(override_name, &config);
        }

        // Platform auto-detection
        #[cfg(target_os = "linux")]
        {
            info!("Platform: Linux, selecting CloudHypervisor adapter");
            Self::create_cloudhypervisor(&config)
        }

        #[cfg(target_os = "macos")]
        {
            info!("Platform: macOS, selecting Virtualization.framework adapter");
            Self::create_virtualization(&config)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(HyprError::PlatformUnsupported {
                feature: "VMM adapters".to_string(),
                platform: std::env::consts::OS.to_string(),
            })
        }
    }

    /// Create an adapter by name (for configuration override).
    #[instrument]
    fn create_by_name(name: &str, config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        match name {
            "cloudhypervisor" => Self::create_cloudhypervisor(config),
            "virtualization" | "libkrun" | "krun" => Self::create_virtualization(config),
            _ => Err(HyprError::InvalidConfig {
                reason: format!(
                    "Unknown adapter '{}'. Valid options: cloudhypervisor, virtualization",
                    name
                ),
            }),
        }
    }

    /// Create CloudHypervisor adapter (Linux only).
    #[cfg(target_os = "linux")]
    #[instrument(skip(config))]
    fn create_cloudhypervisor(config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        use crate::adapters::CloudHypervisorAdapter;

        let adapter = CloudHypervisorAdapter::new()?;
        Self::validate_capabilities(&adapter, config)?;

        info!(
            adapter = adapter.name(),
            capabilities = ?adapter.capabilities(),
            "Created CloudHypervisor adapter"
        );

        Ok(Arc::new(adapter))
    }

    #[cfg(not(target_os = "linux"))]
    #[instrument(skip(_config))]
    fn create_cloudhypervisor(_config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        Err(HyprError::PlatformUnsupported {
            feature: "CloudHypervisor".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }

    /// Create Virtualization.framework adapter (macOS only).
    #[cfg(target_os = "macos")]
    #[instrument(skip(config))]
    fn create_virtualization(config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        use crate::adapters::VirtualizationAdapter;

        let adapter = VirtualizationAdapter::new()?;
        Self::validate_capabilities(&adapter, config)?;

        info!(
            adapter = adapter.name(),
            capabilities = ?adapter.capabilities(),
            "Created Virtualization.framework adapter"
        );

        Ok(Arc::new(adapter))
    }

    #[cfg(not(target_os = "macos"))]
    #[instrument(skip(_config))]
    fn create_virtualization(_config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        Err(HyprError::PlatformUnsupported {
            feature: "Virtualization.framework".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }

    /// Validate that an adapter meets required capabilities.
    #[instrument(skip(adapter, config))]
    fn validate_capabilities(adapter: &impl VmmAdapter, config: &AdapterConfig) -> Result<()> {
        if let Some(ref required) = config.required_capabilities {
            let actual = adapter.capabilities();

            if required.gpu_passthrough && !actual.gpu_passthrough {
                return Err(HyprError::InsufficientResources {
                    reason: format!("Adapter {} does not support GPU passthrough", adapter.name()),
                });
            }

            if required.virtio_fs && !actual.virtio_fs {
                return Err(HyprError::InsufficientResources {
                    reason: format!("Adapter {} does not support virtio-fs", adapter.name()),
                });
            }

            if required.hotplug_devices && !actual.hotplug_devices {
                return Err(HyprError::InsufficientResources {
                    reason: format!("Adapter {} does not support device hotplug", adapter.name()),
                });
            }

            info!(
                required = ?required,
                actual = ?actual,
                "Adapter capabilities validated"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_creates_platform_adapter() {
        // This should succeed on Linux (CloudHypervisor) or macOS (Virtualization.framework)
        // but may fail if the hypervisor binary/library is not installed
        match AdapterFactory::create(None) {
            Ok(adapter) => {
                #[cfg(target_os = "linux")]
                assert_eq!(adapter.name(), "cloud-hypervisor");

                #[cfg(target_os = "macos")]
                assert_eq!(adapter.name(), "virtualization");
            }
            Err(HyprError::HypervisorNotFound { .. }) => {
                // This is acceptable in test environments without hypervisors
                println!("Hypervisor not found (acceptable in test environment)");
            }
            Err(HyprError::IoError { .. }) => {
                // This is acceptable in CI where /var/lib/hypr is not writable
                println!("I/O error (acceptable in test environment without root)");
            }
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_config_override_invalid_adapter() {
        let config = AdapterConfig {
            adapter_override: Some("invalid-adapter".to_string()),
            required_capabilities: None,
        };

        let result = AdapterFactory::create(Some(config));
        assert!(result.is_err());
        match result {
            Err(HyprError::InvalidConfig { reason }) => {
                assert!(reason.contains("Unknown adapter"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_config_override_wrong_platform() {
        #[cfg(target_os = "linux")]
        {
            // Try to use Virtualization.framework on Linux
            let config = AdapterConfig {
                adapter_override: Some("virtualization".to_string()),
                required_capabilities: None,
            };

            let result = AdapterFactory::create(Some(config));
            assert!(result.is_err());
            match result {
                Err(HyprError::PlatformUnsupported { feature, .. }) => {
                    assert_eq!(feature, "Virtualization.framework");
                }
                _ => panic!("Expected PlatformUnsupported error"),
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Try to use CloudHypervisor on macOS
            let config = AdapterConfig {
                adapter_override: Some("cloudhypervisor".to_string()),
                required_capabilities: None,
            };

            let result = AdapterFactory::create(Some(config));
            assert!(result.is_err());
            match result {
                Err(HyprError::PlatformUnsupported { feature, .. }) => {
                    assert_eq!(feature, "CloudHypervisor");
                }
                _ => panic!("Expected PlatformUnsupported error"),
            }
        }
    }

    #[test]
    fn test_capability_validation() {
        // Create a config that requires GPU passthrough
        let required_caps = AdapterCapabilities { gpu_passthrough: true, ..Default::default() };

        let config =
            AdapterConfig { adapter_override: None, required_capabilities: Some(required_caps) };

        let result = AdapterFactory::create(Some(config));

        // Virtualization.framework supports GPU on Apple Silicon, CloudHypervisor supports VFIO on Linux
        #[cfg(target_os = "macos")]
        {
            match result {
                Ok(adapter) => {
                    // Virtualization.framework on Apple Silicon supports GPU
                    assert!(adapter.capabilities().gpu_passthrough);
                }
                Err(HyprError::InsufficientResources { reason }) => {
                    // Intel Macs don't support GPU passthrough
                    assert!(reason.contains("GPU passthrough"));
                }
                Err(HyprError::HypervisorNotFound { .. }) => {
                    // Acceptable if Virtualization.framework not available
                }
                Err(HyprError::IoError { .. }) => {
                    // Acceptable in CI without root
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
        }

        #[cfg(target_os = "linux")]
        {
            match result {
                Ok(_) => {
                    // CloudHypervisor supports GPU passthrough via VFIO
                }
                Err(HyprError::HypervisorNotFound { .. }) => {
                    // Acceptable if hypervisor not installed
                }
                Err(HyprError::IoError { .. }) => {
                    // Acceptable in CI without root
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
        }
    }
}
