//! Adapter factory for platform-specific VMM selection.
//!
//! The factory automatically detects the platform and creates the appropriate
//! adapter, with support for configuration overrides and capability validation.

use crate::adapters::{AdapterCapabilities, VmmAdapter};
use crate::error::{HyprError, Result};
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Configuration for adapter selection.
#[derive(Debug, Clone, Default)]
pub struct AdapterConfig {
    /// Override automatic platform detection.
    /// Values: "cloudhypervisor", "hvf", "krun"
    pub adapter_override: Option<String>,

    /// Required capabilities for the adapter.
    pub required_capabilities: Option<AdapterCapabilities>,
}

/// Factory for creating VMM adapters.
///
/// The factory handles:
/// - Platform auto-detection (Linux → CloudHypervisor, macOS → HVF/Krun)
/// - Configuration overrides
/// - Capability validation
/// - Helpful error messages when adapters are unavailable
pub struct AdapterFactory;

impl AdapterFactory {
    /// Create a new adapter based on platform and configuration.
    ///
    /// # Platform Selection
    ///
    /// - **Linux**: CloudHypervisorAdapter (primary)
    /// - **macOS**: HvfAdapter (primary), KrunAdapter (with feature flag)
    ///
    /// # Configuration Override
    ///
    /// Use `config.adapter_override` to specify a particular adapter:
    /// - `"cloudhypervisor"` → CloudHypervisorAdapter
    /// - `"hvf"` → HvfAdapter
    /// - `"krun"` → KrunAdapter (requires feature flag)
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
    /// - Hypervisor binary not found
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
            // Try krun first if feature is enabled, otherwise HVF
            #[cfg(feature = "krun")]
            {
                info!("Platform: macOS, attempting KrunAdapter (feature enabled)");
                match Self::create_krun(&config) {
                    Ok(adapter) => return Ok(adapter),
                    Err(e) => {
                        warn!(error = %e, "KrunAdapter unavailable, falling back to HVF");
                    }
                }
            }

            info!("Platform: macOS, selecting HVF adapter");
            Self::create_hvf(&config)
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
            "hvf" => Self::create_hvf(config),
            "krun" => Self::create_krun(config),
            _ => Err(HyprError::InvalidConfig {
                reason: format!(
                    "Unknown adapter '{}'. Valid options: cloudhypervisor, hvf, krun",
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

    /// Create HVF adapter (macOS only).
    #[cfg(target_os = "macos")]
    #[instrument(skip(config))]
    fn create_hvf(config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        use crate::adapters::HvfAdapter;

        let adapter = HvfAdapter::new()?;
        Self::validate_capabilities(&adapter, config)?;

        info!(
            adapter = adapter.name(),
            capabilities = ?adapter.capabilities(),
            "Created HVF adapter"
        );

        Ok(Arc::new(adapter))
    }

    #[cfg(not(target_os = "macos"))]
    #[instrument(skip(_config))]
    fn create_hvf(_config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        Err(HyprError::PlatformUnsupported {
            feature: "HVF".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }

    /// Create Krun adapter (macOS with feature flag).
    #[cfg(all(target_os = "macos", feature = "krun"))]
    #[instrument(skip(config))]
    fn create_krun(config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        use crate::adapters::KrunAdapter;

        let adapter = KrunAdapter::new()?;
        Self::validate_capabilities(&adapter, config)?;

        info!(
            adapter = adapter.name(),
            capabilities = ?adapter.capabilities(),
            "Created Krun adapter"
        );

        Ok(Arc::new(adapter))
    }

    #[cfg(not(all(target_os = "macos", feature = "krun")))]
    #[instrument(skip(_config))]
    fn create_krun(_config: &AdapterConfig) -> Result<Arc<dyn VmmAdapter>> {
        #[cfg(target_os = "macos")]
        {
            Err(HyprError::InvalidConfig {
                reason: "Krun adapter requires --features krun".to_string(),
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(HyprError::PlatformUnsupported {
                feature: "Krun".to_string(),
                platform: std::env::consts::OS.to_string(),
            })
        }
    }

    /// Validate that an adapter meets required capabilities.
    #[instrument(skip(adapter, config))]
    fn validate_capabilities(
        adapter: &impl VmmAdapter,
        config: &AdapterConfig,
    ) -> Result<()> {
        if let Some(ref required) = config.required_capabilities {
            let actual = adapter.capabilities();

            if required.gpu_passthrough && !actual.gpu_passthrough {
                return Err(HyprError::InsufficientResources {
                    reason: format!(
                        "Adapter {} does not support GPU passthrough",
                        adapter.name()
                    ),
                });
            }

            if required.virtio_fs && !actual.virtio_fs {
                return Err(HyprError::InsufficientResources {
                    reason: format!(
                        "Adapter {} does not support virtio-fs",
                        adapter.name()
                    ),
                });
            }

            if required.hotplug_devices && !actual.hotplug_devices {
                return Err(HyprError::InsufficientResources {
                    reason: format!(
                        "Adapter {} does not support device hotplug",
                        adapter.name()
                    ),
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
        // This should succeed on Linux (CloudHypervisor) or macOS (HVF)
        // but may fail if the hypervisor binary is not installed
        match AdapterFactory::create(None) {
            Ok(adapter) => {
                #[cfg(target_os = "linux")]
                assert_eq!(adapter.name(), "cloud-hypervisor");

                #[cfg(target_os = "macos")]
                {
                    // Could be HVF or Krun depending on features
                    let name = adapter.name();
                    assert!(
                        name == "hvf" || name == "krun",
                        "Expected hvf or krun, got {}",
                        name
                    );
                }
            }
            Err(HyprError::HypervisorNotFound { .. }) => {
                // This is acceptable in test environments without hypervisors
                println!("Hypervisor binary not found (acceptable in test environment)");
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
            // Try to use HVF on Linux
            let config = AdapterConfig {
                adapter_override: Some("hvf".to_string()),
                required_capabilities: None,
            };

            let result = AdapterFactory::create(Some(config));
            assert!(result.is_err());
            match result {
                Err(HyprError::PlatformUnsupported { feature, .. }) => {
                    assert_eq!(feature, "HVF");
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
    #[cfg(target_os = "macos")]
    fn test_krun_requires_feature_flag() {
        let config = AdapterConfig {
            adapter_override: Some("krun".to_string()),
            required_capabilities: None,
        };

        let result = AdapterFactory::create(Some(config));

        #[cfg(not(feature = "krun"))]
        {
            assert!(result.is_err());
            match result {
                Err(HyprError::InvalidConfig { reason }) => {
                    assert!(reason.contains("feature"));
                }
                _ => panic!("Expected InvalidConfig error about feature flag"),
            }
        }

        #[cfg(feature = "krun")]
        {
            // With feature enabled, it should either succeed or fail with HypervisorNotFound
            match result {
                Ok(_) => {}
                Err(HyprError::HypervisorNotFound { .. }) => {}
                Err(e) => panic!("Unexpected error with krun feature enabled: {}", e),
            }
        }
    }

    #[test]
    fn test_capability_validation() {
        // Create a config that requires GPU passthrough
        let mut required_caps = AdapterCapabilities::default();
        required_caps.gpu_passthrough = true;

        let config = AdapterConfig {
            adapter_override: None,
            required_capabilities: Some(required_caps),
        };

        let result = AdapterFactory::create(Some(config));

        // HVF doesn't support GPU passthrough, so this should fail on macOS
        // CloudHypervisor supports it on Linux, so should succeed (if binary exists)
        #[cfg(target_os = "macos")]
        {
            match result {
                Err(HyprError::InsufficientResources { reason }) => {
                    assert!(reason.contains("GPU passthrough"));
                }
                Err(HyprError::HypervisorNotFound { .. }) => {
                    // Acceptable if hypervisor not installed
                }
                Ok(_) => {
                    // Acceptable if krun feature is enabled and libkrun supports GPU
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
        }

        #[cfg(target_os = "linux")]
        {
            match result {
                Ok(_) => {
                    // CloudHypervisor supports GPU passthrough
                }
                Err(HyprError::HypervisorNotFound { .. }) => {
                    // Acceptable if hypervisor not installed
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
        }
    }
}
