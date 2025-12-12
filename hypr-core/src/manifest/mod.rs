//! Manifest handling for HYPR images and runtime VMs.

pub mod runtime_manifest;

pub use runtime_manifest::{
    HealthCheckConfig, HealthCheckType, NetworkConfig, RestartPolicy, RuntimeManifest,
    VolumeConfig, WorkloadConfig,
};

use crate::error::{HyprError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

/// Encode a runtime manifest for kernel cmdline.
///
/// Process:
/// 1. Serialize to JSON
/// 2. Compress with gzip
/// 3. Encode as base64 (URL-safe, no padding)
///
/// The result can be passed as `manifest=<encoded>` in kernel cmdline.
pub fn encode_manifest(manifest: &RuntimeManifest) -> Result<String> {
    // Step 1: Serialize to JSON
    let json = serde_json::to_vec(manifest).map_err(|e| HyprError::InvalidConfig {
        reason: format!("Failed to serialize manifest: {}", e),
    })?;

    // Step 2: Compress with gzip
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&json).map_err(|e| HyprError::InvalidConfig {
        reason: format!("Failed to compress manifest: {}", e),
    })?;
    let compressed = encoder.finish().map_err(|e| HyprError::InvalidConfig {
        reason: format!("Failed to finish compression: {}", e),
    })?;

    // Step 3: Encode as base64
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);

    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_manifest() {
        let manifest = RuntimeManifest::new(vec!["/bin/sh".to_string(), "-c".to_string()])
            .with_env(vec!["PATH=/usr/bin".to_string()])
            .with_restart(RestartPolicy::Always);

        let encoded = encode_manifest(&manifest).unwrap();

        // Should be base64 string
        assert!(!encoded.is_empty());
        assert!(!encoded.contains(' ')); // No spaces
        assert!(!encoded.contains('=')); // URL-safe no padding

        println!("Encoded manifest: {}", encoded);
        println!("Length: {} bytes", encoded.len());
    }

    #[test]
    fn test_encode_with_network() {
        let network = NetworkConfig {
            ip: "192.168.64.2".to_string(),
            netmask: "255.255.255.0".to_string(),
            gateway: "192.168.64.1".to_string(),
            dns: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        };

        let manifest = RuntimeManifest::new(vec!["/usr/bin/bun".to_string(), "run".to_string()])
            .with_network(network)
            .with_workdir("/app".to_string())
            .with_restart(RestartPolicy::OnFailure);

        let encoded = encode_manifest(&manifest).unwrap();
        println!("Encoded manifest with network: {}", encoded);
        println!("Length: {} bytes", encoded.len());

        // Should still be reasonably short (< 1KB after compression + encoding)
        assert!(encoded.len() < 1024);
    }
}
