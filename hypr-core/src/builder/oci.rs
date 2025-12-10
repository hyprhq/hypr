//! OCI registry client for pulling base images from Docker Hub and other registries.
//!
//! This module handles:
//! - Image manifest fetching
//! - Layer downloading
//! - Layer extraction to filesystem
//!
//! Based on the OCI Distribution Spec: https://github.com/opencontainers/distribution-spec

use crate::builder::executor::{BuildError, BuildResult};
use oci_distribution::client::{Client, ClientConfig, ClientProtocol};
use oci_distribution::manifest::ImageIndexEntry;
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use std::path::{Path, PathBuf};
use tar::Archive;
use tracing::{debug, info, instrument};

/// Helper to find a manifest entry matching a specific architecture.
fn find_linux_arch<'a>(
    manifests: &'a [ImageIndexEntry],
    arch: &str,
) -> Option<&'a ImageIndexEntry> {
    manifests.iter().find(|entry| {
        entry
            .platform
            .as_ref()
            .is_some_and(|platform| platform.os == "linux" && platform.architecture == arch)
    })
}

/// Platform resolver that always selects Linux images with the current architecture.
///
/// This is needed because we're building Linux container images (for microVMs)
/// even when running on macOS or other platforms. The default resolver would
/// try to pull darwin/arm64 on macOS, but we need linux/arm64.
///
/// # Rosetta Fallback (macOS ARM64)
///
/// On Apple Silicon Macs, if no native ARM64 image is available, we automatically
/// fall back to x86_64 (amd64) images. These will run transparently via Apple's
/// Rosetta 2 translation layer inside the Linux VM.
///
/// This enables running x86_64-only images (like older MySQL versions) on ARM64 Macs.
fn linux_platform_resolver(manifests: &[ImageIndexEntry]) -> Option<String> {
    // Detect current architecture
    let host_arch = std::env::consts::ARCH;
    let arch = match host_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    debug!("Looking for linux/{} image variant", arch);

    // 1. Try to find native architecture match (best performance)
    if let Some(entry) = find_linux_arch(manifests, arch) {
        debug!("Found native linux/{} image", arch);
        return Some(entry.digest.clone());
    }

    // 2. Rosetta fallback: On macOS ARM64, try x86_64 if no ARM64 available
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        debug!("Native ARM64 image not found, trying x86_64 (Rosetta fallback)");

        // Try "amd64" first (Docker convention)
        if let Some(entry) = find_linux_arch(manifests, "amd64") {
            info!("Native ARM64 image not available, using x86_64 via Rosetta 2 emulation");
            return Some(entry.digest.clone());
        }

        // Also try "x86_64" in case of non-standard naming
        if let Some(entry) = find_linux_arch(manifests, "x86_64") {
            info!("Native ARM64 image not available, using x86_64 via Rosetta 2 emulation");
            return Some(entry.digest.clone());
        }
    }

    // No suitable image found
    debug!("No suitable linux image found for architecture {}", arch);
    None
}

/// OCI registry client for pulling images.
pub struct OciClient {
    client: Client,
}

impl OciClient {
    /// Create a new OCI client with default configuration.
    pub fn new() -> BuildResult<Self> {
        let config = ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec!["localhost".to_string()]),
            platform_resolver: Some(Box::new(linux_platform_resolver)),
            ..Default::default()
        };

        let client = Client::new(config);

        Ok(Self { client })
    }

    /// Pull an image from a registry and extract it to the specified directory.
    ///
    /// # Arguments
    /// * `image` - Image reference (e.g., "nginx:latest", "docker.io/library/nginx:latest")
    /// * `dest_dir` - Destination directory to extract the image rootfs
    ///
    /// # Returns
    /// Path to the extracted rootfs directory
    #[instrument(skip(self), fields(image = %image))]
    pub async fn pull_image(&mut self, image: &str, dest_dir: &Path) -> BuildResult<PathBuf> {
        info!("Pulling image from registry");

        // Parse image reference
        let reference = Self::parse_reference(image)?;
        debug!("Parsed reference: {:?}", reference);

        // Pull image manifest and layers
        let auth = RegistryAuth::Anonymous;
        let image_data = self
            .client
            .pull(
                &reference,
                &auth,
                vec![
                    oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                ],
            )
            .await
            .map_err(|e| BuildError::ImagePullFailed {
                image: image.to_string(),
                reason: e.to_string(),
            })?;

        info!(layers = image_data.layers.len(), "Image manifest fetched successfully");

        // Create destination directory
        std::fs::create_dir_all(dest_dir)
            .map_err(|e| BuildError::IoError { path: dest_dir.to_path_buf(), source: e })?;

        // Extract layers in order
        for (i, layer) in image_data.layers.iter().enumerate() {
            debug!(
                layer = i + 1,
                total = image_data.layers.len(),
                size = layer.data.len(),
                "Extracting layer"
            );

            self.extract_layer(&layer.data, dest_dir)?;
        }

        info!(
            rootfs = %dest_dir.display(),
            "Image extracted successfully"
        );

        Ok(dest_dir.to_path_buf())
    }

    /// Parse an image reference string into an OCI Reference.
    ///
    /// Handles:
    /// - Short names: "nginx" → "docker.io/library/nginx:latest"
    /// - Tagged names: "nginx:1.25" → "docker.io/library/nginx:1.25"
    /// - Fully qualified: "ghcr.io/org/repo:tag"
    fn parse_reference(image: &str) -> BuildResult<Reference> {
        // If no registry specified, assume Docker Hub
        let normalized = if !image.contains('/') {
            format!("docker.io/library/{}", image)
        } else if !image.starts_with("docker.io/")
            && !image.starts_with("ghcr.io/")
            && !image.starts_with("gcr.io/")
            && !image.starts_with("quay.io/")
            && !image.starts_with("localhost/")
        {
            // Assume Docker Hub for single-component names
            if image.split('/').count() == 2 {
                format!("docker.io/{}", image)
            } else {
                image.to_string()
            }
        } else {
            image.to_string()
        };

        // Add :latest if no tag specified
        let normalized = if !normalized.contains(':') && !normalized.contains('@') {
            format!("{}:latest", normalized)
        } else {
            normalized
        };

        Reference::try_from(normalized.as_str()).map_err(|e| BuildError::InvalidImageRef {
            image: image.to_string(),
            reason: e.to_string(),
        })
    }

    /// Extract a gzip-compressed tar layer to the destination directory.
    fn extract_layer(&self, layer_data: &[u8], dest_dir: &Path) -> BuildResult<()> {
        use flate2::read::GzDecoder;
        use std::io::Cursor;

        let cursor = Cursor::new(layer_data);
        let decoder = GzDecoder::new(cursor);
        let mut archive = Archive::new(decoder);

        // Configure archive for cross-platform compatibility
        archive.set_unpack_xattrs(false);
        archive.set_preserve_mtime(false);
        archive.set_overwrite(true);

        // Unpack entries one-by-one to handle errors gracefully
        // (macOS tmpfs has issues with hardlinks, special permissions)
        let entries = archive.entries().map_err(|e| BuildError::LayerExtractionFailed {
            path: dest_dir.to_path_buf(),
            reason: format!("Failed to read tar entries: {}", e),
        })?;

        for entry_result in entries {
            let mut entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    // Skip unreadable entries (corrupted tar)
                    eprintln!("Warning: skipping unreadable tar entry: {}", e);
                    continue;
                }
            };

            // Try to unpack this entry
            if let Err(e) = entry.unpack_in(dest_dir) {
                // On macOS tmpfs, some operations fail (hardlinks, extended attrs)
                // Log warning but continue - the file might be a hardlink we can skip
                let path = entry
                    .path()
                    .ok()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());
                eprintln!("Warning: failed to unpack {} ({}), continuing...", path, e);
            }
        }

        Ok(())
    }
}

impl Default for OciClient {
    fn default() -> Self {
        Self::new().expect("Failed to create OCI client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_reference_short_name() {
        let reference = OciClient::parse_reference("nginx").unwrap();
        assert_eq!(reference.registry(), "docker.io");
        assert_eq!(reference.repository(), "library/nginx");
        assert_eq!(reference.tag(), Some("latest"));
    }

    #[test]
    fn test_parse_reference_with_tag() {
        let reference = OciClient::parse_reference("nginx:1.25").unwrap();
        assert_eq!(reference.registry(), "docker.io");
        assert_eq!(reference.repository(), "library/nginx");
        assert_eq!(reference.tag(), Some("1.25"));
    }

    #[test]
    fn test_parse_reference_fully_qualified() {
        let reference = OciClient::parse_reference("ghcr.io/org/repo:v1.0.0").unwrap();
        assert_eq!(reference.registry(), "ghcr.io");
        assert_eq!(reference.repository(), "org/repo");
        assert_eq!(reference.tag(), Some("v1.0.0"));
    }

    #[test]
    fn test_parse_reference_with_org() {
        let reference = OciClient::parse_reference("myorg/myapp:latest").unwrap();
        assert_eq!(reference.registry(), "docker.io");
        assert_eq!(reference.repository(), "myorg/myapp");
        assert_eq!(reference.tag(), Some("latest"));
    }
}
