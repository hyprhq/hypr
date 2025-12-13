//! OCI registry image pulling for HYPR.
//!
//! This module handles pulling container images from registries like Docker Hub,
//! extracting them, and converting them to HYPR's squashfs format.

use crate::error::{HyprError, Result};
use crate::paths::images_dir;
use crate::types::image::{Image, ImageManifest, RuntimeConfig};
use oci_distribution::client::{Client, ClientConfig, ClientProtocol};
use oci_distribution::manifest::ImageIndexEntry;
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;
use tracing::{debug, info, instrument, warn};

/// OCI image configuration (from config blob).
#[derive(Debug, Clone, serde::Deserialize)]
struct OciConfig {
    #[serde(default)]
    config: OciContainerConfig,
}

/// Container configuration from OCI image.
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct OciContainerConfig {
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,

    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,

    #[serde(rename = "Env")]
    env: Option<Vec<String>>,

    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,

    #[serde(rename = "User")]
    user: Option<String>,

    #[serde(rename = "ExposedPorts")]
    exposed_ports: Option<HashMap<String, serde_json::Value>>,

    #[serde(rename = "Labels")]
    #[allow(dead_code)]
    labels: Option<HashMap<String, String>>,
}

/// Image puller for OCI registries.
pub struct ImagePuller {
    client: Client,
}

impl ImagePuller {
    /// Create a new image puller.
    pub fn new() -> Result<Self> {
        let config = ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec!["localhost".to_string()]),
            platform_resolver: Some(Box::new(linux_platform_resolver)),
            ..Default::default()
        };

        let client = Client::new(config);
        Ok(Self { client })
    }

    /// Pull an image from a registry.
    ///
    /// This method:
    /// 1. Pulls the image manifest and layers from the registry
    /// 2. Extracts layers to a temporary directory
    /// 3. Converts the rootfs to squashfs format
    /// 4. Extracts metadata from OCI config
    /// 5. Returns an Image ready to be stored in the database
    #[instrument(skip(self), fields(image = %image_ref))]
    pub async fn pull(&mut self, image_ref: &str) -> Result<Image> {
        info!("Pulling image from registry: {}", image_ref);

        // Parse image reference
        let (name, tag) = parse_image_ref(image_ref);
        let reference = parse_oci_reference(image_ref)?;

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
            .map_err(|e| HyprError::ImagePullFailed {
                image: image_ref.to_string(),
                reason: e.to_string(),
            })?;

        info!(layers = image_data.layers.len(), "Image manifest fetched successfully");

        // Parse OCI config for metadata
        let oci_config: OciConfig =
            serde_json::from_slice(&image_data.config.data).map_err(|e| {
                HyprError::ImagePullFailed {
                    image: image_ref.to_string(),
                    reason: format!("Failed to parse image config: {}", e),
                }
            })?;

        debug!("Parsed OCI config: {:?}", oci_config);

        // Create temp directory for extraction
        let temp_dir = tempfile::tempdir()
            .map_err(|e| HyprError::IoError { path: PathBuf::from("/tmp"), source: e })?;

        let rootfs_dir = temp_dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs_dir)
            .map_err(|e| HyprError::IoError { path: rootfs_dir.clone(), source: e })?;

        // Extract layers
        for (i, layer) in image_data.layers.iter().enumerate() {
            debug!(
                layer = i + 1,
                total = image_data.layers.len(),
                size = layer.data.len(),
                "Extracting layer"
            );
            extract_layer(&layer.data, &rootfs_dir)?;
        }

        info!("All layers extracted successfully");

        // Create permanent image directory
        let image_dir = images_dir().join(format!("{}_{}", name.replace('/', "_"), tag));
        std::fs::create_dir_all(&image_dir)
            .map_err(|e| HyprError::IoError { path: image_dir.clone(), source: e })?;

        // Create squashfs
        let squashfs_path = image_dir.join("rootfs.squashfs");
        create_squashfs(&rootfs_dir, &squashfs_path)?;

        // Calculate image ID from squashfs hash
        let squashfs_data = std::fs::read(&squashfs_path)
            .map_err(|e| HyprError::IoError { path: squashfs_path.clone(), source: e })?;
        let mut hasher = Sha256::new();
        hasher.update(&squashfs_data);
        let image_id = format!("sha256:{:x}", hasher.finalize());

        // Get file size
        let size_bytes = std::fs::metadata(&squashfs_path).map(|m| m.len()).unwrap_or(0);

        // Build ImageManifest from OCI config
        let manifest = build_manifest(&name, &tag, &oci_config.config);

        let image = Image {
            id: image_id,
            name: name.to_string(),
            tag: tag.to_string(),
            manifest,
            rootfs_path: squashfs_path,
            size_bytes,
            created_at: SystemTime::now(),
        };

        info!(
            id = %image.id,
            name = %image.name,
            tag = %image.tag,
            size_mb = image.size_bytes / 1024 / 1024,
            "Image pulled successfully"
        );

        Ok(image)
    }

    /// Check if an image exists in a registry without pulling it.
    #[instrument(skip(self), fields(image = %image_ref))]
    pub async fn exists(&mut self, image_ref: &str) -> bool {
        let reference = match parse_oci_reference(image_ref) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let auth = RegistryAuth::Anonymous;
        self.client.fetch_manifest_digest(&reference, &auth).await.is_ok()
    }
}

impl Default for ImagePuller {
    fn default() -> Self {
        Self::new().expect("Failed to create ImagePuller")
    }
}

/// Parse an image reference into name and tag.
pub fn parse_image_ref(image_ref: &str) -> (String, String) {
    // Handle digest references (image@sha256:...)
    if image_ref.contains('@') {
        let parts: Vec<&str> = image_ref.splitn(2, '@').collect();
        return (parts[0].to_string(), parts.get(1).unwrap_or(&"latest").to_string());
    }

    // Handle tag references (image:tag)
    if let Some((name, tag)) = image_ref.rsplit_once(':') {
        // Make sure it's a tag, not a port number (registry:port/image)
        if !name.contains('/') || !tag.chars().all(|c| c.is_ascii_digit()) {
            return (name.to_string(), tag.to_string());
        }
    }

    (image_ref.to_string(), "latest".to_string())
}

/// Parse an image reference string into an OCI Reference.
fn parse_oci_reference(image: &str) -> Result<Reference> {
    // If no registry specified, assume Docker Hub
    let normalized = if !image.contains('/') {
        format!("docker.io/library/{}", image)
    } else if !image.starts_with("docker.io/")
        && !image.starts_with("ghcr.io/")
        && !image.starts_with("gcr.io/")
        && !image.starts_with("quay.io/")
        && !image.starts_with("localhost/")
    {
        // Assume Docker Hub for user/repo format
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

    Reference::try_from(normalized.as_str()).map_err(|e| HyprError::ImagePullFailed {
        image: image.to_string(),
        reason: format!("Invalid image reference: {}", e),
    })
}

/// Extract a gzip-compressed tar layer to the destination directory.
fn extract_layer(layer_data: &[u8], dest_dir: &Path) -> Result<()> {
    use flate2::read::GzDecoder;
    use std::io::Cursor;
    use tar::Archive;

    let cursor = Cursor::new(layer_data);
    let decoder = GzDecoder::new(cursor);
    let mut archive = Archive::new(decoder);

    // Configure archive for cross-platform compatibility
    archive.set_unpack_xattrs(false);
    archive.set_preserve_mtime(false);
    archive.set_overwrite(true);

    let entries = archive.entries().map_err(|e| HyprError::ImagePullFailed {
        image: "layer".to_string(),
        reason: format!("Failed to read tar entries: {}", e),
    })?;

    for entry_result in entries {
        let mut entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                warn!("Skipping unreadable tar entry: {}", e);
                continue;
            }
        };

        if let Err(e) = entry.unpack_in(dest_dir) {
            let path = entry
                .path()
                .ok()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            warn!("Failed to unpack {} ({}), continuing...", path, e);
        }
    }

    Ok(())
}

/// Create a squashfs image from a directory.
fn create_squashfs(source_dir: &Path, dest_path: &Path) -> Result<()> {
    info!(
        source = %source_dir.display(),
        dest = %dest_path.display(),
        "Creating squashfs image"
    );

    let output = Command::new("mksquashfs")
        .arg(source_dir)
        .arg(dest_path)
        .arg("-comp")
        .arg("gzip")
        .arg("-noappend")
        .arg("-quiet")
        .output()
        .map_err(|e| HyprError::ImagePullFailed {
            image: "squashfs".to_string(),
            reason: format!(
                "Failed to run mksquashfs: {}.\n\
                 Make sure squashfs-tools is installed:\n\
                 - Ubuntu/Debian: sudo apt install squashfs-tools\n\
                 - Fedora: sudo dnf install squashfs-tools\n\
                 - macOS: brew install squashfs",
                e
            ),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(HyprError::ImagePullFailed {
            image: "squashfs".to_string(),
            reason: format!("mksquashfs failed: {}", stderr),
        });
    }

    // Align to 4KB boundary for krun compatibility
    let metadata = std::fs::metadata(dest_path)
        .map_err(|e| HyprError::IoError { path: dest_path.to_path_buf(), source: e })?;

    let size = metadata.len();
    let aligned_size = (size + 4095) & !4095;

    if aligned_size > size {
        use std::fs::OpenOptions;
        use std::io::Write;
        let padding = vec![0u8; (aligned_size - size) as usize];
        let mut file = OpenOptions::new()
            .append(true)
            .open(dest_path)
            .map_err(|e| HyprError::IoError { path: dest_path.to_path_buf(), source: e })?;
        file.write_all(&padding)
            .map_err(|e| HyprError::IoError { path: dest_path.to_path_buf(), source: e })?;
    }

    let final_size = std::fs::metadata(dest_path).map(|m| m.len()).unwrap_or(0);
    info!(
        path = %dest_path.display(),
        size_mb = final_size / 1024 / 1024,
        "Squashfs image created"
    );

    Ok(())
}

/// Build an ImageManifest from OCI container config.
fn build_manifest(name: &str, tag: &str, config: &OciContainerConfig) -> ImageManifest {
    // Parse environment variables
    let env: HashMap<String, String> = config
        .env
        .as_ref()
        .map(|vars| {
            vars.iter()
                .filter_map(|var| {
                    let parts: Vec<&str> = var.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse exposed ports (format: "80/tcp" or "8080")
    let exposed_ports: Vec<u16> = config
        .exposed_ports
        .as_ref()
        .map(|ports| {
            ports
                .keys()
                .filter_map(|port_spec| {
                    // Parse "80/tcp" or "80"
                    let port_str = port_spec.split('/').next().unwrap_or(port_spec);
                    port_str.parse::<u16>().ok()
                })
                .collect()
        })
        .unwrap_or_default();

    // Detect architecture
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => other,
    }
    .to_string();

    ImageManifest {
        version: "1.0".to_string(),
        name: name.to_string(),
        tag: tag.to_string(),
        architecture,
        os: "linux".to_string(),
        entrypoint: config.entrypoint.clone().unwrap_or_default(),
        cmd: config.cmd.clone().unwrap_or_default(),
        env,
        workdir: config.working_dir.clone().unwrap_or_else(|| "/".to_string()),
        user: config.user.clone(),
        exposed_ports,
        runtime: RuntimeConfig::default(),
        health: None,
        history: Vec::new(), // Pulled images don't have local history
    }
}

/// Platform resolver that always selects Linux images.
fn linux_platform_resolver(manifests: &[ImageIndexEntry]) -> Option<String> {
    let host_arch = std::env::consts::ARCH;
    let arch = match host_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    debug!("Looking for linux/{} image variant", arch);

    // Try native architecture first
    if let Some(entry) = find_linux_arch(manifests, arch) {
        debug!("Found native linux/{} image", arch);
        return Some(entry.digest.clone());
    }

    // Rosetta fallback on macOS ARM64
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        debug!("Native ARM64 image not found, trying x86_64 (Rosetta fallback)");

        if let Some(entry) = find_linux_arch(manifests, "amd64") {
            info!("Native ARM64 image not available, using x86_64 via Rosetta 2 emulation");
            return Some(entry.digest.clone());
        }

        if let Some(entry) = find_linux_arch(manifests, "x86_64") {
            info!("Native ARM64 image not available, using x86_64 via Rosetta 2 emulation");
            return Some(entry.digest.clone());
        }
    }

    debug!("No suitable linux image found for architecture {}", arch);
    None
}

/// Find a manifest entry for a specific Linux architecture.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_ref_simple() {
        let (name, tag) = parse_image_ref("nginx");
        assert_eq!(name, "nginx");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_parse_image_ref_with_tag() {
        let (name, tag) = parse_image_ref("nginx:1.25");
        assert_eq!(name, "nginx");
        assert_eq!(tag, "1.25");
    }

    #[test]
    fn test_parse_image_ref_with_org() {
        let (name, tag) = parse_image_ref("myorg/myapp:v1.0");
        assert_eq!(name, "myorg/myapp");
        assert_eq!(tag, "v1.0");
    }

    #[test]
    fn test_parse_image_ref_full_registry() {
        let (name, tag) = parse_image_ref("ghcr.io/org/repo:latest");
        assert_eq!(name, "ghcr.io/org/repo");
        assert_eq!(tag, "latest");
    }
}
