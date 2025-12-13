//! Centralized image building API for HYPR.
//!
//! This module provides the unified build API used by:
//! - CLI (`hypr build`)
//! - Daemon (gRPC BuildImage)
//! - Compose converter (service builds)
//!
//! The build logic is based on the proven CLI implementation with
//! additional cache_from support from the compose converter.

use crate::builder::oci::OciClient;
use crate::builder::parser::parse_dockerfile;
use crate::builder::{create_builder, BuildContext, BuildGraph, BuildOutput, CacheManager};
use crate::error::{HyprError, Result};
use crate::paths;
use crate::state::StateManager;
use crate::types::image::{LayerHistory, RestartPolicy, RuntimeConfig};
use crate::types::{Image, ImageManifest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, instrument, warn};

/// Options for building an image.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Path to the build context directory
    pub context_path: PathBuf,

    /// Path to Dockerfile relative to context (default: "Dockerfile")
    pub dockerfile: String,

    /// Image name (e.g., "myapp")
    pub name: String,

    /// Image tag (e.g., "latest")
    pub tag: String,

    /// Build arguments (ARG values)
    pub build_args: HashMap<String, String>,

    /// Target build stage for multi-stage builds
    pub target: Option<String>,

    /// Disable build cache
    pub no_cache: bool,

    /// Images to use as cache sources (pulls layers from these images)
    pub cache_from: Vec<String>,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            context_path: PathBuf::from("."),
            dockerfile: "Dockerfile".to_string(),
            name: "image".to_string(),
            tag: "latest".to_string(),
            build_args: HashMap::new(),
            target: None,
            no_cache: false,
            cache_from: Vec::new(),
        }
    }
}

/// Result of a successful build before registration.
#[derive(Debug)]
pub struct BuildResult {
    /// The raw build output from the executor
    pub output: BuildOutput,

    /// Build statistics
    pub cached_layers: usize,
    pub total_layers: usize,
    pub duration_secs: f64,

    /// Layer history for image history command
    pub history: Vec<LayerHistory>,
}

/// Build an image from a Dockerfile.
///
/// This is the core build function that:
/// 1. Parses the Dockerfile
/// 2. Constructs and validates the build graph
/// 3. Initializes caching (with cache_from support)
/// 4. Executes the build
///
/// After building, call `register_image()` to save to the database.
#[instrument(skip(options), fields(name = %options.name, tag = %options.tag))]
pub async fn build_image(options: BuildOptions) -> Result<BuildResult> {
    let start_time = std::time::Instant::now();

    info!(
        "Building image {}:{} from {:?}",
        options.name, options.tag, options.context_path
    );

    // Validate context path
    let context_path = options.context_path.canonicalize().map_err(|e| {
        HyprError::FileReadError {
            path: options.context_path.to_string_lossy().to_string(),
            source: e,
        }
    })?;

    // Validate Dockerfile exists
    let dockerfile_path = context_path.join(&options.dockerfile);
    if !dockerfile_path.exists() {
        return Err(HyprError::InvalidDockerfile {
            path: dockerfile_path.clone(),
            reason: "Dockerfile not found".to_string(),
        });
    }

    // Phase 1: Parse Dockerfile
    debug!("Parsing Dockerfile: {:?}", dockerfile_path);
    let dockerfile_content =
        std::fs::read_to_string(&dockerfile_path).map_err(|e| HyprError::FileReadError {
            path: dockerfile_path.to_string_lossy().to_string(),
            source: e,
        })?;

    let parsed_dockerfile = parse_dockerfile(&dockerfile_content).map_err(|e| {
        HyprError::InvalidDockerfile {
            path: dockerfile_path.clone(),
            reason: e.to_string(),
        }
    })?;

    let num_stages = parsed_dockerfile.stages.len();
    let total_instructions: usize = parsed_dockerfile
        .stages
        .iter()
        .map(|s| s.instructions.len())
        .sum();

    info!(
        "Parsed Dockerfile: {} stages, {} instructions",
        num_stages, total_instructions
    );

    // Phase 2: Build graph
    debug!("Constructing build graph");
    let graph = BuildGraph::from_dockerfile(&parsed_dockerfile).map_err(|e| {
        HyprError::BuildFailed {
            reason: format!("Failed to construct build graph: {}", e),
        }
    })?;

    // Validate execution order (topological sort)
    let execution_order = graph.topological_sort().map_err(|e| HyprError::BuildFailed {
        reason: format!("Invalid build graph (cycle detected?): {}", e),
    })?;

    info!("Build graph ready: {} steps", execution_order.len());

    // Phase 3: Initialize cache
    debug!("Initializing cache manager");
    let mut cache = CacheManager::new().map_err(|e| HyprError::BuildFailed {
        reason: format!("Failed to initialize cache: {}", e),
    })?;

    // Handle cache_from: import layers from specified images
    if !options.cache_from.is_empty() {
        info!("Processing cache_from sources: {:?}", options.cache_from);
        for cache_image in &options.cache_from {
            match import_cache_from_image(&mut cache, cache_image).await {
                Ok(layers) => {
                    info!("Imported {} cached layers from {}", layers, cache_image);
                }
                Err(e) => {
                    // cache_from failures are non-fatal - just log and continue
                    warn!("Failed to import cache from {}: {}", cache_image, e);
                }
            }
        }
    }

    // Phase 4: Create build context
    let context = BuildContext {
        context_path: context_path.clone(),
        dockerfile_path: PathBuf::from(&options.dockerfile),
        build_args: options.build_args.clone(),
        target: options.target.clone(),
        no_cache: options.no_cache,
    };

    // Phase 5: Execute build
    info!("Executing build");
    let mut builder = create_builder().map_err(|e| HyprError::BuildFailed {
        reason: format!("Failed to create builder: {}", e),
    })?;

    let output = builder
        .execute(&graph, &context, &mut cache)
        .await
        .map_err(|e| HyprError::BuildFailed {
            reason: format!("Build execution failed: {}", e),
        })?;

    let duration = start_time.elapsed();

    info!(
        "Build completed in {:.1}s: image_id={}",
        duration.as_secs_f64(),
        output.image_id
    );

    // Generate layer history from parsed Dockerfile
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let history: Vec<LayerHistory> = parsed_dockerfile
        .stages
        .iter()
        .enumerate()
        .flat_map(|(stage_idx, stage)| {
            stage.instructions.iter().enumerate().map(move |(instr_idx, instr)| {
                // Format the instruction for display
                let created_by = format!("{:?}", instr);
                let created_by = if created_by.len() > 100 {
                    format!("{}...", &created_by[..97])
                } else {
                    created_by
                };

                // Determine if this is an empty layer (metadata-only instructions)
                let empty_layer = matches!(
                    instr,
                    crate::builder::parser::Instruction::Env { .. }
                        | crate::builder::parser::Instruction::Label { .. }
                        | crate::builder::parser::Instruction::Expose { .. }
                        | crate::builder::parser::Instruction::Volume { .. }
                        | crate::builder::parser::Instruction::User { .. }
                        | crate::builder::parser::Instruction::Workdir { .. }
                        | crate::builder::parser::Instruction::Arg { .. }
                        | crate::builder::parser::Instruction::Stopsignal { .. }
                        | crate::builder::parser::Instruction::Entrypoint { .. }
                        | crate::builder::parser::Instruction::Cmd { .. }
                );

                LayerHistory {
                    id: format!("{:08x}", (stage_idx * 1000 + instr_idx) as u32),
                    created_by,
                    size_bytes: 0, // Size calculated later if needed
                    created_at: now_secs,
                    comment: String::new(),
                    empty_layer,
                }
            })
        })
        .collect();

    Ok(BuildResult {
        cached_layers: output.stats.cached_layers,
        total_layers: output.stats.layer_count,
        duration_secs: duration.as_secs_f64(),
        output,
        history,
    })
}

/// Register a built image in the database.
///
/// This function:
/// 1. Moves the rootfs to the permanent images directory
/// 2. Converts the build manifest to the full ImageManifest
/// 3. Optionally overwrites existing image with same name:tag
/// 4. Inserts the image into the database
#[instrument(skip(build_result, state), fields(name = %name, tag = %tag))]
pub async fn register_image(
    build_result: &BuildResult,
    name: &str,
    tag: &str,
    overwrite: bool,
    state: &StateManager,
) -> Result<Image> {
    info!("Registering image {}:{}", name, tag);

    let output = &build_result.output;

    // Move rootfs to permanent location
    let images_dir = paths::images_dir();
    let image_dir = images_dir.join(&output.image_id);

    std::fs::create_dir_all(&image_dir)
        .map_err(|e| HyprError::IoError { path: image_dir.clone(), source: e })?;

    let permanent_rootfs = image_dir.join("rootfs.squashfs");

    // Copy instead of rename to handle cross-filesystem moves
    if output.rootfs_path.exists() {
        std::fs::copy(&output.rootfs_path, &permanent_rootfs).map_err(|e| HyprError::IoError {
            path: permanent_rootfs.clone(),
            source: e,
        })?;
        // Clean up the temp file
        let _ = std::fs::remove_file(&output.rootfs_path);
    }

    // Convert builder manifest to full ImageManifest
    let manifest = ImageManifest {
        version: "1".to_string(),
        name: output.manifest.name.clone(),
        tag: output.manifest.tag.clone(),
        architecture: output.manifest.architecture.clone(),
        os: output.manifest.os.clone(),
        entrypoint: output.manifest.config.entrypoint.clone().unwrap_or_default(),
        cmd: output.manifest.config.cmd.clone().unwrap_or_default(),
        env: output.manifest.config.env.clone(),
        workdir: output
            .manifest
            .config
            .workdir
            .clone()
            .unwrap_or_else(|| "/".to_string()),
        user: output.manifest.config.user.clone(),
        exposed_ports: output
            .manifest
            .config
            .exposed_ports
            .iter()
            .filter_map(|p| p.parse::<u16>().ok())
            .collect(),
        runtime: RuntimeConfig {
            default_memory_mb: 512,
            default_cpus: 2,
            kernel_channel: "stable".to_string(),
            rootfs_type: "squashfs".to_string(),
            restart_policy: RestartPolicy::Always,
        },
        health: None, // TODO: Extract health check from Dockerfile
        history: build_result.history.clone(),
    };

    let image = Image {
        id: output.image_id.clone(),
        name: name.to_string(),
        tag: tag.to_string(),
        manifest,
        rootfs_path: permanent_rootfs.clone(),
        size_bytes: output.stats.total_size,
        created_at: SystemTime::now(),
    };

    // Handle overwrite (Docker-like behavior)
    if overwrite && state.delete_image_by_name_tag(name, tag).await.is_ok() {
        debug!("Overwrote existing image {}:{}", name, tag);
    }

    // Insert into database
    state
        .insert_image(&image)
        .await
        .map_err(|e| HyprError::DatabaseError(format!("Failed to register image: {}", e)))?;

    info!("Image registered: {} ({})", image.id, permanent_rootfs.display());

    Ok(image)
}

/// Import layers from a cache_from image into the cache manager.
///
/// Supports both local images (in images directory) and remote images (pulled).
/// Returns the number of layers imported.
#[instrument(skip(cache))]
async fn import_cache_from_image(cache: &mut CacheManager, image_ref: &str) -> Result<usize> {
    info!("Attempting to import cache from image: {}", image_ref);

    // Check if it's a local image first
    let images_dir = paths::images_dir();

    // Parse image reference (name:tag or just name)
    let name = if image_ref.contains(':') {
        image_ref.split(':').next().unwrap_or(image_ref)
    } else {
        image_ref
    };

    // Look for local image
    let local_image_dir = images_dir.join(name);
    if local_image_dir.exists() {
        let layers_imported = import_local_image_cache(cache, &local_image_dir)?;
        return Ok(layers_imported);
    }

    // Try to pull the image and extract layers
    let cache_dir = paths::cache_dir();
    let temp_dir = cache_dir.join(format!("cache-from-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| HyprError::IoError { path: temp_dir.clone(), source: e })?;

    // Pull the image
    let mut oci_client = OciClient::new().map_err(|e| HyprError::BuildFailed {
        reason: format!("Failed to create OCI client: {}", e),
    })?;

    match oci_client.pull_image(image_ref, &temp_dir).await {
        Ok(_) => {
            let layers_imported = import_local_image_cache(cache, &temp_dir)?;
            let _ = std::fs::remove_dir_all(&temp_dir);
            Ok(layers_imported)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&temp_dir);
            Err(HyprError::BuildFailed {
                reason: format!("Failed to pull cache_from image {}: {}", image_ref, e),
            })
        }
    }
}

/// Import layers from a local image directory into the cache.
fn import_local_image_cache(cache: &mut CacheManager, image_dir: &Path) -> Result<usize> {
    let mut layers_imported = 0;

    // Look for layer files in layers/ subdirectory
    let layers_dir = image_dir.join("layers");

    if layers_dir.exists() {
        for entry in std::fs::read_dir(&layers_dir)
            .map_err(|e| HyprError::IoError { path: layers_dir.clone(), source: e })?
        {
            let entry =
                entry.map_err(|e| HyprError::IoError { path: layers_dir.clone(), source: e })?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("tar") {
                let cache_key = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");

                match std::fs::read(&path) {
                    Ok(data) => {
                        let description = format!("Imported from cache_from: {}", path.display());
                        if cache.insert(cache_key, &data, description, 0).is_ok() {
                            layers_imported += 1;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    Ok(layers_imported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_options_default() {
        let options = BuildOptions::default();
        assert_eq!(options.dockerfile, "Dockerfile");
        assert_eq!(options.tag, "latest");
        assert!(!options.no_cache);
        assert!(options.cache_from.is_empty());
    }
}
