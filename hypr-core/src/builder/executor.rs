//! Build executor for HYPR images.
//!
//! Executes build instructions and produces image layers.
//! Platform-specific implementations:
//! - Linux: Native builder with chroot isolation
//! - macOS: VM-based builder with HVF/vfkit

use crate::builder::graph::{BuildGraph, BuildNode};
use crate::builder::parser::{Instruction, RunCommand};
use crate::builder::cache::CacheManager;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Result type for build operations.
pub type BuildResult<T> = Result<T, BuildError>;

/// Error type for build operations.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Build instruction failed: {instruction}\n{details}")]
    InstructionFailed {
        instruction: String,
        details: String,
    },

    #[error("Base image not found: {0}")]
    BaseImageNotFound(String),

    #[error("Build context error: {0}")]
    ContextError(String),

    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    #[error("Cache error: {0}")]
    Cache(#[from] crate::builder::cache::CacheError),
}

/// Build context containing source files and configuration.
#[derive(Debug, Clone)]
pub struct BuildContext {
    /// Path to the build context directory (usually contains Dockerfile)
    pub context_path: PathBuf,
    /// Path to Dockerfile (relative to context)
    pub dockerfile_path: PathBuf,
    /// Build arguments (ARG values)
    pub build_args: HashMap<String, String>,
    /// Target stage name (for multi-stage builds)
    pub target: Option<String>,
    /// Disable cache
    pub no_cache: bool,
}

/// Result of a successful build.
#[derive(Debug, Clone)]
pub struct BuildOutput {
    /// Final image ID (SHA256 of manifest)
    pub image_id: String,
    /// Path to the final rootfs (SquashFS)
    pub rootfs_path: PathBuf,
    /// Image manifest (metadata)
    pub manifest: ImageManifest,
    /// Build statistics
    pub stats: BuildStats,
}

/// Image manifest with metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageManifest {
    /// Image name and tag
    pub name: String,
    pub tag: String,
    /// Created timestamp
    pub created: String,
    /// Architecture
    pub architecture: String,
    /// OS
    pub os: String,
    /// Configuration from Dockerfile
    pub config: ImageConfig,
}

/// Image configuration extracted from Dockerfile.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageConfig {
    /// Entrypoint command
    pub entrypoint: Option<Vec<String>>,
    /// CMD command
    pub cmd: Option<Vec<String>>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Working directory
    pub workdir: Option<String>,
    /// User
    pub user: Option<String>,
    /// Exposed ports
    pub exposed_ports: Vec<String>,
    /// Volumes
    pub volumes: Vec<String>,
    /// Labels
    pub labels: HashMap<String, String>,
}

/// Build statistics.
#[derive(Debug, Clone)]
pub struct BuildStats {
    /// Total build time (seconds)
    pub duration_secs: f64,
    /// Number of layers
    pub layer_count: usize,
    /// Number of cached layers (cache hits)
    pub cached_layers: usize,
    /// Total size of all layers (bytes)
    pub total_size: u64,
}

/// Platform-agnostic build executor trait.
pub trait BuildExecutor {
    /// Executes a build from a graph.
    fn execute(
        &mut self,
        graph: &BuildGraph,
        context: &BuildContext,
        cache: &mut CacheManager,
    ) -> BuildResult<BuildOutput>;
}

/// Native builder for Linux (uses chroot).
#[cfg(target_os = "linux")]
pub struct NativeBuilder {
    /// Working directory for builds
    work_dir: PathBuf,
}

#[cfg(target_os = "linux")]
impl NativeBuilder {
    /// Creates a new native builder.
    pub fn new() -> BuildResult<Self> {
        let work_dir = Self::create_work_dir()?;
        Ok(Self { work_dir })
    }

    /// Creates a temporary working directory for builds.
    fn create_work_dir() -> BuildResult<PathBuf> {
        let temp = std::env::temp_dir();
        let work_dir = temp.join(format!("hypr-build-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)?;
        Ok(work_dir)
    }

    /// Executes a single build node.
    fn execute_node(
        &mut self,
        node: &BuildNode,
        context: &BuildContext,
        cache: &mut CacheManager,
    ) -> BuildResult<Option<PathBuf>> {
        // Check cache first (unless no-cache is set)
        if !context.no_cache {
            match cache.lookup(&node.cache_key)? {
                crate::builder::cache::CacheLookupResult::Hit { layer_path, metadata } => {
                    info!("Cache hit for {}: {}", node.cache_key, metadata.step_description);
                    return Ok(Some(layer_path));
                }
                crate::builder::cache::CacheLookupResult::Miss => {
                    debug!("Cache miss for {}", node.cache_key);
                }
            }
        }

        // Execute instruction
        let layer_path = match &node.instruction {
            Instruction::From { .. } => {
                // FROM is handled specially (pulls base image)
                self.execute_from(node)?
            }
            Instruction::Run { command } => {
                self.execute_run(command)?
            }
            Instruction::Copy { sources, destination, .. } => {
                self.execute_copy(sources, destination, context)?
            }
            Instruction::Add { sources, destination, .. } => {
                self.execute_add(sources, destination, context)?
            }
            Instruction::Env { vars } => {
                self.execute_env(vars)?
            }
            Instruction::Workdir { path } => {
                self.execute_workdir(path)?
            }
            Instruction::User { user } => {
                self.execute_user(user)?
            }
            // Other instructions don't create layers, just update metadata
            _ => return Ok(None),
        };

        // Cache the layer
        if let Some(ref path) = layer_path {
            let data = std::fs::read(path)?;
            let description = format!("{:?}", node.instruction);
            cache.insert(&node.cache_key, &data, description, node.stage_index)?;
        }

        Ok(layer_path)
    }

    fn execute_from(&mut self, node: &BuildNode) -> BuildResult<Option<PathBuf>> {
        // TODO: Pull base image from registry or local storage
        // For now, return placeholder
        warn!("FROM instruction not yet fully implemented");
        Ok(None)
    }

    fn execute_run(&mut self, command: &RunCommand) -> BuildResult<Option<PathBuf>> {
        // TODO: Execute command in chroot environment
        // For now, return placeholder
        let cmd_str = match command {
            RunCommand::Shell(s) => s.clone(),
            RunCommand::Exec(args) => args.join(" "),
        };

        debug!("Would execute RUN: {}", cmd_str);
        Ok(None)
    }

    fn execute_copy(
        &mut self,
        sources: &[String],
        destination: &str,
        context: &BuildContext,
    ) -> BuildResult<Option<PathBuf>> {
        debug!("Would copy {:?} to {}", sources, destination);
        Ok(None)
    }

    fn execute_add(
        &mut self,
        sources: &[String],
        destination: &str,
        context: &BuildContext,
    ) -> BuildResult<Option<PathBuf>> {
        debug!("Would add {:?} to {}", sources, destination);
        Ok(None)
    }

    fn execute_env(&mut self, vars: &HashMap<String, String>) -> BuildResult<Option<PathBuf>> {
        debug!("Would set env vars: {:?}", vars);
        Ok(None)
    }

    fn execute_workdir(&mut self, path: &str) -> BuildResult<Option<PathBuf>> {
        debug!("Would set workdir: {}", path);
        Ok(None)
    }

    fn execute_user(&mut self, user: &str) -> BuildResult<Option<PathBuf>> {
        debug!("Would set user: {}", user);
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
impl BuildExecutor for NativeBuilder {
    fn execute(
        &mut self,
        graph: &BuildGraph,
        context: &BuildContext,
        cache: &mut CacheManager,
    ) -> BuildResult<BuildOutput> {
        info!("Starting native build (Linux)");

        let start = std::time::Instant::now();
        let mut cached_layers = 0;
        let mut total_layers = 0;

        // Get topological order
        let order = graph.topological_sort()
            .map_err(|e| BuildError::ContextError(format!("Graph error: {}", e)))?;

        // Execute each node in order
        for node_id in order {
            let node = graph.get_node(node_id)
                .ok_or_else(|| BuildError::ContextError(format!("Node {} not found", node_id)))?;

            debug!("Executing node {}: {:?}", node_id, node.instruction);

            if let Some(_layer_path) = self.execute_node(node, context, cache)? {
                total_layers += 1;
                // Check if it was a cache hit
                // (We'd need to track this more carefully in production)
            }
        }

        let duration = start.elapsed();

        // TODO: Generate final rootfs and manifest
        // For now, return placeholder
        let output = BuildOutput {
            image_id: "placeholder".to_string(),
            rootfs_path: self.work_dir.join("rootfs.squashfs"),
            manifest: ImageManifest {
                name: "myimage".to_string(),
                tag: "latest".to_string(),
                created: chrono::Utc::now().to_rfc3339(),
                architecture: "x86_64".to_string(),
                os: "linux".to_string(),
                config: ImageConfig {
                    entrypoint: None,
                    cmd: None,
                    env: HashMap::new(),
                    workdir: None,
                    user: None,
                    exposed_ports: Vec::new(),
                    volumes: Vec::new(),
                    labels: HashMap::new(),
                },
            },
            stats: BuildStats {
                duration_secs: duration.as_secs_f64(),
                layer_count: total_layers,
                cached_layers,
                total_size: 0,
            },
        };

        Ok(output)
    }
}

/// VM-based builder for macOS (uses HVF/vfkit).
#[cfg(target_os = "macos")]
pub struct VmBuilder {
    /// Path to builder VM image
    #[allow(dead_code)]
    vm_image: PathBuf,
}

#[cfg(target_os = "macos")]
impl VmBuilder {
    pub fn new() -> BuildResult<Self> {
        // TODO: Set up builder VM
        Err(BuildError::PlatformNotSupported(
            "VM builder not yet implemented".to_string(),
        ))
    }
}

#[cfg(target_os = "macos")]
impl BuildExecutor for VmBuilder {
    fn execute(
        &mut self,
        _graph: &BuildGraph,
        _context: &BuildContext,
        _cache: &mut CacheManager,
    ) -> BuildResult<BuildOutput> {
        Err(BuildError::PlatformNotSupported(
            "VM builder not yet implemented".to_string(),
        ))
    }
}

/// Creates the appropriate builder for the current platform.
pub fn create_builder() -> BuildResult<Box<dyn BuildExecutor>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(NativeBuilder::new()?))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(VmBuilder::new()?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(BuildError::PlatformNotSupported(
            std::env::consts::OS.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_native_builder_creation() {
        let builder = NativeBuilder::new();
        assert!(builder.is_ok());
    }

    #[test]
    fn test_build_context_creation() {
        let context = BuildContext {
            context_path: PathBuf::from("."),
            dockerfile_path: PathBuf::from("Dockerfile"),
            build_args: HashMap::new(),
            target: None,
            no_cache: false,
        };

        assert_eq!(context.dockerfile_path, PathBuf::from("Dockerfile"));
        assert!(!context.no_cache);
    }

    #[test]
    fn test_image_config_default() {
        let config = ImageConfig {
            entrypoint: None,
            cmd: Some(vec!["nginx".to_string()]),
            env: HashMap::new(),
            workdir: Some("/app".to_string()),
            user: None,
            exposed_ports: vec!["80/tcp".to_string()],
            volumes: Vec::new(),
            labels: HashMap::new(),
        };

        assert_eq!(config.cmd, Some(vec!["nginx".to_string()]));
        assert_eq!(config.workdir, Some("/app".to_string()));
        assert_eq!(config.exposed_ports.len(), 1);
    }
}
