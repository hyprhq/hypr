//! Build executor for HYPR images.
//!
//! Executes build instructions and produces image layers.
//! Platform-specific implementations:
//! - Linux: Native builder with chroot isolation
//! - macOS: VM-based builder with libkrun

use crate::builder::cache::CacheManager;
use crate::builder::graph::BuildGraph;
use crate::builder::parser::Instruction;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, info};

#[cfg(target_os = "linux")]
use tracing::instrument;

#[cfg(target_os = "linux")]
use crate::builder::graph::BuildNode;
#[cfg(target_os = "linux")]
use crate::builder::parser::RunCommand;
#[cfg(target_os = "linux")]
use std::path::Path;

/// Result type for build operations.
pub type BuildResult<T> = Result<T, BuildError>;

/// Error type for build operations.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Build instruction failed: {instruction}\n{details}")]
    InstructionFailed { instruction: String, details: String },

    #[error("Base image not found: {0}")]
    BaseImageNotFound(String),

    #[error("Build context error: {0}")]
    ContextError(String),

    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    #[error("Cache error: {0}")]
    Cache(#[from] crate::builder::cache::CacheError),

    #[error("Manifest error: {0}")]
    Manifest(#[from] crate::builder::manifest::ManifestError),

    #[error("Image pull failed: {image}\n{reason}")]
    ImagePullFailed { image: String, reason: String },

    #[error("Invalid image reference: {image}\n{reason}")]
    InvalidImageRef { image: String, reason: String },

    #[error("Layer extraction failed: {path}\n{reason}")]
    LayerExtractionFailed { path: PathBuf, reason: String },

    #[error("I/O error at {path}: {source}")]
    IoError { path: PathBuf, source: std::io::Error },

    #[error("Mount failed: {target}\n{reason}")]
    MountFailed { target: PathBuf, reason: String },

    #[error("Command execution failed: {command}\nExit code: {exit_code}\n{stderr}")]
    CommandFailed { command: String, exit_code: i32, stderr: String },
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
#[async_trait]
pub trait BuildExecutor: Send {
    /// Executes a build from a graph.
    async fn execute(
        &mut self,
        graph: &BuildGraph,
        context: &BuildContext,
        cache: &mut CacheManager,
    ) -> BuildResult<BuildOutput>;
}

/// Native builder for Linux (uses overlayfs + chroot).
#[cfg(target_os = "linux")]
pub struct NativeBuilder {
    /// Working directory for builds
    work_dir: PathBuf,
    /// Current rootfs (merged from all layers)
    current_rootfs: PathBuf,
    /// Overlay layers (lower dirs)
    layers: Vec<PathBuf>,
    /// Current environment variables
    env: HashMap<String, String>,
    /// Current working directory
    current_workdir: String,
    /// Current user
    current_user: String,
    /// OCI registry client for pulling base images
    oci_client: crate::builder::oci::OciClient,
}

#[cfg(target_os = "linux")]
impl NativeBuilder {
    /// Creates a new native builder.
    #[instrument]
    pub fn new() -> BuildResult<Self> {
        let work_dir = Self::create_work_dir()?;
        let current_rootfs = work_dir.join("rootfs");
        std::fs::create_dir_all(&current_rootfs)?;

        let oci_client = crate::builder::oci::OciClient::new()?;

        Ok(Self {
            work_dir,
            current_rootfs,
            layers: Vec::new(),
            env: HashMap::new(),
            current_workdir: "/".to_string(),
            current_user: "root".to_string(),
            oci_client,
        })
    }

    /// Creates a temporary working directory for builds.
    fn create_work_dir() -> BuildResult<PathBuf> {
        let cache_dir = crate::paths::cache_dir();
        let work_dir = cache_dir.join(format!("build-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)?;
        Ok(work_dir)
    }

    /// Creates a REAL overlay filesystem for a build step using Linux kernel mount().
    ///
    /// This uses the Linux overlayfs to create a union mount with:
    /// - lower: read-only base (current_rootfs)
    /// - upper: writable layer (captures changes)
    /// - work: kernel scratch space
    /// - merged: the combined view (where chroot happens)
    ///
    /// Returns (merged_dir, upper_dir, work_dir)
    fn create_overlay(&self, step_id: usize) -> BuildResult<(PathBuf, PathBuf, PathBuf)> {
        use nix::mount::{mount, MsFlags};
        use tracing::{debug, info};

        let overlay_dir = self.work_dir.join(format!("overlay-{}", step_id));
        let lower_dir = &self.current_rootfs; // Use current rootfs as lower (read-only)
        let upper_dir = overlay_dir.join("upper");
        let work_dir = overlay_dir.join("work");
        let merged_dir = overlay_dir.join("merged");

        // Create overlay directories
        std::fs::create_dir_all(&upper_dir)
            .map_err(|e| BuildError::IoError { path: upper_dir.clone(), source: e })?;
        std::fs::create_dir_all(&work_dir)
            .map_err(|e| BuildError::IoError { path: work_dir.clone(), source: e })?;
        std::fs::create_dir_all(&merged_dir)
            .map_err(|e| BuildError::IoError { path: merged_dir.clone(), source: e })?;

        // Mount overlayfs using Linux kernel mount() syscall
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower_dir.display(),
            upper_dir.display(),
            work_dir.display()
        );

        debug!(
            lower = %lower_dir.display(),
            upper = %upper_dir.display(),
            work = %work_dir.display(),
            merged = %merged_dir.display(),
            "Mounting overlayfs"
        );

        mount(
            Some("overlay"),
            &merged_dir,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
        .map_err(|e| BuildError::MountFailed {
            target: merged_dir.clone(),
            reason: format!("overlayfs mount failed: {}", e),
        })?;

        info!(
            merged = %merged_dir.display(),
            "Overlayfs mounted successfully"
        );

        Ok((merged_dir, upper_dir, work_dir))
    }

    /// Unmounts an overlayfs mount point.
    fn unmount_overlay(&self, merged_dir: &Path) -> BuildResult<()> {
        use nix::mount::umount;
        use tracing::debug;

        debug!(path = %merged_dir.display(), "Unmounting overlayfs");

        umount(merged_dir).map_err(|e| BuildError::MountFailed {
            target: merged_dir.to_path_buf(),
            reason: format!("unmount failed: {}", e),
        })?;

        Ok(())
    }

    /// Executes a command in a REAL chroot environment with proper bind mounts.
    ///
    /// Sets up:
    /// - /proc bind mount (process info)
    /// - /sys bind mount (sysfs)
    /// - /dev bind mount (devices)
    /// - Then chroots and executes command
    fn execute_in_chroot(
        &self,
        rootfs: &PathBuf,
        command: &[String],
        env: &HashMap<String, String>,
        workdir: &str,
    ) -> BuildResult<()> {
        use nix::mount::{mount, umount, MsFlags};
        use std::process::Command;
        use tracing::{debug, info};

        // Create mount points inside chroot
        let proc_dir = rootfs.join("proc");
        let sys_dir = rootfs.join("sys");
        let dev_dir = rootfs.join("dev");

        std::fs::create_dir_all(&proc_dir)
            .map_err(|e| BuildError::IoError { path: proc_dir.clone(), source: e })?;
        std::fs::create_dir_all(&sys_dir)
            .map_err(|e| BuildError::IoError { path: sys_dir.clone(), source: e })?;
        std::fs::create_dir_all(&dev_dir)
            .map_err(|e| BuildError::IoError { path: dev_dir.clone(), source: e })?;

        debug!("Bind mounting /proc /sys /dev into chroot");

        // Bind mount /proc
        mount(
            Some("/proc"),
            &proc_dir,
            Some("proc"),
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| BuildError::MountFailed {
            target: proc_dir.clone(),
            reason: format!("/proc bind mount failed: {}", e),
        })?;

        // Bind mount /sys
        mount(
            Some("/sys"),
            &sys_dir,
            Some("sysfs"),
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| {
            let _ = umount(&proc_dir); // cleanup
            BuildError::MountFailed {
                target: sys_dir.clone(),
                reason: format!("/sys bind mount failed: {}", e),
            }
        })?;

        // Bind mount /dev
        mount(
            Some("/dev"),
            &dev_dir,
            Some("devtmpfs"),
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| {
            let _ = umount(&proc_dir); // cleanup
            let _ = umount(&sys_dir); // cleanup
            BuildError::MountFailed {
                target: dev_dir.clone(),
                reason: format!("/dev bind mount failed: {}", e),
            }
        })?;

        // Create working directory if needed
        let workdir_in_rootfs = rootfs.join(workdir.trim_start_matches('/'));
        std::fs::create_dir_all(&workdir_in_rootfs)
            .map_err(|e| BuildError::IoError { path: workdir_in_rootfs.clone(), source: e })?;

        // Build chroot command
        let mut cmd = Command::new("chroot");
        cmd.arg(rootfs);
        for arg in command {
            cmd.arg(arg);
        }

        // Set environment
        cmd.env_clear();
        cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        cmd.env("HOME", "/root");
        cmd.env("DEBIAN_FRONTEND", "noninteractive"); // Prevent interactive prompts
        for (key, value) in env {
            cmd.env(key, value);
        }

        info!(command = ?command, "Executing in chroot");

        // Execute command
        let output = cmd.output().map_err(|e| {
            // Cleanup mounts on error
            let _ = umount(&dev_dir);
            let _ = umount(&sys_dir);
            let _ = umount(&proc_dir);
            BuildError::InstructionFailed {
                instruction: format!("{:?}", command),
                details: format!("Failed to execute chroot: {}", e),
            }
        })?;

        // Cleanup: unmount in reverse order
        debug!("Cleaning up bind mounts");
        umount(&dev_dir).map_err(|e| BuildError::MountFailed {
            target: dev_dir.clone(),
            reason: format!("unmount /dev failed: {}", e),
        })?;
        umount(&sys_dir).map_err(|e| BuildError::MountFailed {
            target: sys_dir.clone(),
            reason: format!("unmount /sys failed: {}", e),
        })?;
        umount(&proc_dir).map_err(|e| BuildError::MountFailed {
            target: proc_dir.clone(),
            reason: format!("unmount /proc failed: {}", e),
        })?;

        // Check command exit status
        if !output.status.success() {
            let exit_code = output.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BuildError::CommandFailed {
                command: format!("{:?}", command),
                exit_code,
                stderr: stderr.to_string(),
            });
        }

        info!("Command completed successfully");
        Ok(())
    }

    /// Captures a layer by creating a tarball of the upper directory.
    fn capture_layer(&self, upper_dir: &PathBuf, step_id: usize) -> BuildResult<PathBuf> {
        let layer_path = self.work_dir.join(format!("layer-{}.tar", step_id));

        // Create tarball of upper directory
        let tar_gz = std::fs::File::create(&layer_path)?;
        let mut ar = tar::Builder::new(tar_gz);
        ar.append_dir_all(".", upper_dir)?;
        ar.finish()?;

        Ok(layer_path)
    }

    /// Merges a layer into the current rootfs.
    fn merge_layer(&mut self, upper_dir: &PathBuf) -> BuildResult<()> {
        // Copy upper dir contents to current rootfs
        if std::fs::read_dir(upper_dir)?.next().is_some() {
            Self::copy_dir_all(upper_dir, &self.current_rootfs)?;
        }
        Ok(())
    }

    /// Recursively copies a directory tree, preserving structure and permissions.
    fn copy_dir_all(src: &PathBuf, dst: &PathBuf) -> BuildResult<()> {
        debug!("copy_dir_all: Creating dest directory: {}", dst.display());
        std::fs::create_dir_all(dst)
            .map_err(|e| BuildError::IoError { path: dst.clone(), source: e })?;

        debug!("copy_dir_all: Reading source directory: {}", src.display());
        for entry in std::fs::read_dir(src)
            .map_err(|e| BuildError::IoError { path: src.clone(), source: e })?
        {
            let entry = entry.map_err(|e| BuildError::IoError { path: src.clone(), source: e })?;

            let src_path = entry.path();
            debug!("copy_dir_all: Processing entry: {}", src_path.display());

            let ty = entry
                .file_type()
                .map_err(|e| BuildError::IoError { path: src_path.clone(), source: e })?;

            let dst_path = dst.join(entry.file_name());

            // Skip special directories (pseudo-filesystems that shouldn't be copied)
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            if file_name_str == "proc" || file_name_str == "sys" || file_name_str == "dev" {
                // Create empty directory instead of copying
                debug!("copy_dir_all: Skipping pseudo-filesystem: {}", file_name_str);
                std::fs::create_dir_all(&dst_path)
                    .map_err(|e| BuildError::IoError { path: dst_path.clone(), source: e })?;
                continue;
            }

            if ty.is_symlink() {
                // Preserve symlinks
                debug!(
                    "copy_dir_all: Copying symlink: {} -> {}",
                    src_path.display(),
                    dst_path.display()
                );
                let link_target = std::fs::read_link(&src_path)
                    .map_err(|e| BuildError::IoError { path: src_path.clone(), source: e })?;
                // Remove destination if it exists (file or directory)
                if dst_path.exists() {
                    if dst_path.is_dir() {
                        let _ = std::fs::remove_dir_all(&dst_path);
                    } else {
                        let _ = std::fs::remove_file(&dst_path);
                    }
                }
                std::os::unix::fs::symlink(&link_target, &dst_path)
                    .map_err(|e| BuildError::IoError { path: dst_path.clone(), source: e })?;
            } else if ty.is_dir() {
                debug!("copy_dir_all: Recursing into directory: {}", src_path.display());
                Self::copy_dir_all(&src_path, &dst_path)?;
            } else {
                // Copy file
                debug!(
                    "copy_dir_all: Copying file: {} -> {}",
                    src_path.display(),
                    dst_path.display()
                );
                std::fs::copy(&src_path, &dst_path)
                    .map_err(|e| BuildError::IoError { path: src_path.clone(), source: e })?;
                // Preserve permissions
                let metadata = std::fs::metadata(&src_path)
                    .map_err(|e| BuildError::IoError { path: src_path.clone(), source: e })?;
                let permissions = metadata.permissions();
                std::fs::set_permissions(&dst_path, permissions)
                    .map_err(|e| BuildError::IoError { path: dst_path.clone(), source: e })?;
            }
        }

        Ok(())
    }

    /// Executes a single build node.
    ///
    /// Returns (layer_path, was_cached)
    fn execute_node(
        &mut self,
        node: &BuildNode,
        context: &BuildContext,
        cache: &mut CacheManager,
    ) -> BuildResult<(Option<PathBuf>, bool)> {
        // Check cache first (unless no-cache is set)
        if !context.no_cache {
            match cache.lookup(&node.cache_key)? {
                crate::builder::cache::CacheLookupResult::Hit { layer_path, metadata: _ } => {
                    return Ok((Some(layer_path), true));
                }
                crate::builder::cache::CacheLookupResult::Miss => {}
            }
        }

        // Execute instruction
        let layer_path = match &node.instruction {
            Instruction::From { .. } => {
                // FROM is handled specially (pulls base image)
                self.execute_from(node)?
            }
            Instruction::Run { command } => self.execute_run(command)?,
            Instruction::Copy { sources, destination, .. } => {
                self.execute_copy(sources, destination.as_str(), context)?
            }
            Instruction::Add { sources, destination, .. } => {
                self.execute_add(sources, destination.as_str(), context)?
            }
            Instruction::Env { vars } => self.execute_env(vars)?,
            Instruction::Workdir { path } => self.execute_workdir(path.as_str())?,
            Instruction::User { user } => self.execute_user(user.as_str())?,
            // Other instructions don't create layers, just update metadata
            _ => return Ok((None, false)),
        };

        // Cache the layer
        if let Some(ref path) = layer_path {
            let data = std::fs::read(path)?;
            let description = format!("{:?}", node.instruction);
            cache.insert(&node.cache_key, &data, description, node.stage_index)?;
        }

        Ok((layer_path, false))
    }

    fn execute_from(&mut self, node: &BuildNode) -> BuildResult<Option<PathBuf>> {
        use crate::builder::parser::{ImageRef, Instruction};
        use tracing::info;

        // Extract image reference from instruction
        let image_ref = match &node.instruction {
            Instruction::From { image, .. } => image,
            _ => {
                return Err(BuildError::InstructionFailed {
                    instruction: "FROM".to_string(),
                    details: "Expected FROM instruction".to_string(),
                })
            }
        };

        match image_ref {
            ImageRef::Scratch => {
                info!("FROM scratch: initializing empty rootfs");
                // Create minimal directory structure for scratch builds
                std::fs::create_dir_all(self.current_rootfs.join("tmp"))?;
                std::fs::create_dir_all(self.current_rootfs.join("etc"))?;
                std::fs::create_dir_all(self.current_rootfs.join("proc"))?;
                std::fs::create_dir_all(self.current_rootfs.join("sys"))?;
                std::fs::create_dir_all(self.current_rootfs.join("dev"))?;
                Ok(None)
            }
            ImageRef::Stage(stage_name) => {
                // Multi-stage builds: copy from another stage
                // This will be implemented in a future phase when multi-stage builds are supported
                Err(BuildError::InstructionFailed {
                    instruction: "FROM".to_string(),
                    details: format!("Multi-stage builds not yet supported: FROM {}", stage_name),
                })
            }
            ImageRef::Image { name, tag, digest } => {
                // Construct full image reference
                let image_str = if let Some(digest) = digest {
                    format!("{}@{}", name, digest)
                } else {
                    format!("{}:{}", name, tag.as_deref().unwrap_or("latest"))
                };

                info!("FROM {}: pulling base image from registry", image_str);

                // Pull image using OCI client
                // Use block_in_place to avoid nested runtime issues when called from async context
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        self.oci_client.pull_image(&image_str, &self.current_rootfs).await
                    })
                })?;

                info!("Base image extracted successfully to {}", self.current_rootfs.display());

                // FROM doesn't create a layer itself, just sets up the base
                Ok(None)
            }
        }
    }

    fn execute_run(&mut self, command: &RunCommand) -> BuildResult<Option<PathBuf>> {
        use crate::builder::parser::RunCommand;

        // Convert RunCommand to actual command args
        let cmd_args: Vec<String> = match command {
            RunCommand::Shell(cmd) => {
                vec!["/bin/sh".to_string(), "-c".to_string(), cmd.clone()]
            }
            RunCommand::Exec(args) => args.clone(),
        };

        // Create overlay for this step
        let step_id = self.layers.len();
        let (merged_dir, upper_dir, _work_dir) = self.create_overlay(step_id)?;

        // Execute command in chroot (cleanup overlayfs on error or success)
        let exec_result =
            self.execute_in_chroot(&merged_dir, &cmd_args, &self.env, &self.current_workdir);

        // CRITICAL: Unmount overlayfs regardless of success/failure
        self.unmount_overlay(&merged_dir)?;

        // Propagate execution error if it occurred
        exec_result?;

        // Capture the layer
        let layer_path = self.capture_layer(&upper_dir, step_id)?;

        // Merge changes into current rootfs
        self.merge_layer(&upper_dir)?;

        // Track this layer
        self.layers.push(layer_path.clone());

        Ok(Some(layer_path))
    }

    fn execute_copy(
        &mut self,
        sources: &[String],
        destination: &str,
        context: &BuildContext,
    ) -> BuildResult<Option<PathBuf>> {
        use tracing::info;

        let step_id = self.layers.len();

        // CRITICAL: Must copy current_rootfs first (contains base image files from FROM)
        // COPY doesn't need overlayfs but MUST preserve existing files
        let layer_dir = self.work_dir.join(format!("copy-layer-{}", step_id));
        std::fs::create_dir_all(&layer_dir)?;

        // Copy current rootfs to layer directory
        if std::fs::read_dir(&self.current_rootfs)
            .map_err(|e| BuildError::IoError { path: self.current_rootfs.clone(), source: e })?
            .next()
            .is_some()
        {
            info!(
                "Copying current rootfs {} to layer {}",
                self.current_rootfs.display(),
                layer_dir.display()
            );
            Self::copy_dir_all(&self.current_rootfs, &layer_dir)?;
        }

        // Resolve destination path
        // Docker semantics: if destination doesn't end with '/' and there's 1 source, it's a file rename
        let is_dest_dir = destination.ends_with('/') || sources.len() > 1;

        let dest_path = if destination.starts_with('/') {
            layer_dir.join(destination.trim_start_matches('/'))
        } else {
            layer_dir.join(self.current_workdir.trim_start_matches('/')).join(destination)
        };

        // If dest is a directory, create it. If it's a file path, create only the parent
        if is_dest_dir {
            std::fs::create_dir_all(&dest_path)?;
            info!("Created dest directory: {}", dest_path.display());
        } else if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
            info!(
                "Created parent directory: {} for dest: {}",
                parent.display(),
                dest_path.display()
            );
        }

        info!(sources = ?sources, destination = %destination, is_dest_dir = is_dest_dir, "Copying files");

        // Copy files from build context
        for source in sources {
            let src_path = context.context_path.join(source);
            info!(
                "COPY: source={} -> src_path={} (exists={})",
                source,
                src_path.display(),
                src_path.exists()
            );

            if !src_path.exists() {
                return Err(BuildError::ContextError(format!(
                    "Source file not found: {} (resolved to: {})",
                    source,
                    src_path.display()
                )));
            }

            // Determine target path based on whether dest is a directory or file
            let target_path = if is_dest_dir {
                // Dest is directory - copy into it with original filename
                let file_name = src_path.file_name().ok_or_else(|| {
                    BuildError::ContextError(format!("Invalid source path: {}", source))
                })?;
                dest_path.join(file_name)
            } else {
                // Dest is file path - copy directly to it (rename)
                dest_path.clone()
            };

            info!(
                "COPY: {} -> {} (is_dir={})",
                src_path.display(),
                target_path.display(),
                src_path.is_dir()
            );

            if src_path.is_dir() {
                Self::copy_dir_all(&src_path, &target_path)?;
            } else {
                std::fs::copy(&src_path, &target_path)
                    .map_err(|e| BuildError::IoError { path: src_path.clone(), source: e })?;
            }
        }

        // Capture the layer
        let layer_path = self.capture_layer(&layer_dir, step_id)?;

        // Merge changes into current rootfs
        self.merge_layer(&layer_dir)?;

        self.layers.push(layer_path.clone());

        Ok(Some(layer_path))
    }

    fn execute_add(
        &mut self,
        sources: &[String],
        destination: &str,
        context: &BuildContext,
    ) -> BuildResult<Option<PathBuf>> {
        // ADD is similar to COPY but also handles tar extraction
        // For now, just use COPY implementation
        // Tar extraction (.tar, .tar.gz, etc.) will be added in a future enhancement
        self.execute_copy(sources, destination, context)
    }

    fn execute_env(&mut self, vars: &HashMap<String, String>) -> BuildResult<Option<PathBuf>> {
        // ENV doesn't create a layer, just updates environment
        for (key, value) in vars {
            self.env.insert(key.clone(), value.clone());
        }
        Ok(None)
    }

    fn execute_workdir(&mut self, path: &str) -> BuildResult<Option<PathBuf>> {
        // WORKDIR creates the directory and sets it as current
        self.current_workdir = path.to_string();

        // Create the directory in the current rootfs
        let workdir_path = self.current_rootfs.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(&workdir_path)?;

        Ok(None)
    }

    fn execute_user(&mut self, user: &str) -> BuildResult<Option<PathBuf>> {
        // USER just tracks the user, doesn't create a layer
        self.current_user = user.to_string();
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl BuildExecutor for NativeBuilder {
    #[instrument(skip(self, graph, cache), fields(no_cache = context.no_cache))]
    async fn execute(
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
        let order = graph
            .topological_sort()
            .map_err(|e| BuildError::ContextError(format!("Graph error: {}", e)))?;

        // Execute each node in order
        for node_id in order {
            let node = graph
                .get_node(node_id)
                .ok_or_else(|| BuildError::ContextError(format!("Node {} not found", node_id)))?;

            // Determine instruction type for metrics
            let instruction_type = match &node.instruction {
                crate::builder::parser::Instruction::From { .. } => "From",
                crate::builder::parser::Instruction::Run { .. } => "Run",
                crate::builder::parser::Instruction::Copy { .. } => "Copy",
                crate::builder::parser::Instruction::Add { .. } => "Add",
                crate::builder::parser::Instruction::Env { .. } => "Env",
                crate::builder::parser::Instruction::Workdir { .. } => "Workdir",
                crate::builder::parser::Instruction::User { .. } => "User",
                crate::builder::parser::Instruction::Cmd { .. } => "Cmd",
                crate::builder::parser::Instruction::Entrypoint { .. } => "Entrypoint",
                crate::builder::parser::Instruction::Expose { .. } => "Expose",
                _ => "Other",
            };

            let (layer_path, was_cached) =
                self.execute_node(node, context, cache).map_err(|e| {
                    metrics::counter!("hypr_build_failures_total",
                        "platform" => "linux",
                        "step_type" => instruction_type,
                        "reason" => "execution_failed"
                    )
                    .increment(1);
                    e
                })?;

            if layer_path.is_some() {
                total_layers += 1;
                if was_cached {
                    cached_layers += 1;
                }
            }
        }

        let duration = start.elapsed();

        // Generate final SquashFS image
        let squashfs_path = self.generate_squashfs().map_err(|e| {
            metrics::counter!("hypr_build_failures_total",
                "platform" => "linux",
                "step_type" => "squashfs_generation",
                "reason" => "compression_failed"
            )
            .increment(1);
            e
        })?;

        // Calculate total size
        let total_size = std::fs::metadata(&squashfs_path)?.len();

        // Generate image ID (SHA256 of squashfs)
        use sha2::{Digest, Sha256};
        let squashfs_data = std::fs::read(&squashfs_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&squashfs_data);
        let image_id = format!("{:x}", hasher.finalize());

        // Generate manifest using ManifestGenerator
        use crate::builder::manifest::ManifestGenerator;
        let mut manifest_gen = ManifestGenerator::new();

        // Parse tag from context or use defaults
        let (name, tag) = ("myimage".to_string(), "latest".to_string());

        let manifest = manifest_gen.generate(graph, name, tag, None)?;

        let output = BuildOutput {
            image_id: image_id[..12].to_string(), // Short ID like Docker
            rootfs_path: squashfs_path,
            manifest,
            stats: BuildStats {
                duration_secs: duration.as_secs_f64(),
                layer_count: total_layers,
                cached_layers,
                total_size,
            },
        };

        // Record success metrics
        metrics::histogram!("hypr_build_duration_seconds").record(duration.as_secs_f64());
        metrics::counter!("hypr_build_complete_total", "platform" => "linux").increment(1);
        metrics::counter!("hypr_cache_hits_total").increment(cached_layers as u64);
        metrics::counter!("hypr_cache_misses_total")
            .increment((total_layers - cached_layers) as u64);
        info!(
            duration_secs = duration.as_secs_f64(),
            total_layers,
            cached_layers,
            image_size_bytes = total_size,
            "Build completed successfully"
        );

        Ok(output)
    }
}

#[cfg(target_os = "linux")]
impl NativeBuilder {
    /// Generates a SquashFS image from the current rootfs.
    ///
    /// The output is padded to 4KB alignment for macOS Virtualization.framework compatibility.
    /// Linux ignores trailing data in squashfs, so this is safe for cross-platform use.
    fn generate_squashfs(&self) -> BuildResult<PathBuf> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use tracing::{debug, info};

        let squashfs_path = self.work_dir.join("rootfs.squashfs");

        info!(
            rootfs = %self.current_rootfs.display(),
            output = %squashfs_path.display(),
            "Generating SquashFS image"
        );

        // Use mksquashfs command to create SquashFS with gzip compression
        // -comp gzip: Universal support in all kernels
        // -noappend: Overwrite if exists
        // -no-progress: Suppress progress output
        let output = std::process::Command::new("mksquashfs")
            .arg(&self.current_rootfs)
            .arg(&squashfs_path)
            .arg("-comp")
            .arg("gzip") // gzip is universally supported by all kernels
            .arg("-noappend")
            .arg("-no-progress")
            .output()
            .map_err(|e| BuildError::InstructionFailed {
                instruction: "mksquashfs".to_string(),
                details: format!(
                    "Failed to run mksquashfs: {}.\n\
                     Make sure squashfs-tools is installed:\n\
                     - Ubuntu/Debian: sudo apt install squashfs-tools\n\
                     - Fedora: sudo dnf install squashfs-tools\n\
                     - Arch: sudo pacman -S squashfs-tools",
                    e
                ),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BuildError::InstructionFailed {
                instruction: "mksquashfs".to_string(),
                details: format!("mksquashfs failed:\n{}", stderr),
            });
        }

        // Align file size to 4KB boundary for macOS Virtualization.framework compatibility.
        // 4KB covers both 512-byte and 4096-byte sector sizes.
        // Linux squashfs ignores trailing data, so this is safe for both platforms.
        const ALIGNMENT: u64 = 4096;
        let metadata = std::fs::metadata(&squashfs_path)?;
        let current_size = metadata.len();
        let remainder = current_size % ALIGNMENT;

        if remainder != 0 {
            let padding_needed = ALIGNMENT - remainder;
            let mut file = OpenOptions::new().append(true).open(&squashfs_path)?;

            let zeros = vec![0u8; padding_needed as usize];
            file.write_all(&zeros)?;

            debug!(
                original_size = current_size,
                padding = padding_needed,
                final_size = current_size + padding_needed,
                "Aligned squashfs image to 4KB boundary"
            );
        }

        let final_size = std::fs::metadata(&squashfs_path)?.len();
        let size_mb = final_size as f64 / (1024.0 * 1024.0);
        info!(
            path = %squashfs_path.display(),
            size_mb = format!("{:.2}", size_mb),
            "SquashFS image generated successfully"
        );

        Ok(squashfs_path)
    }
}

/// Linux VM-based builder using cloud-hypervisor.
///
/// Executes build steps in isolated VMs with cloud-hypervisor,
/// providing the same security guarantees as MacOsVmBuilder.
/// Supports multi-stage builds with intermediate stage caching.
#[cfg(target_os = "linux")]
pub struct LinuxVmBuilder {
    /// VM builder for executing build steps
    vm_builder: crate::builder::VmBuilder,
    /// Working directory for builds
    work_dir: PathBuf,
    /// Current environment variables (accumulated from ENV instructions)
    env: HashMap<String, String>,
    /// Current working directory (from WORKDIR instructions)
    workdir: String,
    /// Image configuration being built
    config: ImageConfig,
    /// OCI registry client for pulling base images
    oci_client: crate::builder::oci::OciClient,
    /// Path to current base image rootfs (shared via virtio-fs)
    base_rootfs: Option<PathBuf>,
    /// Map of stage name/index -> final rootfs path (for multi-stage builds)
    stage_outputs: HashMap<String, PathBuf>,
}

/// macOS VM-based builder using libkrun.
///
/// Executes builds in isolated Linux VMs. Base images are pulled on the host
/// and shared via virtio-fs. The build VM pivots root into the base image.
/// All HTTP traffic is proxied via vsock to the host's BuilderHttpProxy.
/// Supports multi-stage builds with intermediate stage caching.
#[cfg(target_os = "macos")]
pub struct MacOsVmBuilder {
    /// VM builder for executing build steps
    vm_builder: crate::builder::VmBuilder,
    /// Working directory for builds
    work_dir: PathBuf,
    /// Current environment variables (accumulated from ENV instructions)
    env: HashMap<String, String>,
    /// Current working directory (from WORKDIR instructions)
    workdir: String,
    /// Image configuration being built
    config: ImageConfig,
    /// OCI registry client for pulling base images
    oci_client: crate::builder::oci::OciClient,
    /// Path to current base image rootfs (shared via virtio-fs)
    base_rootfs: Option<PathBuf>,
    /// Map of stage name/index -> final rootfs path (for multi-stage builds)
    stage_outputs: HashMap<String, PathBuf>,
}

#[cfg(target_os = "linux")]
impl LinuxVmBuilder {
    /// Create a new Linux VM-based builder using cloud-hypervisor.
    pub fn new() -> BuildResult<Self> {
        use crate::adapters::CloudHypervisorAdapter;

        let cache_dir = crate::paths::cache_dir();
        let work_dir = cache_dir.join(format!("build-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)
            .map_err(|e| BuildError::IoError { path: work_dir.clone(), source: e })?;

        // Locate or download kernel (uses centralized paths with auto-download)
        let kernel_path = crate::paths::ensure_kernel()
            .map_err(|e| BuildError::ContextError(format!("Failed to ensure kernel: {}", e)))?;

        // Placeholder: builder_rootfs will be replaced by on-the-fly initramfs
        let builder_rootfs = crate::paths::runtime_dir().join("builder-initramfs.cpio");

        // Create VMM adapter for Linux (cloud-hypervisor)
        let adapter = CloudHypervisorAdapter::new().map_err(|e| {
            BuildError::ContextError(format!("Failed to create cloud-hypervisor adapter: {}", e))
        })?;

        let vm_builder = crate::builder::VmBuilder::new(
            Box::new(adapter),
            builder_rootfs,
            kernel_path,
            work_dir.clone(),
        );

        let oci_client = crate::builder::oci::OciClient::new()?;

        Ok(Self {
            vm_builder,
            work_dir,
            env: HashMap::new(),
            workdir: "/".to_string(), // Start at root, WORKDIR instruction will change this
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
            oci_client,
            base_rootfs: None,
            stage_outputs: HashMap::new(),
        })
    }

    /// Reset builder state for a new stage (preserves stage_outputs)
    fn reset_for_stage(&mut self) {
        self.env.clear();
        self.workdir = "/".to_string();
        self.config = ImageConfig {
            entrypoint: None,
            cmd: None,
            env: HashMap::new(),
            workdir: None,
            user: None,
            exposed_ports: Vec::new(),
            volumes: Vec::new(),
            labels: HashMap::new(),
        };
        self.base_rootfs = None;
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl BuildExecutor for LinuxVmBuilder {
    async fn execute(
        &mut self,
        _graph: &BuildGraph,
        context: &BuildContext,
        cache: &mut CacheManager,
    ) -> BuildResult<BuildOutput> {
        #[allow(unused_imports)]
        use crate::builder::parser::{BuildStage, ImageRef};

        info!("Starting Linux VM-based build with cloud-hypervisor (multi-stage support)");

        // Get the parsed Dockerfile from the context to access stages
        let dockerfile_content = std::fs::read_to_string(
            context.context_path.join(&context.dockerfile_path),
        )
        .map_err(|e| BuildError::IoError {
            path: context.context_path.join(&context.dockerfile_path),
            source: e,
        })?;

        let dockerfile = crate::builder::parser::parse_dockerfile(&dockerfile_content)
            .map_err(|e| BuildError::ContextError(format!("Failed to parse Dockerfile: {}", e)))?;

        let num_stages = dockerfile.stages.len();
        info!("Dockerfile has {} stage(s)", num_stages);

        // Determine target stage (last stage if not specified)
        let target_stage_idx = if let Some(ref target_name) = context.target {
            dockerfile
                .stages
                .iter()
                .position(|s| s.name.as_deref() == Some(target_name))
                .ok_or_else(|| {
                    BuildError::ContextError(format!("Target stage '{}' not found", target_name))
                })?
        } else {
            num_stages - 1
        };

        // Copy build context once (shared across all stages)
        let context_dir = self.work_dir.join("context");
        std::fs::create_dir_all(&context_dir)?;

        // Check for .dockerignore and build rsync args
        let dockerignore_path = context.context_path.join(".dockerignore");
        let has_dockerignore = dockerignore_path.exists();
        if has_dockerignore {
            info!("Found .dockerignore, excluding matched patterns from build context");
        }

        info!(
            "Copying build context from {} to {}",
            context.context_path.display(),
            context_dir.display()
        );

        let mut rsync_args = vec!["-a".to_string()];
        if has_dockerignore {
            // Use rsync's filter to read .dockerignore patterns
            // :- means "exclude if matching", reading from .dockerignore in source dir
            rsync_args.push("--filter=:- .dockerignore".to_string());
        }
        rsync_args.push(format!("{}/", context.context_path.to_str().unwrap()));
        rsync_args.push(context_dir.to_str().unwrap().to_string());

        let status = std::process::Command::new("rsync")
            .args(&rsync_args)
            .status()
            .map_err(|e| BuildError::IoError { path: context.context_path.clone(), source: e })?;
        if !status.success() {
            return Err(BuildError::InstructionFailed {
                instruction: "Copy build context".to_string(),
                details: "Failed to copy build context files".into(),
            });
        }

        // Process each stage up to and including the target
        for (stage_idx, stage) in dockerfile.stages.iter().enumerate() {
            if stage_idx > target_stage_idx {
                info!("Skipping stage {} (after target)", stage_idx);
                break;
            }

            let stage_name = stage.name.clone().unwrap_or_else(|| format!("stage{}", stage_idx));
            info!("=== Building stage {}: {} ===", stage_idx, stage_name);

            // Reset builder state for this stage (but keep stage_outputs)
            self.reset_for_stage();

            // Execute this stage
            let stage_rootfs = self.execute_stage(stage_idx, stage, &context_dir, cache).await?;

            // Store stage output for potential COPY --from references
            self.stage_outputs.insert(stage_name.clone(), stage_rootfs.clone());
            self.stage_outputs.insert(stage_idx.to_string(), stage_rootfs);

            info!("Stage {} complete", stage_idx);
        }

        // The final stage's rootfs becomes our output
        let target_stage_name = dockerfile.stages[target_stage_idx]
            .name
            .clone()
            .unwrap_or_else(|| format!("stage{}", target_stage_idx));
        let final_rootfs = self
            .stage_outputs
            .get(&target_stage_name)
            .ok_or_else(|| BuildError::ContextError("Final stage rootfs not found".into()))?
            .clone();

        // Create SquashFS from final rootfs
        info!(
            "Creating SquashFS from {} -> {}",
            final_rootfs.display(),
            self.work_dir.join("final.squashfs").display()
        );

        // Log the size of final_rootfs directory before compression
        if let Ok(output) =
            std::process::Command::new("du").args(["-sh", final_rootfs.to_str().unwrap()]).output()
        {
            let du_output = String::from_utf8_lossy(&output.stdout);
            info!("Final rootfs size (before compression): {}", du_output.trim());
        }

        let squashfs_path = self.work_dir.join("final.squashfs");
        let mksquashfs_output = std::process::Command::new("mksquashfs")
            .args([
                final_rootfs.to_str().unwrap(),
                squashfs_path.to_str().unwrap(),
                "-noappend",
                "-comp",
                "gzip",
            ])
            .output()
            .map_err(|e| BuildError::IoError { path: squashfs_path.clone(), source: e })?;

        if !mksquashfs_output.status.success() {
            let stderr = String::from_utf8_lossy(&mksquashfs_output.stderr);
            error!("mksquashfs failed: {}", stderr);
            return Err(BuildError::ContextError(format!("mksquashfs failed: {}", stderr)));
        }

        // Log mksquashfs output
        let stdout = String::from_utf8_lossy(&mksquashfs_output.stdout);
        let stderr = String::from_utf8_lossy(&mksquashfs_output.stderr);
        if !stdout.is_empty() {
            info!("mksquashfs stdout: {}", stdout);
        }
        if !stderr.is_empty() {
            info!("mksquashfs stderr: {}", stderr);
        }

        // Generate manifest
        let manifest = ImageManifest {
            name: "built-image".to_string(),
            tag: "latest".to_string(),
            config: self.config.clone(),
            created: chrono::Utc::now().to_rfc3339(),
            architecture: std::env::consts::ARCH.to_string(),
            os: "linux".to_string(),
        };

        // Compute image ID
        let manifest_json = serde_json::to_string(&manifest).map_err(|e| {
            BuildError::ContextError(format!("Failed to serialize manifest: {}", e))
        })?;
        use sha2::Digest;
        let image_id = format!("{:x}", sha2::Sha256::digest(manifest_json.as_bytes()));

        let total_size = std::fs::metadata(&squashfs_path).map(|m| m.len()).unwrap_or(0);
        info!("Build complete: {} (size: {} bytes)", image_id, total_size);

        Ok(BuildOutput {
            image_id,
            rootfs_path: squashfs_path,
            manifest,
            stats: BuildStats {
                duration_secs: 0.0,
                layer_count: num_stages,
                cached_layers: 0,
                total_size,
            },
        })
    }
}

#[cfg(target_os = "linux")]
impl LinuxVmBuilder {
    /// Execute a single build stage, returning the path to its final rootfs
    async fn execute_stage(
        &mut self,
        stage_idx: usize,
        stage: &crate::builder::parser::BuildStage,
        context_dir: &std::path::Path,
        _cache: &mut CacheManager,
    ) -> BuildResult<PathBuf> {
        use crate::builder::parser::ImageRef;

        // Determine base for this stage
        match &stage.from {
            ImageRef::Scratch => {
                info!("FROM scratch: using minimal rootfs");
                let scratch_dir = self.work_dir.join(format!("rootfs-stage{}-scratch", stage_idx));
                std::fs::create_dir_all(&scratch_dir)?;
                std::fs::create_dir_all(scratch_dir.join("tmp"))?;
                std::fs::create_dir_all(scratch_dir.join("etc"))?;
                std::fs::create_dir_all(scratch_dir.join("proc"))?;
                std::fs::create_dir_all(scratch_dir.join("sys"))?;
                std::fs::create_dir_all(scratch_dir.join("dev"))?;
                self.base_rootfs = Some(scratch_dir);
            }
            ImageRef::Stage(stage_name) => {
                // Multi-stage: use output from a previous stage
                let source_rootfs = self.stage_outputs.get(stage_name).ok_or_else(|| {
                    BuildError::InstructionFailed {
                        instruction: "FROM".to_string(),
                        details: format!(
                            "Stage '{}' not found. Available: {:?}",
                            stage_name,
                            self.stage_outputs.keys().collect::<Vec<_>>()
                        ),
                    }
                })?;
                info!(
                    "FROM {}: using previous stage rootfs at {}",
                    stage_name,
                    source_rootfs.display()
                );

                // Copy the stage rootfs as our base
                let base_dir = self.work_dir.join(format!("rootfs-stage{}-base", stage_idx));
                std::fs::create_dir_all(&base_dir)?;
                let status = std::process::Command::new("rsync")
                    .args([
                        "-a",
                        &format!("{}/", source_rootfs.to_str().unwrap()),
                        base_dir.to_str().unwrap(),
                    ])
                    .status()
                    .map_err(|e| BuildError::IoError { path: source_rootfs.clone(), source: e })?;
                if !status.success() {
                    return Err(BuildError::InstructionFailed {
                        instruction: "FROM".to_string(),
                        details: format!("Failed to copy stage '{}' rootfs", stage_name),
                    });
                }
                self.base_rootfs = Some(base_dir);
            }
            ImageRef::Image { name, tag, digest } => {
                let image_str = if let Some(digest) = digest {
                    format!("{}@{}", name, digest)
                } else {
                    format!("{}:{}", name, tag.as_deref().unwrap_or("latest"))
                };
                info!("FROM {}: pulling base image", image_str);

                let base_dir = self.work_dir.join(format!("rootfs-stage{}-base", stage_idx));
                std::fs::create_dir_all(&base_dir)?;
                self.oci_client.pull_image(&image_str, &base_dir).await?;
                info!("Base image extracted to {}", base_dir.display());
                self.base_rootfs = Some(base_dir);
            }
        }

        // Collect build steps for this stage
        let mut build_steps = Vec::new();
        for (instr_idx, instruction) in stage.instructions.iter().enumerate() {
            let _ = instr_idx; // Suppress unused warning
            match instruction {
                Instruction::Run { command } => {
                    let cmd_str = match command {
                        crate::builder::parser::RunCommand::Shell(c) => c.clone(),
                        crate::builder::parser::RunCommand::Exec(args) => args.join(" "),
                    };
                    build_steps.push(crate::builder::BuildStep::Run {
                        command: cmd_str,
                        workdir: self.workdir.clone(),
                    });
                }
                Instruction::Copy { sources, destination, from_stage, .. } => {
                    let dest_path = self.normalize_path(destination);

                    if let Some(stage_name) = from_stage {
                        // COPY --from=stage: copy from another stage's rootfs
                        let source_rootfs =
                            self.stage_outputs.get(stage_name).ok_or_else(|| {
                                BuildError::InstructionFailed {
                                    instruction: "COPY --from".to_string(),
                                    details: format!("Stage '{}' not found", stage_name),
                                }
                            })?;

                        // Copy files on the host side before VM execution
                        for source in sources {
                            let src_path = source_rootfs.join(source.trim_start_matches('/'));
                            if src_path.exists() {
                                let base_rootfs = self.base_rootfs.as_ref().unwrap();
                                let dest_full = base_rootfs.join(dest_path.trim_start_matches('/'));

                                // Create parent directory, not dest itself
                                if let Some(parent) = dest_full.parent() {
                                    std::fs::create_dir_all(parent)?;
                                }

                                if src_path.is_dir() {
                                    // Use rsync to properly copy directory contents
                                    let status = std::process::Command::new("rsync")
                                        .args([
                                            "-a",
                                            &format!("{}/", src_path.to_str().unwrap()),
                                            &format!("{}/", dest_full.to_str().unwrap()),
                                        ])
                                        .status()
                                        .map_err(|e| BuildError::IoError {
                                            path: src_path.clone(),
                                            source: e,
                                        })?;
                                    if !status.success() {
                                        return Err(BuildError::InstructionFailed {
                                            instruction: "COPY --from".to_string(),
                                            details: format!(
                                                "Failed to copy {} from stage {}",
                                                source, stage_name
                                            ),
                                        });
                                    }
                                } else {
                                    // For files, if dest_path looks like a directory, copy to dest_full/filename
                                    let final_dest =
                                        if dest_full.is_dir() || dest_path.ends_with('/') {
                                            std::fs::create_dir_all(&dest_full)?;
                                            dest_full.join(src_path.file_name().unwrap())
                                        } else {
                                            dest_full.clone()
                                        };
                                    std::fs::copy(&src_path, &final_dest)?;
                                }
                                info!("COPY --from={}: {} -> {}", stage_name, source, dest_path);
                            } else {
                                return Err(BuildError::InstructionFailed {
                                    instruction: "COPY --from".to_string(),
                                    details: format!(
                                        "Source '{}' not found in stage '{}' (looked in {})",
                                        source,
                                        stage_name,
                                        src_path.display()
                                    ),
                                });
                            }
                        }
                    } else {
                        // Regular COPY from build context
                        // Build a robust copy command that checks file existence and reports errors
                        let source_list = sources.join(" ");
                        let copy_cmd = format!(
                            "mkdir -p {} && cd /context && for src in {}; do if [ -e \"$src\" ]; then cp -r \"$src\" {}/; else echo \"COPY ERROR: $src not found in /context\" >&2; exit 1; fi; done",
                            dest_path, source_list, dest_path
                        );
                        build_steps.push(crate::builder::BuildStep::Run {
                            command: copy_cmd,
                            workdir: self.workdir.clone(),
                        });
                    }
                }
                Instruction::Workdir { path } => {
                    self.workdir = path.clone();
                    self.config.workdir = Some(path.clone());
                    // Create workdir in base rootfs
                    if let Some(ref base) = self.base_rootfs {
                        std::fs::create_dir_all(base.join(path.trim_start_matches('/')))?;
                    }
                }
                Instruction::Env { vars } => {
                    for (k, v) in vars {
                        self.env.insert(k.clone(), v.clone());
                        self.config.env.insert(k.clone(), v.clone());
                    }
                }
                Instruction::Cmd { command } => {
                    let cmd_vec = match command {
                        crate::builder::parser::RunCommand::Shell(c) => {
                            vec!["/bin/sh".to_string(), "-c".to_string(), c.clone()]
                        }
                        crate::builder::parser::RunCommand::Exec(args) => args.clone(),
                    };
                    self.config.cmd = Some(cmd_vec);
                }
                Instruction::Entrypoint { command } => {
                    let entry_vec = match command {
                        crate::builder::parser::RunCommand::Shell(c) => {
                            vec!["/bin/sh".to_string(), "-c".to_string(), c.clone()]
                        }
                        crate::builder::parser::RunCommand::Exec(args) => args.clone(),
                    };
                    self.config.entrypoint = Some(entry_vec);
                }
                Instruction::Expose { ports } => {
                    for port_spec in ports {
                        let port_str = format!("{}", port_spec.port);
                        if !self.config.exposed_ports.contains(&port_str) {
                            self.config.exposed_ports.push(port_str);
                        }
                    }
                }
                Instruction::User { user } => {
                    self.config.user = Some(user.clone());
                }
                Instruction::Label { labels } => {
                    self.config.labels.extend(labels.clone());
                }
                Instruction::Volume { paths } => {
                    self.config.volumes.extend(paths.clone());
                }
                _ => {} // Skip other instructions (ARG, etc.)
            }
        }

        // Execute build steps in VM if any
        let stage_rootfs = self.work_dir.join(format!("rootfs-stage{}", stage_idx));
        std::fs::create_dir_all(&stage_rootfs)?;

        // Start with base rootfs
        if let Some(base_path) = &self.base_rootfs {
            let status = std::process::Command::new("rsync")
                .args([
                    "-a",
                    &format!("{}/", base_path.to_str().unwrap()),
                    stage_rootfs.to_str().unwrap(),
                ])
                .status()
                .map_err(|e| BuildError::IoError { path: base_path.clone(), source: e })?;
            if !status.success() {
                return Err(BuildError::InstructionFailed {
                    instruction: "Copy base rootfs".to_string(),
                    details: "Failed to copy base image files".into(),
                });
            }
        }

        // Log what we collected for this stage
        info!("Stage {} collected {} build steps (RUN/COPY)", stage_idx, build_steps.len());
        for (i, step) in build_steps.iter().enumerate() {
            match step {
                crate::builder::BuildStep::Run { command, workdir } => {
                    let preview = if command.len() > 60 { &command[..60] } else { command };
                    info!("  Step {}: RUN {} (workdir: {})", i + 1, preview, workdir);
                }
                crate::builder::BuildStep::Finalize { layer_id } => {
                    info!("  Step {}: FINALIZE {}", i + 1, layer_id);
                }
            }
        }

        if !build_steps.is_empty() {
            info!("Executing {} build steps for stage {} in VM...", build_steps.len(), stage_idx);
            let output_dir = self.work_dir.join(format!("layers-stage{}", stage_idx));
            std::fs::create_dir_all(&output_dir)?;

            let _layer_infos = self
                .vm_builder
                .execute_all_steps(
                    build_steps,
                    context_dir,
                    &output_dir,
                    self.base_rootfs.as_deref(),
                )
                .await
                .map_err(|e| BuildError::InstructionFailed {
                    instruction: "VM build execution".to_string(),
                    details: e.to_string(),
                })?;

            // Extract layer tarballs into stage rootfs
            for entry in std::fs::read_dir(&output_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("tar") {
                    debug!("Extracting layer: {}", path.display());
                    let status = std::process::Command::new("tar")
                        .args(["-xf", path.to_str().unwrap(), "-C", stage_rootfs.to_str().unwrap()])
                        .status()
                        .map_err(|e| BuildError::IoError { path: path.clone(), source: e })?;
                    if !status.success() {
                        return Err(BuildError::LayerExtractionFailed {
                            path,
                            reason: "tar extraction failed".into(),
                        });
                    }
                }
            }
        }

        Ok(stage_rootfs)
    }

    /// Normalize a destination path relative to current workdir
    fn normalize_path(&self, destination: &str) -> String {
        if destination.starts_with('/') {
            destination.to_string()
        } else if destination == "." || destination == "./" {
            self.workdir.clone()
        } else {
            let clean_dest = destination.strip_prefix("./").unwrap_or(destination);
            format!("{}/{}", self.workdir.trim_end_matches('/'), clean_dest)
        }
    }
}

#[cfg(target_os = "macos")]
impl MacOsVmBuilder {
    /// Create a new macOS VM-based builder.
    pub fn new() -> BuildResult<Self> {
        use crate::adapters::LibkrunAdapter;

        let cache_dir = crate::paths::cache_dir();
        let work_dir = cache_dir.join(format!("build-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)
            .map_err(|e| BuildError::IoError { path: work_dir.clone(), source: e })?;

        // Locate or download kernel (uses centralized paths with auto-download)
        let kernel_path = crate::paths::ensure_kernel()
            .map_err(|e| BuildError::ContextError(format!("Failed to ensure kernel: {}", e)))?;

        // Placeholder: builder_rootfs will be replaced by on-the-fly initramfs
        let builder_rootfs = crate::paths::runtime_dir().join("builder-initramfs.cpio");

        // Create VMM adapter for macOS (libkrun)
        let adapter = LibkrunAdapter::new().map_err(|e| {
            BuildError::ContextError(format!("Failed to create libkrun adapter: {}", e))
        })?;

        let vm_builder = crate::builder::VmBuilder::new(
            Box::new(adapter),
            builder_rootfs,
            kernel_path,
            work_dir.clone(),
        );

        let oci_client = crate::builder::oci::OciClient::new()?;

        Ok(Self {
            vm_builder,
            work_dir,
            env: HashMap::new(),
            workdir: "/".to_string(), // Start at root, WORKDIR instruction will change this
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
            oci_client,
            base_rootfs: None,
            stage_outputs: HashMap::new(),
        })
    }

    /// Reset builder state for a new stage (preserves stage_outputs)
    fn reset_for_stage(&mut self) {
        self.env.clear();
        self.workdir = "/".to_string();
        self.config = ImageConfig {
            entrypoint: None,
            cmd: None,
            env: HashMap::new(),
            workdir: None,
            user: None,
            exposed_ports: Vec::new(),
            volumes: Vec::new(),
            labels: HashMap::new(),
        };
        self.base_rootfs = None;
    }
}

#[cfg(target_os = "macos")]
#[async_trait]
impl BuildExecutor for MacOsVmBuilder {
    async fn execute(
        &mut self,
        _graph: &BuildGraph,
        context: &BuildContext,
        cache: &mut CacheManager,
    ) -> BuildResult<BuildOutput> {
        info!("Starting macOS VM-based build with HVF (multi-stage support)");

        // Get the parsed Dockerfile from the context to access stages
        let dockerfile_content = std::fs::read_to_string(
            context.context_path.join(&context.dockerfile_path),
        )
        .map_err(|e| BuildError::IoError {
            path: context.context_path.join(&context.dockerfile_path),
            source: e,
        })?;

        let dockerfile = crate::builder::parser::parse_dockerfile(&dockerfile_content)
            .map_err(|e| BuildError::ContextError(format!("Failed to parse Dockerfile: {}", e)))?;

        let num_stages = dockerfile.stages.len();
        info!("Dockerfile has {} stage(s)", num_stages);

        // Determine target stage (last stage if not specified)
        let target_stage_idx = if let Some(ref target_name) = context.target {
            dockerfile
                .stages
                .iter()
                .position(|s| s.name.as_deref() == Some(target_name))
                .ok_or_else(|| {
                    BuildError::ContextError(format!("Target stage '{}' not found", target_name))
                })?
        } else {
            num_stages - 1
        };

        // Copy build context once (shared across all stages)
        let context_dir = self.work_dir.join("context");
        std::fs::create_dir_all(&context_dir)?;

        // Check for .dockerignore and build rsync args
        let dockerignore_path = context.context_path.join(".dockerignore");
        let has_dockerignore = dockerignore_path.exists();
        if has_dockerignore {
            info!("Found .dockerignore, excluding matched patterns from build context");
        }

        info!(
            "Copying build context from {} to {}",
            context.context_path.display(),
            context_dir.display()
        );

        let mut rsync_args = vec!["-a".to_string()];
        if has_dockerignore {
            // Use rsync's filter to read .dockerignore patterns
            // :- means "exclude if matching", reading from .dockerignore in source dir
            rsync_args.push("--filter=:- .dockerignore".to_string());
        }
        rsync_args.push(format!("{}/", context.context_path.to_str().unwrap()));
        rsync_args.push(context_dir.to_str().unwrap().to_string());

        let status = std::process::Command::new("rsync")
            .args(&rsync_args)
            .status()
            .map_err(|e| BuildError::IoError { path: context.context_path.clone(), source: e })?;
        if !status.success() {
            return Err(BuildError::InstructionFailed {
                instruction: "Copy build context".to_string(),
                details: "Failed to copy build context files".into(),
            });
        }

        // Process each stage up to and including the target
        for (stage_idx, stage) in dockerfile.stages.iter().enumerate() {
            if stage_idx > target_stage_idx {
                info!("Skipping stage {} (after target)", stage_idx);
                break;
            }

            let stage_name = stage.name.clone().unwrap_or_else(|| format!("stage{}", stage_idx));
            info!("=== Building stage {}: {} ===", stage_idx, stage_name);

            // Reset builder state for this stage (but keep stage_outputs)
            self.reset_for_stage();

            // Execute this stage
            let stage_rootfs = self.execute_stage(stage_idx, stage, &context_dir, cache).await?;

            // Store stage output for potential COPY --from references
            self.stage_outputs.insert(stage_name.clone(), stage_rootfs.clone());
            self.stage_outputs.insert(stage_idx.to_string(), stage_rootfs);

            info!("Stage {} complete", stage_idx);
        }

        // The final stage's rootfs becomes our output
        let target_stage_name = dockerfile.stages[target_stage_idx]
            .name
            .clone()
            .unwrap_or_else(|| format!("stage{}", target_stage_idx));
        let final_rootfs = self
            .stage_outputs
            .get(&target_stage_name)
            .ok_or_else(|| BuildError::ContextError("Final stage rootfs not found".into()))?
            .clone();

        // Create SquashFS from final rootfs
        info!(
            "Creating SquashFS from {} -> {}",
            final_rootfs.display(),
            self.work_dir.join("final.squashfs").display()
        );

        // Log the size of final_rootfs directory before compression
        if let Ok(output) =
            std::process::Command::new("du").args(["-sh", final_rootfs.to_str().unwrap()]).output()
        {
            let du_output = String::from_utf8_lossy(&output.stdout);
            info!("Final rootfs size (before compression): {}", du_output.trim());
        }

        let squashfs_path = self.work_dir.join("final.squashfs");
        let mksquashfs_output = std::process::Command::new("mksquashfs")
            .args([
                final_rootfs.to_str().unwrap(),
                squashfs_path.to_str().unwrap(),
                "-noappend",
                "-comp",
                "gzip",
            ])
            .output()
            .map_err(|e| BuildError::IoError { path: squashfs_path.clone(), source: e })?;

        if !mksquashfs_output.status.success() {
            let stderr = String::from_utf8_lossy(&mksquashfs_output.stderr);
            error!("mksquashfs failed: {}", stderr);
            return Err(BuildError::ContextError(format!("mksquashfs failed: {}", stderr)));
        }

        // Log mksquashfs output
        let stdout = String::from_utf8_lossy(&mksquashfs_output.stdout);
        let stderr = String::from_utf8_lossy(&mksquashfs_output.stderr);
        if !stdout.is_empty() {
            info!("mksquashfs stdout: {}", stdout);
        }
        if !stderr.is_empty() {
            info!("mksquashfs stderr: {}", stderr);
        }

        // Generate manifest
        let manifest = ImageManifest {
            name: "built-image".to_string(),
            tag: "latest".to_string(),
            config: self.config.clone(),
            created: chrono::Utc::now().to_rfc3339(),
            architecture: std::env::consts::ARCH.to_string(),
            os: "linux".to_string(),
        };

        // Compute image ID
        let manifest_json = serde_json::to_string(&manifest).map_err(|e| {
            BuildError::ContextError(format!("Failed to serialize manifest: {}", e))
        })?;
        use sha2::Digest;
        let image_id = format!("{:x}", sha2::Sha256::digest(manifest_json.as_bytes()));

        let total_size = match std::fs::metadata(&squashfs_path) {
            Ok(m) => {
                let size = m.len();
                info!(
                    "Squashfs file {} size: {} bytes ({:.2} MB)",
                    squashfs_path.display(),
                    size,
                    size as f64 / 1024.0 / 1024.0
                );
                size
            }
            Err(e) => {
                error!("Failed to read squashfs metadata at {}: {}", squashfs_path.display(), e);
                0
            }
        };
        info!("Build complete: {} (size: {} bytes)", image_id, total_size);

        Ok(BuildOutput {
            image_id,
            rootfs_path: squashfs_path,
            manifest,
            stats: BuildStats {
                duration_secs: 0.0,
                layer_count: num_stages,
                cached_layers: 0,
                total_size,
            },
        })
    }
}

#[cfg(target_os = "macos")]
impl MacOsVmBuilder {
    /// Execute a single build stage, returning the path to its final rootfs
    async fn execute_stage(
        &mut self,
        stage_idx: usize,
        stage: &crate::builder::parser::BuildStage,
        context_dir: &std::path::Path,
        _cache: &mut CacheManager,
    ) -> BuildResult<PathBuf> {
        use crate::builder::parser::ImageRef;

        // Determine base for this stage
        match &stage.from {
            ImageRef::Scratch => {
                info!("FROM scratch: using minimal rootfs");
                let scratch_dir = self.work_dir.join(format!("rootfs-stage{}-scratch", stage_idx));
                std::fs::create_dir_all(&scratch_dir)?;
                std::fs::create_dir_all(scratch_dir.join("tmp"))?;
                std::fs::create_dir_all(scratch_dir.join("etc"))?;
                std::fs::create_dir_all(scratch_dir.join("proc"))?;
                std::fs::create_dir_all(scratch_dir.join("sys"))?;
                std::fs::create_dir_all(scratch_dir.join("dev"))?;
                self.base_rootfs = Some(scratch_dir);
            }
            ImageRef::Stage(stage_name) => {
                // Multi-stage: use output from a previous stage
                let source_rootfs = self.stage_outputs.get(stage_name).ok_or_else(|| {
                    BuildError::InstructionFailed {
                        instruction: "FROM".to_string(),
                        details: format!(
                            "Stage '{}' not found. Available: {:?}",
                            stage_name,
                            self.stage_outputs.keys().collect::<Vec<_>>()
                        ),
                    }
                })?;
                info!(
                    "FROM {}: using previous stage rootfs at {}",
                    stage_name,
                    source_rootfs.display()
                );

                // Copy the stage rootfs as our base
                let base_dir = self.work_dir.join(format!("rootfs-stage{}-base", stage_idx));
                std::fs::create_dir_all(&base_dir)?;
                let status = std::process::Command::new("rsync")
                    .args([
                        "-a",
                        &format!("{}/", source_rootfs.to_str().unwrap()),
                        base_dir.to_str().unwrap(),
                    ])
                    .status()
                    .map_err(|e| BuildError::IoError { path: source_rootfs.clone(), source: e })?;
                if !status.success() {
                    return Err(BuildError::InstructionFailed {
                        instruction: "FROM".to_string(),
                        details: format!("Failed to copy stage '{}' rootfs", stage_name),
                    });
                }
                self.base_rootfs = Some(base_dir);
            }
            ImageRef::Image { name, tag, digest } => {
                let image_str = if let Some(digest) = digest {
                    format!("{}@{}", name, digest)
                } else {
                    format!("{}:{}", name, tag.as_deref().unwrap_or("latest"))
                };
                info!("FROM {}: pulling base image", image_str);

                let base_dir = self.work_dir.join(format!("rootfs-stage{}-base", stage_idx));
                std::fs::create_dir_all(&base_dir)?;
                self.oci_client.pull_image(&image_str, &base_dir).await?;
                info!("Base image extracted to {}", base_dir.display());
                self.base_rootfs = Some(base_dir);
            }
        }

        // Collect build steps for this stage
        let mut build_steps = Vec::new();
        for (instr_idx, instruction) in stage.instructions.iter().enumerate() {
            let _ = instr_idx; // Suppress unused warning
            match instruction {
                Instruction::Run { command } => {
                    let cmd_str = match command {
                        crate::builder::parser::RunCommand::Shell(c) => c.clone(),
                        crate::builder::parser::RunCommand::Exec(args) => args.join(" "),
                    };
                    build_steps.push(crate::builder::BuildStep::Run {
                        command: cmd_str,
                        workdir: self.workdir.clone(),
                    });
                }
                Instruction::Copy { sources, destination, from_stage, .. } => {
                    let dest_path = self.normalize_path(destination);

                    if let Some(stage_name) = from_stage {
                        // COPY --from=stage: copy from another stage's rootfs
                        let source_rootfs =
                            self.stage_outputs.get(stage_name).ok_or_else(|| {
                                BuildError::InstructionFailed {
                                    instruction: "COPY --from".to_string(),
                                    details: format!("Stage '{}' not found", stage_name),
                                }
                            })?;

                        // Copy files on the host side before VM execution
                        for source in sources {
                            let src_path = source_rootfs.join(source.trim_start_matches('/'));
                            if src_path.exists() {
                                let base_rootfs = self.base_rootfs.as_ref().unwrap();
                                let dest_full = base_rootfs.join(dest_path.trim_start_matches('/'));

                                // Create parent directory, not dest itself
                                if let Some(parent) = dest_full.parent() {
                                    std::fs::create_dir_all(parent)?;
                                }

                                if src_path.is_dir() {
                                    // Use rsync to properly copy directory contents
                                    // rsync -a src/ dest/ copies contents of src INTO dest
                                    let status = std::process::Command::new("rsync")
                                        .args([
                                            "-a",
                                            &format!("{}/", src_path.to_str().unwrap()),
                                            &format!("{}/", dest_full.to_str().unwrap()),
                                        ])
                                        .status()
                                        .map_err(|e| BuildError::IoError {
                                            path: src_path.clone(),
                                            source: e,
                                        })?;
                                    if !status.success() {
                                        return Err(BuildError::InstructionFailed {
                                            instruction: "COPY --from".to_string(),
                                            details: format!(
                                                "Failed to copy {} from stage {}",
                                                source, stage_name
                                            ),
                                        });
                                    }
                                } else {
                                    // For files, if dest_path looks like a directory (ends with / or dest_full is a dir),
                                    // copy to dest_full/filename, otherwise copy directly to dest_full
                                    let final_dest =
                                        if dest_full.is_dir() || dest_path.ends_with('/') {
                                            std::fs::create_dir_all(&dest_full)?;
                                            dest_full.join(src_path.file_name().unwrap())
                                        } else {
                                            dest_full.clone()
                                        };
                                    std::fs::copy(&src_path, &final_dest)?;
                                }
                                info!("COPY --from={}: {} -> {}", stage_name, source, dest_path);
                            } else {
                                return Err(BuildError::InstructionFailed {
                                    instruction: "COPY --from".to_string(),
                                    details: format!(
                                        "Source '{}' not found in stage '{}' (looked in {})",
                                        source,
                                        stage_name,
                                        src_path.display()
                                    ),
                                });
                            }
                        }
                    } else {
                        // Regular COPY from build context
                        // Build a robust copy command that checks file existence and reports errors
                        let source_list = sources.join(" ");
                        let copy_cmd = format!(
                            "mkdir -p {} && cd /context && for src in {}; do if [ -e \"$src\" ]; then cp -r \"$src\" {}/; else echo \"COPY ERROR: $src not found in /context\" >&2; exit 1; fi; done",
                            dest_path, source_list, dest_path
                        );
                        build_steps.push(crate::builder::BuildStep::Run {
                            command: copy_cmd,
                            workdir: self.workdir.clone(),
                        });
                    }
                }
                Instruction::Workdir { path } => {
                    self.workdir = path.clone();
                    self.config.workdir = Some(path.clone());
                    if let Some(ref base) = self.base_rootfs {
                        std::fs::create_dir_all(base.join(path.trim_start_matches('/')))?;
                    }
                }
                Instruction::Env { vars } => {
                    for (k, v) in vars {
                        self.env.insert(k.clone(), v.clone());
                        self.config.env.insert(k.clone(), v.clone());
                    }
                }
                Instruction::Cmd { command } => {
                    let cmd_vec = match command {
                        crate::builder::parser::RunCommand::Shell(c) => {
                            vec!["/bin/sh".to_string(), "-c".to_string(), c.clone()]
                        }
                        crate::builder::parser::RunCommand::Exec(args) => args.clone(),
                    };
                    self.config.cmd = Some(cmd_vec);
                }
                Instruction::Entrypoint { command } => {
                    let entry_vec = match command {
                        crate::builder::parser::RunCommand::Shell(c) => {
                            vec!["/bin/sh".to_string(), "-c".to_string(), c.clone()]
                        }
                        crate::builder::parser::RunCommand::Exec(args) => args.clone(),
                    };
                    self.config.entrypoint = Some(entry_vec);
                }
                Instruction::Expose { ports } => {
                    for port_spec in ports {
                        let port_str = format!("{}", port_spec.port);
                        if !self.config.exposed_ports.contains(&port_str) {
                            self.config.exposed_ports.push(port_str);
                        }
                    }
                }
                Instruction::User { user } => {
                    self.config.user = Some(user.clone());
                }
                Instruction::Label { labels } => {
                    self.config.labels.extend(labels.clone());
                }
                Instruction::Volume { paths } => {
                    self.config.volumes.extend(paths.clone());
                }
                _ => {} // Skip other instructions
            }
        }

        // Execute build steps in VM if any
        let stage_rootfs = self.work_dir.join(format!("rootfs-stage{}", stage_idx));
        std::fs::create_dir_all(&stage_rootfs)?;

        // Start with base rootfs
        if let Some(base_path) = &self.base_rootfs {
            let status = std::process::Command::new("rsync")
                .args([
                    "-a",
                    &format!("{}/", base_path.to_str().unwrap()),
                    stage_rootfs.to_str().unwrap(),
                ])
                .status()
                .map_err(|e| BuildError::IoError { path: base_path.clone(), source: e })?;
            if !status.success() {
                return Err(BuildError::InstructionFailed {
                    instruction: "Copy base rootfs".to_string(),
                    details: "Failed to copy base image files".into(),
                });
            }
        }

        // Log what we collected for this stage
        info!("Stage {} collected {} build steps (RUN/COPY)", stage_idx, build_steps.len());
        for (i, step) in build_steps.iter().enumerate() {
            match step {
                crate::builder::BuildStep::Run { command, workdir } => {
                    let preview = if command.len() > 60 { &command[..60] } else { command };
                    info!("  Step {}: RUN {} (workdir: {})", i + 1, preview, workdir);
                }
                crate::builder::BuildStep::Finalize { layer_id } => {
                    info!("  Step {}: FINALIZE {}", i + 1, layer_id);
                }
            }
        }

        if !build_steps.is_empty() {
            info!("Executing {} build steps for stage {} in VM...", build_steps.len(), stage_idx);
            let output_dir = self.work_dir.join(format!("layers-stage{}", stage_idx));
            std::fs::create_dir_all(&output_dir)?;

            let _layer_infos = self
                .vm_builder
                .execute_all_steps(
                    build_steps,
                    context_dir,
                    &output_dir,
                    self.base_rootfs.as_deref(),
                )
                .await
                .map_err(|e| BuildError::InstructionFailed {
                    instruction: "VM build execution".to_string(),
                    details: e.to_string(),
                })?;

            // Extract layer tarballs into stage rootfs
            for entry in std::fs::read_dir(&output_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("tar") {
                    debug!("Extracting layer: {}", path.display());
                    let status = std::process::Command::new("tar")
                        .args(["-xf", path.to_str().unwrap(), "-C", stage_rootfs.to_str().unwrap()])
                        .status()
                        .map_err(|e| BuildError::IoError { path: path.clone(), source: e })?;
                    if !status.success() {
                        return Err(BuildError::LayerExtractionFailed {
                            path,
                            reason: "tar extraction failed".into(),
                        });
                    }
                }
            }
        }

        Ok(stage_rootfs)
    }

    /// Normalize a destination path relative to current workdir
    fn normalize_path(&self, destination: &str) -> String {
        if destination.starts_with('/') {
            destination.to_string()
        } else if destination == "." || destination == "./" {
            self.workdir.clone()
        } else {
            let clean_dest = destination.strip_prefix("./").unwrap_or(destination);
            format!("{}/{}", self.workdir.trim_end_matches('/'), clean_dest)
        }
    }
}

/// Creates a platform-specific build executor.
pub fn create_builder() -> BuildResult<Box<dyn BuildExecutor>> {
    #[cfg(target_os = "linux")]
    {
        info!("Creating Linux VM-based builder (cloud-hypervisor + Alpine)");
        Ok(Box::new(LinuxVmBuilder::new()?))
    }

    #[cfg(target_os = "macos")]
    {
        info!("Creating macOS VM-based builder (HVF + Alpine)");
        Ok(Box::new(MacOsVmBuilder::new()?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(BuildError::PlatformNotSupported(format!(
            "Builds not supported on {}. Supported: Linux, macOS",
            std::env::consts::OS
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_native_builder_creation() {
        // Use temp dir to avoid /var/lib/hypr permission issues in CI
        let temp_dir = std::env::temp_dir().join(format!("hypr-test-{}", std::process::id()));
        std::env::set_var("HYPR_DATA_DIR", &temp_dir);

        let builder = NativeBuilder::new();

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);

        // May still fail in CI for various I/O reasons
        match builder {
            Ok(_) => {}
            Err(BuildError::Io(_)) => {
                println!("Skipping: I/O error in CI environment");
            }
            Err(BuildError::ContextError(msg)) if msg.contains("I/O error") => {
                println!("Skipping: I/O error in CI environment");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
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
