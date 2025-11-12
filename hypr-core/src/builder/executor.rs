//! Build executor for HYPR images.
//!
//! Executes build instructions and produces image layers.
//! Platform-specific implementations:
//! - Linux: Native builder with chroot isolation
//! - macOS: VM-based builder with HVF/vfkit

use crate::builder::cache::CacheManager;
use crate::builder::graph::BuildGraph;
use crate::builder::graph::BuildNode;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, info};

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

    #[error("Manifest error: {0}")]
    Manifest(#[from] crate::builder::manifest::ManifestError),

    #[error("Image pull failed: {image}\n{reason}")]
    ImagePullFailed { image: String, reason: String },

    #[error("Invalid image reference: {image}\n{reason}")]
    InvalidImageRef { image: String, reason: String },

    #[error("Layer extraction failed: {path}\n{reason}")]
    LayerExtractionFailed { path: PathBuf, reason: String },

    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Mount failed: {target}\n{reason}")]
    MountFailed { target: PathBuf, reason: String },

    #[error("Command execution failed: {command}\nExit code: {exit_code}\n{stderr}")]
    CommandFailed {
        command: String,
        exit_code: i32,
        stderr: String,
    },
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
        let temp = std::env::temp_dir();
        let work_dir = temp.join(format!("hypr-build-{}", uuid::Uuid::new_v4()));
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
        std::fs::create_dir_all(&upper_dir).map_err(|e| BuildError::IoError {
            path: upper_dir.clone(),
            source: e,
        })?;
        std::fs::create_dir_all(&work_dir).map_err(|e| BuildError::IoError {
            path: work_dir.clone(),
            source: e,
        })?;
        std::fs::create_dir_all(&merged_dir).map_err(|e| BuildError::IoError {
            path: merged_dir.clone(),
            source: e,
        })?;

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
        use nix::mount::{umount, MntFlags};
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

        std::fs::create_dir_all(&proc_dir).map_err(|e| BuildError::IoError {
            path: proc_dir.clone(),
            source: e,
        })?;
        std::fs::create_dir_all(&sys_dir).map_err(|e| BuildError::IoError {
            path: sys_dir.clone(),
            source: e,
        })?;
        std::fs::create_dir_all(&dev_dir).map_err(|e| BuildError::IoError {
            path: dev_dir.clone(),
            source: e,
        })?;

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
        std::fs::create_dir_all(&workdir_in_rootfs).map_err(|e| BuildError::IoError {
            path: workdir_in_rootfs.clone(),
            source: e,
        })?;

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
        use std::os::unix::fs::PermissionsExt;

        debug!("copy_dir_all: Creating dest directory: {}", dst.display());
        std::fs::create_dir_all(dst).map_err(|e| BuildError::IoError {
            path: dst.clone(),
            source: e,
        })?;

        debug!("copy_dir_all: Reading source directory: {}", src.display());
        for entry in std::fs::read_dir(src).map_err(|e| BuildError::IoError {
            path: src.clone(),
            source: e,
        })? {
            let entry = entry.map_err(|e| BuildError::IoError {
                path: src.clone(),
                source: e,
            })?;

            let src_path = entry.path();
            debug!("copy_dir_all: Processing entry: {}", src_path.display());

            let ty = entry.file_type().map_err(|e| BuildError::IoError {
                path: src_path.clone(),
                source: e,
            })?;

            let dst_path = dst.join(entry.file_name());

            // Skip special directories (pseudo-filesystems that shouldn't be copied)
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            if file_name_str == "proc" || file_name_str == "sys" || file_name_str == "dev" {
                // Create empty directory instead of copying
                debug!("copy_dir_all: Skipping pseudo-filesystem: {}", file_name_str);
                std::fs::create_dir_all(&dst_path).map_err(|e| BuildError::IoError {
                    path: dst_path.clone(),
                    source: e,
                })?;
                continue;
            }

            if ty.is_symlink() {
                // Preserve symlinks
                debug!("copy_dir_all: Copying symlink: {} -> {}", src_path.display(), dst_path.display());
                let link_target = std::fs::read_link(&src_path).map_err(|e| BuildError::IoError {
                    path: src_path.clone(),
                    source: e,
                })?;
                // Remove destination if it exists (file or directory)
                if dst_path.exists() {
                    if dst_path.is_dir() {
                        let _ = std::fs::remove_dir_all(&dst_path);
                    } else {
                        let _ = std::fs::remove_file(&dst_path);
                    }
                }
                std::os::unix::fs::symlink(&link_target, &dst_path).map_err(|e| {
                    BuildError::IoError {
                        path: dst_path.clone(),
                        source: e,
                    }
                })?;
            } else if ty.is_dir() {
                debug!("copy_dir_all: Recursing into directory: {}", src_path.display());
                Self::copy_dir_all(&src_path, &dst_path)?;
            } else {
                // Copy file
                debug!("copy_dir_all: Copying file: {} -> {}", src_path.display(), dst_path.display());
                std::fs::copy(&src_path, &dst_path).map_err(|e| BuildError::IoError {
                    path: src_path.clone(),
                    source: e,
                })?;
                // Preserve permissions
                let metadata = std::fs::metadata(&src_path).map_err(|e| BuildError::IoError {
                    path: src_path.clone(),
                    source: e,
                })?;
                let permissions = metadata.permissions();
                std::fs::set_permissions(&dst_path, permissions).map_err(|e| BuildError::IoError {
                    path: dst_path.clone(),
                    source: e,
                })?;
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
        use tracing::{info, instrument};

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
                        self.oci_client
                            .pull_image(&image_str, &self.current_rootfs)
                            .await
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
        let exec_result = self.execute_in_chroot(&merged_dir, &cmd_args, &self.env, &self.current_workdir);

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
            .map_err(|e| BuildError::IoError {
                path: self.current_rootfs.clone(),
                source: e,
            })?
            .next()
            .is_some()
        {
            info!("Copying current rootfs {} to layer {}", self.current_rootfs.display(), layer_dir.display());
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
            info!("Created parent directory: {} for dest: {}", parent.display(), dest_path.display());
        }

        info!(sources = ?sources, destination = %destination, is_dest_dir = is_dest_dir, "Copying files");

        // Copy files from build context
        for source in sources {
            let src_path = context.context_path.join(source);
            info!("COPY: source={} -> src_path={} (exists={})", source, src_path.display(), src_path.exists());

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

            info!("COPY: {} -> {} (is_dir={})", src_path.display(), target_path.display(), src_path.is_dir());

            if src_path.is_dir() {
                Self::copy_dir_all(&src_path, &target_path)?;
            } else {
                std::fs::copy(&src_path, &target_path).map_err(|e| BuildError::IoError {
                    path: src_path.clone(),
                    source: e,
                })?;
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

            let (layer_path, was_cached) = self.execute_node(node, context, cache)?;

            if layer_path.is_some() {
                total_layers += 1;
                if was_cached {
                    cached_layers += 1;
                }
            }
        }

        let duration = start.elapsed();

        // Generate final SquashFS image
        let squashfs_path = self.generate_squashfs()?;

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

        Ok(output)
    }
}

#[cfg(target_os = "linux")]
impl NativeBuilder {
    /// Generates a SquashFS image from the current rootfs.
    fn generate_squashfs(&self) -> BuildResult<PathBuf> {
        use tracing::{info, instrument};

        let squashfs_path = self.work_dir.join("rootfs.squashfs");

        info!(
            rootfs = %self.current_rootfs.display(),
            output = %squashfs_path.display(),
            "Generating SquashFS image"
        );

        // Use mksquashfs command to create SquashFS with zstd compression
        // -comp zstd: Fast compression, good ratio
        // -noappend: Overwrite if exists
        // -no-progress: Suppress progress output
        let output = std::process::Command::new("mksquashfs")
            .arg(&self.current_rootfs)
            .arg(&squashfs_path)
            .arg("-comp")
            .arg("zstd")      // zstd is faster than xz with similar compression
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

        let size_mb = std::fs::metadata(&squashfs_path)?.len() as f64 / (1024.0 * 1024.0);
        info!(
            path = %squashfs_path.display(),
            size_mb = format!("{:.2}", size_mb),
            "SquashFS image generated successfully"
        );

        Ok(squashfs_path)
    }
}

/// macOS builder - uses simple chroot without overlayfs.
///
/// This is a development-friendly builder for macOS that doesn't use overlayfs
/// (which doesn't exist on macOS). Instead it uses directory copying for layers.
/// For production builds, use Linux with NativeBuilder.
#[cfg(target_os = "macos")]
pub struct MacOsBuilder {
    /// Working directory for builds
    work_dir: PathBuf,
    /// Current rootfs (merged from all layers)
    current_rootfs: PathBuf,
    /// Layers (captured tarballs)
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

#[cfg(target_os = "macos")]
impl MacOsBuilder {
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

    fn create_work_dir() -> BuildResult<PathBuf> {
        let temp = std::env::temp_dir();
        let work_dir = temp.join(format!("hypr-build-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir)?;
        Ok(work_dir)
    }

    /// Creates a layer directory by copying current rootfs.
    /// (macOS doesn't have overlayfs, so we copy instead)
    fn create_layer_dir(&self, step_id: usize) -> BuildResult<PathBuf> {
        use tracing::debug;

        let layer_dir = self.work_dir.join(format!("layer-{}", step_id));
        debug!("Creating layer directory: {}", layer_dir.display());
        std::fs::create_dir_all(&layer_dir).map_err(|e| BuildError::IoError {
            path: layer_dir.clone(),
            source: e,
        })?;

        // Copy current rootfs to layer dir
        let has_contents = std::fs::read_dir(&self.current_rootfs)
            .map_err(|e| BuildError::IoError {
                path: self.current_rootfs.clone(),
                source: e,
            })?
            .next()
            .is_some();

        if has_contents {
            debug!("Copying rootfs {} to layer directory {}", self.current_rootfs.display(), layer_dir.display());
            Self::copy_dir_all(&self.current_rootfs, &layer_dir)?;
        }

        debug!("Layer directory created successfully: {}", layer_dir.display());
        Ok(layer_dir)
    }

    /// Recursively copies a directory tree.
    fn copy_dir_all(src: &PathBuf, dst: &PathBuf) -> BuildResult<()> {
        debug!("copy_dir_all: Creating dest directory: {}", dst.display());
        std::fs::create_dir_all(dst).map_err(|e| BuildError::IoError {
            path: dst.clone(),
            source: e,
        })?;

        debug!("copy_dir_all: Reading source directory: {}", src.display());
        for entry in std::fs::read_dir(src).map_err(|e| BuildError::IoError {
            path: src.clone(),
            source: e,
        })? {
            let entry = entry.map_err(|e| BuildError::IoError {
                path: src.clone(),
                source: e,
            })?;

            let src_path = entry.path();
            debug!("copy_dir_all: Processing entry: {}", src_path.display());

            let ty = entry.file_type().map_err(|e| BuildError::IoError {
                path: src_path.clone(),
                source: e,
            })?;

            let dst_path = dst.join(entry.file_name());

            // Skip special directories (pseudo-filesystems that shouldn't be copied)
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            if file_name_str == "proc" || file_name_str == "sys" || file_name_str == "dev" {
                // Create empty directory instead of copying
                debug!("copy_dir_all: Skipping pseudo-filesystem: {}", file_name_str);
                std::fs::create_dir_all(&dst_path).map_err(|e| BuildError::IoError {
                    path: dst_path.clone(),
                    source: e,
                })?;
                continue;
            }

            if ty.is_symlink() {
                debug!("copy_dir_all: Copying symlink: {} -> {}", src_path.display(), dst_path.display());
                let link_target = std::fs::read_link(&src_path).map_err(|e| BuildError::IoError {
                    path: src_path.clone(),
                    source: e,
                })?;
                // Remove destination if it exists (file or directory)
                if dst_path.exists() {
                    if dst_path.is_dir() {
                        let _ = std::fs::remove_dir_all(&dst_path);
                    } else {
                        let _ = std::fs::remove_file(&dst_path);
                    }
                }
                std::os::unix::fs::symlink(&link_target, &dst_path).map_err(|e| BuildError::IoError {
                    path: dst_path.clone(),
                    source: e,
                })?;
            } else if ty.is_dir() {
                debug!("copy_dir_all: Recursing into directory: {}", src_path.display());
                Self::copy_dir_all(&src_path, &dst_path)?;
            } else {
                debug!("copy_dir_all: Copying file: {} -> {}", src_path.display(), dst_path.display());
                std::fs::copy(&src_path, &dst_path).map_err(|e| BuildError::IoError {
                    path: src_path.clone(),
                    source: e,
                })?;
            }
        }

        Ok(())
    }

    /// Executes a command in chroot (without overlayfs).
    /// On macOS this is less isolated but still works for builds.
    fn execute_in_chroot(
        &self,
        rootfs: &PathBuf,
        command: &[String],
        env: &HashMap<String, String>,
        workdir: &str,
    ) -> BuildResult<()> {
        use std::process::Command;
        use tracing::info;

        // Create working directory
        let workdir_in_rootfs = rootfs.join(workdir.trim_start_matches('/'));
        std::fs::create_dir_all(&workdir_in_rootfs)?;

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
        for (key, value) in env {
            cmd.env(key, value);
        }

        info!(command = ?command, "Executing in chroot (macOS)");

        let output = cmd.output().map_err(|e| BuildError::InstructionFailed {
            instruction: format!("{:?}", command),
            details: format!("Failed to execute chroot: {}. Note: chroot may require sudo on macOS.", e),
        })?;

        if !output.status.success() {
            let exit_code = output.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BuildError::CommandFailed {
                command: format!("{:?}", command),
                exit_code,
                stderr: stderr.to_string(),
            });
        }

        Ok(())
    }

    /// Captures layer changes by diffing directories.
    fn capture_layer(&self, layer_dir: &PathBuf, step_id: usize) -> BuildResult<PathBuf> {
        let layer_path = self.work_dir.join(format!("layer-{}.tar", step_id));
        debug!("Creating layer tarball: {}", layer_path.display());

        // Verify layer directory exists before tarring
        if !layer_dir.exists() {
            return Err(BuildError::InstructionFailed {
                instruction: "COPY".into(),
                details: format!("Layer directory does not exist: {}", layer_dir.display()),
            });
        }
        debug!("Layer directory exists, contains {} entries",
            std::fs::read_dir(layer_dir)?.count());

        let tar_file = std::fs::File::create(&layer_path).map_err(|e| BuildError::IoError {
            path: layer_path.clone(),
            source: e,
        })?;

        let mut ar = tar::Builder::new(tar_file);

        // CRITICAL: Don't follow symlinks! Alpine has symlinks like /usr/bin/top -> /bin/busybox
        // which point to absolute paths that don't exist on the macOS host.
        ar.follow_symlinks(false);

        debug!("Appending layer directory {} to tar (archive path='.', follow_symlinks=false)", layer_dir.display());
        ar.append_dir_all(".", layer_dir).map_err(|e| {
            // Log additional context
            debug!("append_dir_all failed: {}", e);
            debug!("layer_dir exists: {}", layer_dir.exists());
            debug!("layer_dir is_dir: {}", layer_dir.is_dir());
            BuildError::IoError {
                path: layer_dir.clone(),
                source: e,
            }
        })?;

        debug!("Finalizing tar");
        ar.finish().map_err(|e| BuildError::IoError {
            path: layer_path.clone(),
            source: e,
        })?;

        Ok(layer_path)
    }

    /// Merges layer into current rootfs.
    fn merge_layer(&mut self, layer_dir: &PathBuf) -> BuildResult<()> {
        if std::fs::read_dir(layer_dir)?.next().is_some() {
            // Clear current rootfs
            for entry in std::fs::read_dir(&self.current_rootfs)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    std::fs::remove_dir_all(entry.path())?;
                } else {
                    std::fs::remove_file(entry.path())?;
                }
            }
            // Copy layer to rootfs
            Self::copy_dir_all(layer_dir, &self.current_rootfs)?;
        }
        Ok(())
    }

    /// Generate SquashFS (requires squashfs-tools on macOS: brew install squashfs)
    fn generate_squashfs(&self) -> BuildResult<PathBuf> {
        use tracing::info;

        let squashfs_path = self.work_dir.join("rootfs.squashfs");

        info!(
            rootfs = %self.current_rootfs.display(),
            output = %squashfs_path.display(),
            "Generating SquashFS image (macOS)"
        );

        let output = std::process::Command::new("mksquashfs")
            .arg(&self.current_rootfs)
            .arg(&squashfs_path)
            .arg("-comp")
            .arg("zstd")
            .arg("-noappend")
            .arg("-no-progress")
            .output()
            .map_err(|e| BuildError::InstructionFailed {
                instruction: "mksquashfs".to_string(),
                details: format!(
                    "Failed to run mksquashfs: {}.\n\
                     Install with: brew install squashfs",
                    e
                ),
            })?;

        if !output.status.success() {
            return Err(BuildError::InstructionFailed {
                instruction: "mksquashfs".to_string(),
                details: format!("mksquashfs failed:\n{}", String::from_utf8_lossy(&output.stderr)),
            });
        }

        let size_mb = std::fs::metadata(&squashfs_path)?.len() as f64 / (1024.0 * 1024.0);
        info!(size_mb = format!("{:.2}", size_mb), "SquashFS generated");

        Ok(squashfs_path)
    }

    // Reuse FROM implementation from Linux builder
    fn execute_from(&mut self, node: &BuildNode) -> BuildResult<Option<PathBuf>> {
        use crate::builder::parser::{ImageRef, Instruction};
        use tracing::info;

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
                std::fs::create_dir_all(self.current_rootfs.join("tmp"))?;
                std::fs::create_dir_all(self.current_rootfs.join("etc"))?;
                Ok(None)
            }
            ImageRef::Stage(stage_name) => Err(BuildError::InstructionFailed {
                instruction: "FROM".to_string(),
                details: format!("Multi-stage builds not yet supported: FROM {}", stage_name),
            }),
            ImageRef::Image { name, tag, digest } => {
                let image_str = if let Some(digest) = digest {
                    format!("{}@{}", name, digest)
                } else {
                    format!("{}:{}", name, tag.as_deref().unwrap_or("latest"))
                };

                info!("FROM {}: pulling base image", image_str);

                // Use block_in_place to avoid nested runtime issues when called from async context
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        self.oci_client.pull_image(&image_str, &self.current_rootfs).await
                    })
                })?;

                info!("Base image extracted");
                Ok(None)
            }
        }
    }

    fn execute_run(&mut self, command: &crate::builder::parser::RunCommand) -> BuildResult<Option<PathBuf>> {
        use crate::builder::parser::RunCommand;

        let cmd_args: Vec<String> = match command {
            RunCommand::Shell(cmd) => vec!["/bin/sh".to_string(), "-c".to_string(), cmd.clone()],
            RunCommand::Exec(args) => args.clone(),
        };

        let step_id = self.layers.len();
        let layer_dir = self.create_layer_dir(step_id)?;

        self.execute_in_chroot(&layer_dir, &cmd_args, &self.env, &self.current_workdir)?;

        let layer_path = self.capture_layer(&layer_dir, step_id)?;
        self.merge_layer(&layer_dir)?;
        self.layers.push(layer_path.clone());

        Ok(Some(layer_path))
    }

    fn execute_copy(&mut self, sources: &[String], destination: &str, context: &BuildContext) -> BuildResult<Option<PathBuf>> {
        let step_id = self.layers.len();
        // CRITICAL: Must copy current_rootfs first (contains base image files from FROM)
        let layer_dir = self.create_layer_dir(step_id)?;

        // Docker semantics: if destination doesn't end with '/' and there's 1 source, it's a file rename
        let is_dest_dir = destination.ends_with('/') || sources.len() > 1;

        let dest_path = if destination.starts_with('/') {
            layer_dir.join(destination.trim_start_matches('/'))
        } else {
            layer_dir.join(self.current_workdir.trim_start_matches('/')).join(destination)
        };

        // If dest is a directory, create it. If it's a file path, create only the parent
        if is_dest_dir {
            debug!("Creating destination directory: {}", dest_path.display());
            std::fs::create_dir_all(&dest_path).map_err(|e| BuildError::IoError {
                path: dest_path.clone(),
                source: e,
            })?;
        } else if let Some(parent) = dest_path.parent() {
            debug!("Creating parent directory: {}", parent.display());
            std::fs::create_dir_all(parent).map_err(|e| BuildError::IoError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        for source in sources {
            let src_path = context.context_path.join(source);
            debug!("Copying source {} to layer", source);

            if !src_path.exists() {
                return Err(BuildError::ContextError(format!("Source not found: {}", source)));
            }

            // Determine target path based on whether dest is a directory or file
            let target_path = if is_dest_dir {
                // Dest is directory - copy into it with original filename
                let file_name = src_path.file_name().ok_or_else(|| BuildError::ContextError("Invalid path".into()))?;
                dest_path.join(file_name)
            } else {
                // Dest is file path - copy directly to it (rename)
                dest_path.clone()
            };

            if src_path.is_dir() {
                debug!("Copying directory: {} -> {}", src_path.display(), target_path.display());
                Self::copy_dir_all(&src_path, &target_path)?;
            } else {
                debug!("Copying file: {} -> {}", src_path.display(), target_path.display());
                std::fs::copy(&src_path, &target_path).map_err(|e| BuildError::IoError {
                    path: src_path.clone(),
                    source: e,
                })?;
            }
        }

        debug!("Capturing layer {}", step_id);
        let layer_path = self.capture_layer(&layer_dir, step_id)?;

        debug!("Merging layer into current rootfs");
        self.merge_layer(&layer_dir)?;

        self.layers.push(layer_path.clone());

        Ok(Some(layer_path))
    }

    fn execute_env(&mut self, vars: &HashMap<String, String>) -> BuildResult<Option<PathBuf>> {
        for (key, value) in vars {
            self.env.insert(key.clone(), value.clone());
        }
        Ok(None)
    }

    fn execute_workdir(&mut self, path: &str) -> BuildResult<Option<PathBuf>> {
        self.current_workdir = path.to_string();
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

#[cfg(target_os = "macos")]
impl BuildExecutor for MacOsBuilder {
    fn execute(
        &mut self,
        graph: &BuildGraph,
        context: &BuildContext,
        _cache: &mut CacheManager,
    ) -> BuildResult<BuildOutput> {
        use sha2::{Digest, Sha256};
        use std::time::Instant;
        use tracing::info;

        info!("Starting build (macOS mode - no overlayfs, less isolated)");

        let start = Instant::now();

        // Execute all nodes in topological order
        let node_ids = graph.topological_sort().map_err(|e| BuildError::InstructionFailed {
            instruction: "topological_sort".to_string(),
            details: format!("Failed to sort build graph: {}", e),
        })?;

        for node_id in node_ids {
            let node = &graph.nodes[node_id];
            match &node.instruction {
                crate::builder::parser::Instruction::From { .. } => {
                    self.execute_from(node)?;
                }
                crate::builder::parser::Instruction::Run { command } => {
                    self.execute_run(command)?;
                }
                crate::builder::parser::Instruction::Copy { sources, destination, .. } => {
                    self.execute_copy(sources, destination, context)?;
                }
                crate::builder::parser::Instruction::Add { sources, destination, .. } => {
                    self.execute_copy(sources, destination, context)?; // ADD same as COPY for now
                }
                crate::builder::parser::Instruction::Env { vars } => {
                    self.execute_env(vars)?;
                }
                crate::builder::parser::Instruction::Workdir { path } => {
                    self.execute_workdir(path)?;
                }
                crate::builder::parser::Instruction::User { user } => {
                    self.execute_user(user)?;
                }
                _ => {} // Skip other instructions for now
            }
        }

        let duration = start.elapsed();

        // Generate SquashFS
        let squashfs_path = self.generate_squashfs()?;
        let total_size = std::fs::metadata(&squashfs_path)?.len();

        // Generate image ID (SHA256 of squashfs)
        let squashfs_data = std::fs::read(&squashfs_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&squashfs_data);
        let image_id = format!("{:x}", hasher.finalize());

        // Generate manifest
        let mut manifest_gen = crate::builder::manifest::ManifestGenerator::new();
        let (name, tag) = ("myimage".to_string(), "latest".to_string());
        let manifest = manifest_gen.generate(graph, name, tag, None)?;

        Ok(BuildOutput {
            image_id: image_id[..12].to_string(), // Short ID like Docker
            rootfs_path: squashfs_path,
            manifest,
            stats: BuildStats {
                duration_secs: duration.as_secs_f64(),
                layer_count: self.layers.len(),
                cached_layers: 0, // No caching on macOS builder yet
                total_size,
            },
        })
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
        Ok(Box::new(MacOsBuilder::new()?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(BuildError::PlatformNotSupported(
            format!("Builds not supported on {}. Supported: Linux, macOS", std::env::consts::OS)
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
