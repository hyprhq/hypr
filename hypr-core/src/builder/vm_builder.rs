//! VM-based builder for secure, isolated image builds.
//!
//! Builds occur inside ephemeral Alpine Linux VMs with:
//! - No network interface (HTTP traffic proxied via vsock to host)
//! - Build context shared via virtio-fs
//! - Commands sent via vsock to builder-agent.c
//! - Layer tarballs extracted via virtio-fs

use crate::adapters::VmmAdapter;
use crate::error::{HyprError, Result};
use crate::types::vm::{VirtioFsMount, VmConfig, VmHandle};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, instrument, warn};

/// VM-based builder that executes builds in isolated Linux VMs with minimal initramfs.
///
/// Each build spawns a fresh VM (<100ms cold start), executes build steps,
/// extracts the resulting layer, and terminates the VM.
///
/// # Architecture
///
/// ```text
/// Host:
///   - BuilderHttpProxy on localhost:41010 (proxies to internet)
///   - VmBuilder spawns minimal Linux VM with initramfs + virtio-fs mounts
///   - OCI base images pulled and shared via virtio-fs
///
/// Guest (minimal initramfs):
///   - kestrel.c (PID 1, mode=build) listens on vsock port 41011
///   - Mounts base image rootfs from virtio-fs, pivots root
///   - Build commands execute in base image context (chroot)
///   - Layers written to /shared (virtio-fs) → host extracts
/// ```
pub struct VmBuilder {
    /// VMM adapter for spawning VMs
    adapter: Box<dyn VmmAdapter>,

    /// Path to Linux kernel
    kernel_path: PathBuf,

    /// Work directory for build contexts and layer extraction (reserved for future use)
    _work_dir: PathBuf,

    /// Whether HTTP proxy is running
    proxy_running: bool,

    /// Cached initramfs path (generated once, reused across builds)
    initramfs_cache: Option<PathBuf>,
}

impl VmBuilder {
    /// Create a new VM-based builder.
    ///
    /// # Arguments
    /// * `adapter` - VMM adapter for spawning VMs
    /// * `kernel_path` - Path to Linux kernel
    /// * `work_dir` - Working directory for builds
    ///
    /// Note: builder_rootfs parameter removed (now uses on-the-fly initramfs)
    pub fn new(
        adapter: Box<dyn VmmAdapter>,
        _builder_rootfs: PathBuf, // Kept for compatibility, will be removed
        kernel_path: PathBuf,
        work_dir: PathBuf,
    ) -> Self {
        Self {
            adapter,
            kernel_path,
            _work_dir: work_dir,
            proxy_running: false,
            initramfs_cache: None,
        }
    }

    /// Get or create the initramfs for builder VMs.
    ///
    /// Generates initramfs once and caches it for reuse across builds.
    fn get_or_create_initramfs(&mut self) -> Result<PathBuf> {
        if let Some(cached) = &self.initramfs_cache {
            if cached.exists() {
                debug!("Using cached initramfs: {}", cached.display());
                return Ok(cached.clone());
            }
        }

        // Generate new initramfs
        info!("Generating builder initramfs");
        let initramfs = crate::builder::initramfs::create_builder_initramfs().map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to create initramfs: {}", e) }
        })?;

        self.initramfs_cache = Some(initramfs.clone());
        Ok(initramfs)
    }

    /// Execute a build step in an ephemeral builder VM.
    ///
    /// # Arguments
    /// * `step` - Build step to execute
    /// * `context_dir` - Build context directory (mounted via virtio-fs)
    /// * `output_layer` - Path where layer tarball will be written
    /// * `base_rootfs` - Optional base image rootfs (from FROM instruction, mounted via virtio-fs)
    ///
    /// # Returns
    /// Build layer info (size, hash)
    #[instrument(skip(self, step), fields(step_type = %step.step_type()))]
    pub async fn execute_step(
        &mut self,
        step: &BuildStep,
        context_dir: &Path,
        output_layer: &Path,
        base_rootfs: Option<&Path>,
    ) -> Result<BuildLayerInfo> {
        info!("Executing build step: {}", step.step_type());
        let start = Instant::now();

        // TODO: HTTP proxy for VM builder network access
        // For testing: temporarily disabled until proxy is implemented
        // The builder VM will fail on RUN commands that need network
        if !self.proxy_running {
            warn!("HTTP proxy not running - network operations in VM will fail");
        }

        // Spawn builder VM
        let vm =
            self.spawn_builder_vm(context_dir, output_layer.parent().unwrap(), base_rootfs).await?;

        // Send build command via filesystem IPC
        let exit_code = self.send_build_command(&vm, step, context_dir).await;

        // Terminate VM (always, even on error)
        if let Err(e) = self.terminate_vm(&vm).await {
            warn!("Failed to terminate builder VM: {}", e);
        }

        // Check build result
        let exit_code = exit_code?;
        if exit_code != 0 {
            return Err(HyprError::BuildFailed {
                reason: format!("Build command exited with code {}", exit_code),
            });
        }

        // Extract layer metadata
        let metadata = self.extract_layer_metadata(output_layer).await?;

        let duration = start.elapsed();
        info!("Build step completed in {:?}", duration);
        metrics::histogram!("hypr_build_step_duration_seconds").record(duration.as_secs_f64());

        Ok(metadata)
    }

    /// Spawn an ephemeral builder VM with minimal initramfs.
    #[instrument(skip(self))]
    async fn spawn_builder_vm(
        &mut self,
        context_dir: &Path,
        output_dir: &Path,
        base_rootfs: Option<&Path>,
    ) -> Result<VmHandle> {
        debug!("Spawning builder VM");

        let vm_id = format!("builder-{}", uuid::Uuid::new_v4());

        // Get or create initramfs
        let initramfs = self.get_or_create_initramfs()?;

        // Configure virtio-fs mounts:
        // 1. Build context (read-only)
        // 2. Output directory for layers (read-write)
        // 3. Base image rootfs (optional, read-only)
        let mut virtio_fs_mounts = vec![
            VirtioFsMount { host_path: context_dir.to_path_buf(), tag: "context".to_string() },
            VirtioFsMount { host_path: output_dir.to_path_buf(), tag: "shared".to_string() },
        ];

        // Add base rootfs mount if provided
        if let Some(base) = base_rootfs {
            debug!("Adding base rootfs mount: {}", base.display());
            virtio_fs_mounts
                .push(VirtioFsMount { host_path: base.to_path_buf(), tag: "base".to_string() });
        }

        use crate::types::vm::VmResources;

        let config = VmConfig {
            network_enabled: false, // Build VMs are network-isolated for security
            id: vm_id.clone(),
            name: vm_id.clone(),
            resources: VmResources {
                cpus: 2,
                memory_mb: 1024, // 1GB for builds
            },
            kernel_path: Some(self.kernel_path.clone()),
            kernel_args: vec![
                "init=/init".to_string(),
                "mode=build".to_string(),
                "console=ttyS0".to_string(),
            ],
            initramfs_path: Some(initramfs),
            disks: vec![], // No disks, using initramfs only
            network: Default::default(),
            ports: vec![],
            env: Default::default(),
            volumes: vec![],
            gpu: None,
            virtio_fs_mounts,
        };

        // Boot the VM (hypervisor creates the Unix socket, guest connects via vsock)
        let handle = self.adapter.create(&config).await.map_err(|e| {
            error!("Failed to spawn builder VM: {}", e);
            HyprError::BuildFailed { reason: format!("Failed to spawn builder VM: {}", e) }
        })?;

        // Wait for kestrel to be ready (watches for "[kestrel] READY" in stdout)
        // TODO: Implement stdout monitoring
        info!("Builder VM started, waiting for kestrel to be ready...");
        tokio::time::sleep(Duration::from_secs(2)).await; // Temporary: give VM time to boot

        Ok(handle)
    }

    /// Send a build command to builder via filesystem IPC.
    ///
    /// Writes command file to /context/.hypr/commands/NNN.cmd
    /// Waits for kestrel to process and delete the file
    /// Parses [HYPR-RESULT] block from stdout
    #[instrument(skip(self, step), fields(step_type = %step.step_type()))]
    async fn send_build_command(
        &self,
        _handle: &VmHandle,
        step: &BuildStep,
        context_dir: &std::path::Path,
    ) -> Result<i32> {
        debug!("Sending build command via filesystem");

        // Create .hypr/commands directory if it doesn't exist
        let commands_dir = context_dir.join(".hypr/commands");
        tokio::fs::create_dir_all(&commands_dir).await.map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to create commands directory: {}", e),
        })?;

        // Generate command file (sequential numbering)
        static COMMAND_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let cmd_num = COMMAND_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let cmd_file = commands_dir.join(format!("{:03}.cmd", cmd_num));

        // Build command content
        let command_text = match step {
            BuildStep::Run { command, workdir } => {
                format!("RUN {}\n{}", workdir, command)
            }
            BuildStep::Finalize { layer_id } => {
                format!("FINALIZE {}", layer_id)
            }
        };

        // Write command file
        tokio::fs::write(&cmd_file, command_text).await.map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to write command file: {}", e),
        })?;

        debug!("Command file written: {}", cmd_file.display());

        // Wait for result file to appear (kestrel writes NNN.cmd.result)
        let result_file = cmd_file.with_extension("cmd.result");
        let start = Instant::now();
        while !result_file.exists() {
            if start.elapsed() > Duration::from_secs(300) {
                // 5 minute timeout
                return Err(HyprError::BuildFailed {
                    reason: "Command execution timeout (5 minutes)".to_string(),
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Read result file
        let result_contents = tokio::fs::read_to_string(&result_file).await.map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to read result file: {}", e) }
        })?;

        // Parse exit code from "exit=N" format
        let exit_code = if let Some(line) = result_contents.lines().next() {
            if let Some(code_str) = line.strip_prefix("exit=") {
                code_str.parse::<i32>().unwrap_or(127)
            } else {
                127
            }
        } else {
            127
        };

        debug!("Command processed by kestrel, exit_code={}", exit_code);

        // Clean up command and result files
        let _ = tokio::fs::remove_file(&cmd_file).await;
        let _ = tokio::fs::remove_file(&result_file).await;

        Ok(exit_code)
    }

    /// Terminate a builder VM.
    #[instrument(skip(self, handle))]
    async fn terminate_vm(&self, handle: &VmHandle) -> Result<()> {
        debug!("Terminating builder VM");

        let stop_result = self.adapter.stop(handle, Duration::from_secs(5)).await;

        if stop_result.is_err() {
            warn!("Failed to gracefully stop VM, force killing");
            self.adapter.kill(handle).await?;
        }

        self.adapter.delete(handle).await?;

        Ok(())
    }

    /// Extract metadata from layer tarball.
    async fn extract_layer_metadata(&self, layer_path: &Path) -> Result<BuildLayerInfo> {
        let metadata = tokio::fs::metadata(layer_path).await.map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to read layer metadata: {}", e) }
        })?;

        // Compute SHA256 hash
        let hash = self.compute_layer_hash(layer_path).await?;

        Ok(BuildLayerInfo { size_bytes: metadata.len(), sha256: hash })
    }

    /// Compute SHA256 hash of layer tarball.
    async fn compute_layer_hash(&self, layer_path: &Path) -> Result<String> {
        use sha2::{Digest, Sha256};

        let bytes = tokio::fs::read(layer_path).await.map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to read layer for hashing: {}", e),
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hasher.finalize();

        Ok(format!("{:x}", hash))
    }
}

/// Build step to execute in builder VM.
#[derive(Debug, Clone)]
pub enum BuildStep {
    /// Execute a RUN command
    Run {
        /// Shell command to execute
        command: String,
        /// Working directory
        workdir: String,
    },
    /// Finalize layer (create tarball)
    Finalize {
        /// Layer ID for output filename
        layer_id: String,
    },
}

impl BuildStep {
    /// Get the type of this build step (for logging).
    pub fn step_type(&self) -> &str {
        match self {
            BuildStep::Run { .. } => "RUN",
            BuildStep::Finalize { .. } => "FINALIZE",
        }
    }
}

/// Information about a built layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildLayerInfo {
    /// Size of layer tarball in bytes
    pub size_bytes: u64,
    /// SHA256 hash of layer tarball
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_step_type() {
        let run_step =
            BuildStep::Run { command: "echo hello".into(), workdir: "/workspace".into() };
        assert_eq!(run_step.step_type(), "RUN");

        let finalize_step = BuildStep::Finalize { layer_id: "layer-123".into() };
        assert_eq!(finalize_step.step_type(), "FINALIZE");
    }
}
