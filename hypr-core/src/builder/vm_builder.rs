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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
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

        // Send build command via vsock
        let result = self.send_build_command(&vm, step).await;

        // Terminate VM (always, even on error)
        if let Err(e) = self.terminate_vm(&vm).await {
            warn!("Failed to terminate builder VM: {}", e);
        }

        // Check build result
        let () = result?;

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
            vsock_path: PathBuf::from(format!("/tmp/hypr-{}.sock", vm_id)),
            virtio_fs_mounts,
        };

        let handle = self.adapter.create(&config).await.map_err(|e| {
            error!("Failed to spawn builder VM: {}", e);
            HyprError::BuildFailed { reason: format!("Failed to spawn builder VM: {}", e) }
        })?;

        // Wait for VM to boot and builder-agent to be ready
        self.wait_for_builder_ready(&handle).await?;

        Ok(handle)
    }

    /// Wait for builder-agent to become ready.
    #[instrument(skip(self, handle))]
    async fn wait_for_builder_ready(&self, handle: &VmHandle) -> Result<()> {
        debug!("Waiting for builder-agent to be ready");

        let timeout = Duration::from_secs(10);
        let start = Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(HyprError::BuildFailed {
                    reason: "Builder agent did not become ready in time".into(),
                });
            }

            // Try to connect to vsock
            match self.ping_builder_agent(handle).await {
                Ok(()) => {
                    info!("Builder agent ready");
                    return Ok(());
                }
                Err(_) => {
                    // Not ready yet, wait and retry
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Send a ping to builder-agent to check if it's ready.
    async fn ping_builder_agent(&self, handle: &VmHandle) -> Result<()> {
        let vsock_path = self.adapter.vsock_path(handle);

        let mut stream = UnixStream::connect(vsock_path).await.map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to connect to builder agent: {}", e) }
        })?;

        // Send Ping command
        let ping_cmd = r#"{"Ping":{}}"#;
        stream.write_all(ping_cmd.as_bytes()).await.map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to send ping: {}", e),
        })?;

        // Read response
        let mut response = String::new();
        stream.read_to_string(&mut response).await.map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to read ping response: {}", e),
        })?;

        if response.contains("Pong") {
            Ok(())
        } else {
            Err(HyprError::BuildFailed {
                reason: format!("Unexpected ping response: {}", response),
            })
        }
    }

    /// Send a build command to builder-agent via vsock.
    #[instrument(skip(self, handle, step))]
    async fn send_build_command(&self, handle: &VmHandle, step: &BuildStep) -> Result<()> {
        debug!("Sending build command via vsock");

        let vsock_path = self.adapter.vsock_path(handle);

        let mut stream = UnixStream::connect(vsock_path).await.map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to connect to builder agent: {}", e) }
        })?;

        // Serialize build command
        let command = self.build_command_json(step)?;

        // Send command
        stream.write_all(command.as_bytes()).await.map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to send build command: {}", e),
        })?;

        // Read response
        let mut response = String::new();
        stream.read_to_string(&mut response).await.map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to read build response: {}", e),
        })?;

        // Check for success
        if response.contains(r#""Ok""#) {
            Ok(())
        } else {
            Err(HyprError::BuildFailed { reason: format!("Build command failed: {}", response) })
        }
    }

    /// Convert build step to JSON command for builder-agent.
    fn build_command_json(&self, step: &BuildStep) -> Result<String> {
        match step {
            BuildStep::Run { command, workdir } => {
                let json = serde_json::json!({
                    "Run": {
                        "command": command,
                        "workdir": workdir
                    }
                });
                Ok(json.to_string())
            }
            BuildStep::Finalize { layer_id } => {
                let json = serde_json::json!({
                    "Finalize": {
                        "layer_id": layer_id
                    }
                });
                Ok(json.to_string())
            }
        }
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
