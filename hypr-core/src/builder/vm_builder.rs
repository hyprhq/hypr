//! VM-based builder for secure, isolated image builds.
//!
//! # CANONICAL BUILD PLANE ARCHITECTURE v1.0
//!
//! This module implements HYPR's deterministic, hermetic build system.
//!
//! ## Core Principles (DO NOT VIOLATE):
//!
//! 1. **Static Input DAG**: ALL build commands are written to disk BEFORE VM boots
//! 2. **No Dynamic Coordination**: NO waiting for READY, NO sending commands after boot
//! 3. **Filesystem-Only IPC**: Communication via virtio-fs files + stdout markers
//! 4. **No Network**: Build VMs are 100% offline, all deps prefetched by host
//! 5. **One-Shot Execution**: VM boots → runs commands → exits. No RPC, no agents.
//!
//! ## Data Flow:
//!
//! ```text
//! Phase 1 - Host Preparation (BEFORE VM boot):
//!   - OCI image pulling (if FROM image)
//!   - Package prefetching (apt, npm, pip, etc.)
//!   - Hydrate rootfs into /base
//!   - Write ALL command files to /context/.hypr/commands/ as NNN.cmd
//!   - Prepare /packages/ directory with offline deps
//!
//! Phase 2 - VM Boot & Execution:
//!   - Spawn VM with virtio-fs mounts (context, shared, base, packages)
//!   - Kestrel boots → mounts filesystems → creates overlayfs → chroots
//!   - Kestrel scans /context/.hypr/commands/ directory
//!   - Executes commands in lexical order (000.cmd, 001.cmd, ...)
//!   - Prints [HYPR-RESULT] markers to stdout after each command
//!   - VM exits when all commands complete
//!
//! Phase 3 - Result Collection (AFTER VM exit):
//!   - Host parses stdout for [HYPR-RESULT] blocks
//!   - Host collects layer outputs from /shared
//!   - Build succeeds if all exit codes == 0
//! ```
//!
//! ## What This Module Does NOT Do:
//!
//! ❌ Wait for READY markers
//! ❌ Send commands dynamically after boot
//! ❌ Implement timing coordination
//! ❌ Use vsock or network for build coordination
//! ❌ Treat stdout as a control protocol
//! ❌ Modify command sequence mid-build
//!
//! ## Stdout Streaming:
//!
//! Stdout is streamed for user visibility and log collection, but has ZERO
//! influence on build semantics. It's a pure presentation layer.
//!
//! Think: `tail -f | prettier` - just decoration, no protocol.

use crate::adapters::VmmAdapter;
use crate::builder::output_stream::BuildOutputStream;
use crate::error::{HyprError, Result};
use crate::types::vm::{VirtioFsMount, VmConfig, VmHandle};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

/// VM-based builder that executes builds in isolated Linux VMs.
///
/// Each build spawns a fresh VM, executes build steps, extracts layers, and terminates.
pub struct VmBuilder {
    /// VMM adapter for spawning VMs
    adapter: Box<dyn VmmAdapter>,

    /// Path to Linux kernel
    kernel_path: PathBuf,

    /// Work directory for build contexts
    _work_dir: PathBuf,

    /// Cached initramfs path (generated once, reused)
    initramfs_cache: Option<PathBuf>,
}

impl VmBuilder {
    /// Create a new VM-based builder.
    pub fn new(
        adapter: Box<dyn VmmAdapter>,
        _builder_rootfs: PathBuf, // Kept for compatibility
        kernel_path: PathBuf,
        work_dir: PathBuf,
    ) -> Self {
        Self { adapter, kernel_path, _work_dir: work_dir, initramfs_cache: None }
    }

    /// Get or create the initramfs for builder VMs.
    fn get_or_create_initramfs(&mut self) -> Result<PathBuf> {
        if let Some(cached) = &self.initramfs_cache {
            if cached.exists() {
                debug!("Using cached initramfs: {}", cached.display());
                return Ok(cached.clone());
            }
        }

        info!("Generating builder initramfs");
        let initramfs = crate::builder::initramfs::create_builder_initramfs().map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to create initramfs: {}", e) }
        })?;

        self.initramfs_cache = Some(initramfs.clone());
        Ok(initramfs)
    }

    /// Execute a build step in an ephemeral builder VM.
    ///
    /// **CANONICAL FLOW:**
    /// 1. Write command file to context_dir/.hypr/commands/ (static input)
    /// 2. Spawn VM (which mounts context_dir via virtio-fs)
    /// 3. Stream stdout (prettified, for user visibility)
    /// 4. Wait for VM to exit
    /// 5. Parse results from stdout
    ///
    /// NO dynamic coordination. NO READY flags. Pure determinism.
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

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 1: PREPARE STATIC INPUTS (BEFORE VM BOOT)
        // ═══════════════════════════════════════════════════════════════════

        // Create commands directory
        let commands_dir = context_dir.join(".hypr/commands");
        std::fs::create_dir_all(&commands_dir).map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to create commands dir: {}", e),
        })?;

        // Write command file (static, before boot)
        let cmd_file = commands_dir.join("001.cmd");
        let command_text = self.build_command_file(step)?;
        std::fs::write(&cmd_file, &command_text).map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to write command file: {}", e),
        })?;

        debug!("Command file written: {} (BEFORE VM boot)", cmd_file.display());
        debug!("Command content:\n{}", command_text);

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 2: SPAWN VM & STREAM OUTPUT
        // ═══════════════════════════════════════════════════════════════════

        let (vm, mut child) =
            self.spawn_builder_vm(context_dir, output_layer.parent().unwrap(), base_rootfs).await?;

        // Stream stdout using prettifier (pure presentation layer)
        let log_path = PathBuf::from(format!("/tmp/hypr-vm-{}.log", vm.id));
        let mut streamer = BuildOutputStream::new();

        info!("Streaming VM output from: {}", log_path.display());
        let results = streamer.stream_from_file(&log_path).await?;

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 3: WAIT FOR VM EXIT & PARSE RESULTS
        // ═══════════════════════════════════════════════════════════════════

        // Wait for VM to exit
        let exit_status = child.wait().await.map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to wait for VM: {}", e),
        })?;

        debug!("VM exited with status: {:?}", exit_status);

        // Clean up command file
        let _ = std::fs::remove_file(&cmd_file);

        // Terminate VM resources
        if let Err(e) = self.terminate_vm(&vm).await {
            warn!("Failed to terminate builder VM: {}", e);
        }

        // Parse build results
        if results.is_empty() {
            return Err(HyprError::BuildFailed {
                reason: "No build results found in VM output".to_string(),
            });
        }

        let result = &results[0];
        if result.exit_code != 0 {
            return Err(HyprError::BuildFailed {
                reason: format!("Build command failed with exit code {}", result.exit_code),
            });
        }

        info!("✓ Build step completed successfully in {:.2}s", start.elapsed().as_secs_f64());

        // Extract layer metadata
        let metadata = self.extract_layer_metadata(output_layer).await?;

        metrics::histogram!("hypr_build_step_duration_seconds")
            .record(start.elapsed().as_secs_f64());
        metrics::counter!("hypr_build_steps_completed_total").increment(1);

        Ok(metadata)
    }

    /// Build command file content from build step.
    ///
    /// This generates the static command file in kestrel's expected format:
    /// - RUN commands: "RUN {workdir}\n{command}"
    /// - FINALIZE commands: "FINALIZE {layer_id}"
    fn build_command_file(&self, step: &BuildStep) -> Result<String> {
        let content = match step {
            BuildStep::Run { command, workdir } => {
                format!("RUN {}\n{}", workdir, command)
            }
            BuildStep::Finalize { layer_id } => {
                format!("FINALIZE {}", layer_id)
            }
        };

        Ok(content)
    }

    /// Spawn an ephemeral builder VM with minimal initramfs.
    #[instrument(skip(self))]
    async fn spawn_builder_vm(
        &mut self,
        context_dir: &Path,
        output_dir: &Path,
        base_rootfs: Option<&Path>,
    ) -> Result<(VmHandle, tokio::process::Child)> {
        debug!("Spawning builder VM");

        let vm_id = format!("builder-{}", uuid::Uuid::new_v4());
        let initramfs = self.get_or_create_initramfs()?;

        // Configure virtio-fs mounts
        let mut virtio_fs_mounts = vec![
            VirtioFsMount { host_path: context_dir.to_path_buf(), tag: "context".to_string() },
            VirtioFsMount { host_path: output_dir.to_path_buf(), tag: "shared".to_string() },
        ];

        if let Some(base) = base_rootfs {
            debug!("Adding base rootfs mount: {}", base.display());
            virtio_fs_mounts
                .push(VirtioFsMount { host_path: base.to_path_buf(), tag: "base".to_string() });
        }

        use crate::types::vm::VmResources;

        let config = VmConfig {
            network_enabled: false, // CRITICAL: No network for hermetic builds
            id: vm_id.clone(),
            name: vm_id.clone(),
            resources: VmResources { cpus: 2, memory_mb: 1024 },
            kernel_path: Some(self.kernel_path.clone()),
            kernel_args: vec![
                "init=/init".to_string(),
                "mode=build".to_string(),
                "console=hvc0".to_string(), // vfkit uses hvc0, not ttyS0
            ],
            initramfs_path: Some(initramfs),
            disks: vec![],
            network: Default::default(),
            ports: vec![],
            env: Default::default(),
            volumes: vec![],
            gpu: None,
            virtio_fs_mounts,
        };

        // Build command (async for virtiofsd setup)
        let cmd_spec = self.adapter.build_command(&config).await.map_err(|e| {
            error!("Failed to build VM command: {}", e);
            HyprError::BuildFailed { reason: format!("Failed to build VM command: {}", e) }
        })?;

        // Create log file for VM stdout/stderr
        let log_path = PathBuf::from(format!("/tmp/hypr-vm-{}.log", vm_id));
        let log_file = std::fs::File::create(&log_path).map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to create log file: {}", e),
        })?;

        // Spawn VM process with stdout/stderr redirected to log file
        info!("Spawning builder VM: {} {:?}", cmd_spec.program, cmd_spec.args);
        info!("VM output will be logged to: {}", log_path.display());
        let child = tokio::process::Command::new(&cmd_spec.program)
            .args(&cmd_spec.args)
            .envs(cmd_spec.env)
            .stdout(log_file.try_clone().unwrap())
            .stderr(log_file)
            .spawn()
            .map_err(|e| {
                error!("Failed to spawn builder VM: {}", e);
                HyprError::BuildFailed { reason: format!("Failed to spawn builder VM: {}", e) }
            })?;

        let pid = child.id().ok_or_else(|| HyprError::BuildFailed {
            reason: "Failed to get VM process PID".to_string(),
        })?;

        let handle = VmHandle { id: vm_id.clone(), pid: Some(pid), socket_path: None };

        info!("Builder VM spawned: pid={}", pid);

        Ok((handle, child))
    }

    /// Terminate a builder VM.
    #[instrument(skip(self, handle))]
    async fn terminate_vm(&self, handle: &VmHandle) -> Result<()> {
        debug!("Terminating builder VM");
        self.adapter.kill(handle).await?;
        self.adapter.delete(handle).await?;
        Ok(())
    }

    /// Extract layer metadata after build completes.
    async fn extract_layer_metadata(&self, layer_path: &Path) -> Result<BuildLayerInfo> {
        if !layer_path.exists() {
            return Err(HyprError::BuildFailed {
                reason: format!("Layer file not found: {}", layer_path.display()),
            });
        }

        let metadata = tokio::fs::metadata(layer_path).await.map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to read layer metadata: {}", e) }
        })?;

        Ok(BuildLayerInfo {
            size_bytes: metadata.len(),
            layer_hash: "sha256:placeholder".to_string(), // TODO: compute actual hash
        })
    }

    /// Execute ALL build steps in a SINGLE VM (the correct way).
    pub async fn execute_all_steps(
        &mut self,
        steps: Vec<BuildStep>,
        context_dir: &Path,
        output_dir: &Path,
        base_rootfs: Option<&Path>,
    ) -> Result<Vec<BuildLayerInfo>> {
        info!("Executing {} steps in one VM", steps.len());

        // Generate layer ID
        let layer_id = uuid::Uuid::new_v4().to_string();
        let layer_path = output_dir.join(format!("layer-{}.tar", layer_id));

        // Write ALL command files first (including FINALIZE at the end)
        let commands_dir = context_dir.join(".hypr/commands");
        std::fs::create_dir_all(&commands_dir).map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to create commands dir: {}", e),
        })?;

        let mut cmd_num = 1;
        for step in steps.iter() {
            let cmd_file = commands_dir.join(format!("{:03}.cmd", cmd_num));
            let command_text = self.build_command_file(step)?;
            std::fs::write(&cmd_file, &command_text).map_err(|e| HyprError::BuildFailed {
                reason: format!("Failed to write command file: {}", e),
            })?;
            cmd_num += 1;
        }

        // Add FINALIZE step to create tarball of all changes
        let finalize_step = BuildStep::Finalize { layer_id: layer_id.clone() };
        let finalize_file = commands_dir.join(format!("{:03}.cmd", cmd_num));
        let finalize_cmd = self.build_command_file(&finalize_step)?;
        std::fs::write(&finalize_file, &finalize_cmd).map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to write finalize command: {}", e),
        })?;

        info!("Written {} build commands + 1 FINALIZE command", steps.len());

        // Boot VM ONCE
        let (vm, mut child) = self.spawn_builder_vm(context_dir, output_dir, base_rootfs).await?;

        // Stream logs in real-time WHILE VM runs
        let log_path = PathBuf::from(format!("/tmp/hypr-vm-{}.log", vm.id));

        // Run streaming and VM concurrently
        let stream_task = tokio::spawn({
            let log_path = log_path.clone();
            async move {
                let mut s = BuildOutputStream::new();
                s.stream_from_file(&log_path).await
            }
        });

        // Wait for VM to finish OR handle Ctrl+C
        let _vm_result = tokio::select! {
            result = child.wait() => {
                result.map_err(|e| HyprError::BuildFailed { reason: format!("VM wait failed: {}", e) })?
            }
            _ = tokio::signal::ctrl_c() => {
                // User pressed Ctrl+C - kill the VM and clean up
                info!("Received SIGINT, shutting down build VM");
                let _ = child.start_kill();
                let _ = child.wait().await; // Wait for it to die

                // Clean up any adapter-managed resources (e.g., virtiofsd on Linux)
                if let Err(e) = self.adapter.delete(&vm).await {
                    warn!("Failed to clean up VM resources: {}", e);
                }

                return Err(HyprError::BuildFailed {
                    reason: "Build cancelled by user".to_string()
                });
            }
        };

        // Wait for streaming to complete (should finish shortly after VM exits)
        let _results = stream_task.await
            .map_err(|e| HyprError::BuildFailed { reason: format!("Stream task failed: {}", e) })??;

        // Check if layer tarball was created
        if !layer_path.exists() {
            return Err(HyprError::BuildFailed {
                reason: format!("Layer tarball not created at {}", layer_path.display()),
            });
        }

        let metadata = tokio::fs::metadata(&layer_path).await.map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to read layer metadata: {}", e) }
        })?;

        info!("Layer extracted: {} ({} bytes)", layer_path.display(), metadata.len());

        Ok(vec![BuildLayerInfo {
            size_bytes: metadata.len(),
            layer_hash: format!("sha256:{}", layer_id),
        }])
    }
}

/// Build step types.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        /// Layer ID
        layer_id: String,
    },
}

impl BuildStep {
    pub fn step_type(&self) -> &str {
        match self {
            BuildStep::Run { .. } => "RUN",
            BuildStep::Finalize { .. } => "FINALIZE",
        }
    }
}

/// Build layer metadata.
#[derive(Debug, Clone)]
pub struct BuildLayerInfo {
    pub size_bytes: u64,
    pub layer_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_command_file_run() {
        #[cfg(target_os = "macos")]
        let adapter: Box<dyn crate::adapters::VmmAdapter> =
            Box::new(crate::adapters::hvf::HvfAdapter::new().unwrap());

        #[cfg(target_os = "linux")]
        let adapter: Box<dyn crate::adapters::VmmAdapter> =
            Box::new(crate::adapters::cloudhypervisor::CloudHypervisorAdapter::new().unwrap());

        let builder = VmBuilder {
            adapter,
            kernel_path: PathBuf::from("/tmp/vmlinuz"),
            _work_dir: PathBuf::from("/tmp"),
            initramfs_cache: None,
        };

        let step =
            BuildStep::Run { command: "echo hello".to_string(), workdir: "/app".to_string() };

        let content = builder.build_command_file(&step).unwrap();
        // Kestrel expects: "RUN {workdir}\n{command}"
        assert_eq!(content, "RUN /app\necho hello");
    }

    #[test]
    fn test_build_command_file_finalize() {
        #[cfg(target_os = "macos")]
        let adapter: Box<dyn crate::adapters::VmmAdapter> =
            Box::new(crate::adapters::hvf::HvfAdapter::new().unwrap());

        #[cfg(target_os = "linux")]
        let adapter: Box<dyn crate::adapters::VmmAdapter> =
            Box::new(crate::adapters::cloudhypervisor::CloudHypervisorAdapter::new().unwrap());

        let builder = VmBuilder {
            adapter,
            kernel_path: PathBuf::from("/tmp/vmlinuz"),
            _work_dir: PathBuf::from("/tmp"),
            initramfs_cache: None,
        };

        let step = BuildStep::Finalize { layer_id: "abc123".to_string() };

        let content = builder.build_command_file(&step).unwrap();
        // Kestrel expects: "FINALIZE {layer_id}"
        assert_eq!(content, "FINALIZE abc123");
    }
}
