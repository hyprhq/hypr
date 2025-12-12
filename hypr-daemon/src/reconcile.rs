//! State reconciliation for hyprd.
//!
//! On daemon startup, reconciles the database state with actual system state.
//! This handles cases where the daemon crashed or was killed without proper shutdown.

use hypr_core::adapters::VmmAdapter;
use hypr_core::{StateManager, VmStatus};
use std::sync::Arc;
use tracing::{info, warn};

use crate::network_manager::NetworkManager;

/// Reconciles daemon state on startup.
pub struct StateReconciler {
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
    network_mgr: Arc<NetworkManager>,
}

impl StateReconciler {
    /// Create a new state reconciler.
    pub fn new(
        state: Arc<StateManager>,
        adapter: Arc<dyn VmmAdapter>,
        network_mgr: Arc<NetworkManager>,
    ) -> Self {
        Self { state, adapter, network_mgr }
    }

    /// Reconcile database state with actual system state.
    ///
    /// This method:
    /// 1. Finds VMs marked as RUNNING in the database
    /// 2. Checks if their processes are still alive
    /// 3. Updates status to FAILED/STOPPED for dead processes
    /// 4. Cleans up orphaned resources (TAP devices, port forwards)
    /// 5. Rebuilds port forwarding rules for alive VMs
    pub async fn reconcile(
        &self,
    ) -> Result<ReconcileReport, Box<dyn std::error::Error + Send + Sync>> {
        info!("Reconciling daemon state...");

        let mut report = ReconcileReport::default();

        // Get all VMs from database
        let vms = self.state.list_vms().await?;

        for vm in vms {
            match vm.status {
                VmStatus::Running | VmStatus::Creating => {
                    // Check if process is still alive
                    let is_alive =
                        if let Some(pid) = vm.pid { is_process_alive(pid) } else { false };

                    if is_alive {
                        info!(
                            "VM {} ({}) is still running (PID {})",
                            vm.name,
                            vm.id,
                            vm.pid.unwrap_or(0)
                        );
                        report.running += 1;

                        // Rebuild port forwarding for this VM
                        if let Some(ip_str) = &vm.ip_address {
                            if let Ok(ip) = ip_str.parse() {
                                for port_cfg in &vm.config.ports {
                                    if let Err(e) = self
                                        .network_mgr
                                        .add_port_forward(
                                            port_cfg.host_port,
                                            ip,
                                            port_cfg.vm_port,
                                            port_cfg.protocol,
                                            vm.id.clone(),
                                        )
                                        .await
                                    {
                                        warn!(
                                            "Failed to rebuild port forward for VM {}: {}",
                                            vm.name, e
                                        );
                                    }
                                }

                                // Rebuild DNS entry
                                let service_name =
                                    if !vm.name.is_empty() { &vm.name } else { &vm.id };
                                let ports: Vec<_> = vm
                                    .config
                                    .ports
                                    .iter()
                                    .map(|p| (p.vm_port, p.protocol))
                                    .collect();

                                if let Err(e) =
                                    self.network_mgr.register_service(service_name, ip, ports).await
                                {
                                    warn!("Failed to rebuild DNS for VM {}: {}", vm.name, e);
                                }
                            }
                        }
                    } else {
                        // Process is dead - update state and clean up
                        warn!(
                            "VM {} ({}) was marked as running but process is dead",
                            vm.name, vm.id
                        );
                        report.orphaned += 1;

                        // Update status to Failed
                        if let Err(e) = self.state.update_vm_status(&vm.id, VmStatus::Failed).await
                        {
                            warn!("Failed to update VM {} status: {}", vm.name, e);
                        }

                        // Clean up resources
                        self.cleanup_vm_resources(&vm).await;
                    }
                }
                VmStatus::Stopped | VmStatus::Failed | VmStatus::Deleting => {
                    // Make sure no stale resources remain
                    self.cleanup_vm_resources(&vm).await;
                    report.stopped += 1;
                }
            }
        }

        // Clean up orphaned TAP devices
        #[cfg(target_os = "linux")]
        {
            if let Ok(orphaned) = cleanup_orphaned_tap_devices(&self.state).await {
                report.orphaned_taps = orphaned;
            }
        }

        // Clean up orphaned VFIO bindings
        #[cfg(target_os = "linux")]
        {
            if let Ok(orphaned) = cleanup_orphaned_vfio_bindings(&self.state).await {
                report.orphaned_vfio = orphaned;
            }
        }

        // Clean up orphaned virtiofsd processes
        #[cfg(target_os = "linux")]
        {
            if let Ok(orphaned) = cleanup_orphaned_virtiofsd(&self.state).await {
                report.orphaned_virtiofsd = orphaned;
            }
        }

        info!(
            "Reconciliation complete: {} running, {} stopped, {} orphaned",
            report.running, report.stopped, report.orphaned
        );

        Ok(report)
    }

    /// Clean up resources for a VM that's no longer running.
    async fn cleanup_vm_resources(&self, vm: &hypr_core::Vm) {
        // Remove port forwards
        if let Err(e) = self.network_mgr.remove_vm_port_forwards(&vm.id).await {
            warn!("Failed to cleanup port forwards for VM {}: {}", vm.name, e);
        }

        // Unregister DNS
        let service_name = if !vm.name.is_empty() { &vm.name } else { &vm.id };
        if let Err(e) = self.network_mgr.unregister_service(service_name).await {
            warn!("Failed to cleanup DNS for VM {}: {}", vm.name, e);
        }

        // Release IP
        if let Err(e) = self.network_mgr.release_ip(&vm.id).await {
            warn!("Failed to cleanup IP for VM {}: {}", vm.name, e);
        }

        // Clean up via adapter (handles VFIO unbinding, etc.)
        let handle = hypr_core::VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };

        if let Err(e) = self.adapter.delete(&handle).await {
            // This is expected to fail if the process is dead, just log debug
            tracing::debug!("Adapter cleanup for VM {}: {}", vm.name, e);
        }
    }
}

/// Report of reconciliation actions taken.
#[derive(Default, Debug)]
pub struct ReconcileReport {
    /// Number of VMs still running
    pub running: usize,
    /// Number of VMs stopped/failed
    pub stopped: usize,
    /// Number of orphaned VMs (marked running but process dead)
    pub orphaned: usize,
    /// Number of orphaned TAP devices cleaned up
    pub orphaned_taps: usize,
    /// Number of orphaned VFIO bindings cleaned up
    pub orphaned_vfio: usize,
    /// Number of orphaned virtiofsd processes cleaned up
    pub orphaned_virtiofsd: usize,
}

/// Check if a process with the given PID is still alive.
fn is_process_alive(pid: u32) -> bool {
    // Use kill(pid, 0) to check if process exists
    // This is more reliable than parsing /proc or using ps
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Clean up TAP devices that don't correspond to running VMs.
#[cfg(target_os = "linux")]
async fn cleanup_orphaned_tap_devices(
    state: &StateManager,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    let mut cleaned = 0;

    // Get running VM IDs
    let vms = state.list_vms().await?;
    let running_vm_count = vms.iter().filter(|vm| vm.status == VmStatus::Running).count();

    // List TAP devices attached to vbr0
    let output = Command::new("ip").args(["link", "show", "master", "vbr0"]).output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse TAP device names (format: "3: tap0@vbr0: ...")
        for line in stdout.lines() {
            if let Some(name) = line.split(':').nth(1) {
                let name = name.trim().split('@').next().unwrap_or("").trim();
                if let Some(suffix) = name.strip_prefix("tap") {
                    // Extract tap number
                    if let Ok(tap_num) = suffix.parse::<usize>() {
                        // If we have more TAP devices than running VMs, delete extras
                        if tap_num >= running_vm_count {
                            info!("Cleaning up orphaned TAP device: {}", name);
                            let _ = Command::new("ip").args(["link", "del", name]).status();
                            cleaned += 1;
                        }
                    }
                }
            }
        }
    }

    if cleaned > 0 {
        info!("Cleaned up {} orphaned TAP devices", cleaned);
    }

    Ok(cleaned)
}

/// Clean up VFIO bindings for GPUs not used by running VMs.
#[cfg(target_os = "linux")]
async fn cleanup_orphaned_vfio_bindings(
    state: &StateManager,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    use std::path::Path;

    let mut cleaned = 0;

    // Get PCI addresses of GPUs used by running VMs
    let vms = state.list_vms().await?;
    let running_gpu_addresses: std::collections::HashSet<String> = vms
        .iter()
        .filter(|vm| vm.status == VmStatus::Running)
        .filter_map(|vm| vm.config.gpu.as_ref())
        .filter_map(|gpu| gpu.pci_address.clone())
        .collect();

    // Check for devices bound to vfio-pci
    let vfio_pci_path = Path::new("/sys/bus/pci/drivers/vfio-pci");
    if !vfio_pci_path.exists() {
        return Ok(0);
    }

    // List devices bound to vfio-pci
    if let Ok(entries) = std::fs::read_dir(vfio_pci_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip non-device entries
            if name_str == "bind"
                || name_str == "unbind"
                || name_str == "new_id"
                || name_str == "remove_id"
                || name_str == "module"
                || name_str == "uevent"
            {
                continue;
            }

            // Check if this is a PCI address format (0000:XX:XX.X)
            if name_str.contains(':') && name_str.contains('.') {
                // Is this GPU in use by a running VM?
                if !running_gpu_addresses.contains(name_str.as_ref()) {
                    info!("Found orphaned VFIO-bound device: {}", name_str);

                    // Try to unbind from vfio-pci
                    // Note: We don't automatically rebind to the original driver
                    // because we don't know what it was. The device will remain
                    // unbound until the user manually binds it or reboots.
                    let unbind_path = vfio_pci_path.join("unbind");
                    if let Err(e) = std::fs::write(&unbind_path, name_str.as_ref()) {
                        warn!("Failed to unbind {}: {}", name_str, e);
                    } else {
                        info!("Unbound {} from vfio-pci", name_str);
                        cleaned += 1;
                    }
                }
            }
        }
    }

    if cleaned > 0 {
        info!("Cleaned up {} orphaned VFIO bindings", cleaned);
    }

    Ok(cleaned)
}

/// Clean up virtiofsd processes that don't correspond to running VMs.
///
/// virtiofsd processes are spawned with sockets in /run/hypr/ch/{vm_id}-{tag}.sock
/// We can identify orphaned ones by checking if the socket's VM ID has a running process.
#[cfg(target_os = "linux")]
async fn cleanup_orphaned_virtiofsd(
    state: &StateManager,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    let mut cleaned = 0;

    // Get running VM IDs
    let vms = state.list_vms().await?;
    let running_vm_ids: std::collections::HashSet<String> = vms
        .iter()
        .filter(|vm| vm.status == VmStatus::Running)
        .map(|vm| vm.id.clone())
        .collect();

    // Find virtiofsd processes using pgrep
    let output = Command::new("pgrep").args(["-f", "virtiofsd"]).output();

    if let Ok(output) = output {
        if !output.status.success() {
            // No virtiofsd processes found
            return Ok(0);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for pid_str in stdout.lines() {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                // Get the command line to extract the socket path
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                    // cmdline is null-separated
                    let args: Vec<&str> = cmdline.split('\0').collect();

                    // Look for --socket-path argument
                    let mut socket_path = None;
                    let mut next_is_socket = false;
                    for arg in &args {
                        if next_is_socket {
                            socket_path = Some(*arg);
                            break;
                        }
                        if arg.starts_with("--socket-path=") {
                            socket_path = arg.strip_prefix("--socket-path=");
                            break;
                        }
                        if *arg == "--socket-path" {
                            next_is_socket = true;
                        }
                    }

                    if let Some(socket) = socket_path {
                        // Socket format: /run/hypr/ch/{vm_id}-{tag}.sock
                        // Extract VM ID from socket path
                        if let Some(filename) = std::path::Path::new(socket).file_name() {
                            let name = filename.to_string_lossy();
                            // Extract VM ID (everything before the first hyphen-word-dot pattern)
                            if let Some(vm_id) = extract_vm_id_from_socket(&name) {
                                if !running_vm_ids.contains(&vm_id) {
                                    info!(
                                        "Killing orphaned virtiofsd process: PID={}, socket={}",
                                        pid, socket
                                    );

                                    // Send SIGTERM
                                    let _ = Command::new("kill")
                                        .args(["-TERM", &pid.to_string()])
                                        .status();

                                    // Remove socket file
                                    let _ = std::fs::remove_file(socket);

                                    cleaned += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if cleaned > 0 {
        info!("Cleaned up {} orphaned virtiofsd processes", cleaned);
    }

    Ok(cleaned)
}

/// Extract VM ID from a virtiofsd socket filename.
///
/// Socket format: {vm_id}-{tag}.sock
/// VM IDs are typically UUIDs (36 chars with hyphens) but we handle any format.
#[cfg(target_os = "linux")]
fn extract_vm_id_from_socket(filename: &str) -> Option<String> {
    // Remove .sock extension
    let name = filename.strip_suffix(".sock").unwrap_or(filename);

    // Find the last hyphen that separates VM ID from tag
    // The tag is typically a short name like "shared" or "data"
    // while VM ID is a UUID like "abc123de-f456-7890-abcd-ef1234567890"
    //
    // Strategy: If the name looks like a UUID-tag pattern, extract the UUID part
    // UUID format: 8-4-4-4-12 hex chars = 36 chars
    if name.len() > 36 {
        // Check if first 36 chars could be a UUID
        let potential_uuid = &name[..36];
        if is_uuid_format(potential_uuid) {
            return Some(potential_uuid.to_string());
        }
    }

    // Fallback: return everything before the last hyphen
    // This handles both UUID and non-UUID VM IDs
    if let Some(pos) = name.rfind('-') {
        return Some(name[..pos].to_string());
    }

    None
}

/// Check if a string looks like a UUID format.
#[cfg(target_os = "linux")]
fn is_uuid_format(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }

    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != '-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}
