//! Integration tests for VM lifecycle operations.
//!
//! These tests verify the full VM lifecycle:
//! - Create VM
//! - Start VM
//! - Stop VM
//! - Delete VM
//!
//! Tests use an in-memory database and mock adapter for portability.

use hypr_core::{
    adapters::{AdapterCapabilities, VmmAdapter},
    error::{HyprError, Result},
    types::{
        network::NetworkConfig,
        vm::{CommandSpec, DiskConfig, GpuConfig, VmConfig, VmHandle, VmResources, VmStatus},
        Vm,
    },
    StateManager,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

/// Mock adapter for testing (doesn't require actual hypervisor).
#[derive(Clone)]
struct MockAdapter {
    capabilities: AdapterCapabilities,
    /// Temp directory for socket paths (avoids hardcoded /tmp paths)
    temp_dir: PathBuf,
}

impl MockAdapter {
    fn new(temp_dir: &TempDir) -> Self {
        Self {
            capabilities: AdapterCapabilities {
                gpu_passthrough: false,
                virtio_fs: true,
                hotplug_devices: false,
                metadata: HashMap::new(),
            },
            temp_dir: temp_dir.path().to_path_buf(),
        }
    }
}

#[async_trait::async_trait]
impl VmmAdapter for MockAdapter {
    async fn build_command(&self, _config: &VmConfig) -> Result<CommandSpec> {
        // Mock: Return dummy command spec
        Ok(CommandSpec { program: "true".to_string(), args: vec![], env: vec![] })
    }

    async fn create(&self, config: &VmConfig) -> Result<VmHandle> {
        // Mock: Return handle without actually spawning VM
        Ok(VmHandle {
            id: config.id.clone(),
            pid: Some(12345),
            socket_path: Some(self.temp_dir.join("mock.sock")),
        })
    }

    async fn start(&self, _handle: &VmHandle) -> Result<()> {
        // Mock: Simulate successful start
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }

    async fn stop(&self, _handle: &VmHandle, _timeout: Duration) -> Result<()> {
        // Mock: Simulate successful stop
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }

    async fn kill(&self, _handle: &VmHandle) -> Result<()> {
        // Mock: Simulate successful kill
        Ok(())
    }

    async fn delete(&self, _handle: &VmHandle) -> Result<()> {
        // Mock: Simulate successful delete
        Ok(())
    }

    async fn attach_disk(&self, _handle: &VmHandle, _disk: &DiskConfig) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "disk hotplug".to_string(),
            platform: "mock".to_string(),
        })
    }

    async fn attach_network(&self, _handle: &VmHandle, _net: &NetworkConfig) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "network hotplug".to_string(),
            platform: "mock".to_string(),
        })
    }

    async fn attach_gpu(&self, _handle: &VmHandle, _gpu: &GpuConfig) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "GPU".to_string(),
            platform: "mock".to_string(),
        })
    }

    fn vsock_path(&self, handle: &VmHandle) -> PathBuf {
        self.temp_dir.join(format!("mock-{}.vsock", handle.id))
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.capabilities.clone()
    }

    fn name(&self) -> &str {
        "mock"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[tokio::test]
async fn test_vm_lifecycle_create_start_stop_delete() {
    // Create temp directory for test artifacts (avoids /tmp collisions in CI)
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Initialize state manager with in-memory database
    let state = StateManager::new_in_memory().await.expect("Failed to create state manager");

    let adapter = Arc::new(MockAdapter::new(&temp_dir));

    // Create VM configuration
    let config = VmConfig {
        network_enabled: true,
        id: "test-vm-1".to_string(),
        name: "test-vm".to_string(),
        resources: VmResources { cpus: 2, memory_mb: 512, balloon_enabled: true },
        kernel_path: Some(temp_dir.path().join("vmlinux")),
        kernel_args: vec!["console=ttyS0".to_string()],
        initramfs_path: None,
        disks: vec![],
        network: NetworkConfig {
            network: "default".to_string(),
            ip_address: None,
            mac_address: Some("52:54:00:12:34:56".to_string()),
            dns_servers: vec![],
        },
        ports: vec![],
        env: HashMap::new(),
        volumes: vec![],
        virtio_fs_mounts: vec![],
        gpu: None,
    };

    // Step 1: Create VM
    let handle = adapter.create(&config).await.expect("Failed to create VM");

    assert_eq!(handle.id, "test-vm-1");
    assert!(handle.pid.is_some());

    // Insert VM state
    let vm = Vm {
        id: config.id.clone(),
        name: config.name.clone(),
        image_id: "test-image".to_string(),
        status: VmStatus::Creating,
        config: config.clone(),
        ip_address: None,
        pid: handle.pid,
        created_at: SystemTime::now(),
        started_at: None,
        stopped_at: None,
    };

    state.insert_vm(&vm).await.expect("Failed to insert VM");

    // Verify VM exists in state
    let retrieved_vm = state.get_vm("test-vm-1").await.expect("Failed to get VM");
    assert_eq!(retrieved_vm.id, "test-vm-1");
    assert_eq!(retrieved_vm.name, "test-vm");
    assert_eq!(retrieved_vm.status, VmStatus::Creating);

    // Step 2: Start VM
    adapter.start(&handle).await.expect("Failed to start VM");

    // Update status to Running
    state.update_vm_status("test-vm-1", VmStatus::Running).await.expect("Failed to update status");

    let running_vm = state.get_vm("test-vm-1").await.expect("Failed to get VM");
    assert_eq!(running_vm.status, VmStatus::Running);

    // Step 3: Stop VM
    adapter.stop(&handle, Duration::from_secs(5)).await.expect("Failed to stop VM");

    // Update status to Stopped
    state.update_vm_status("test-vm-1", VmStatus::Stopped).await.expect("Failed to update status");

    let stopped_vm = state.get_vm("test-vm-1").await.expect("Failed to get VM");
    assert_eq!(stopped_vm.status, VmStatus::Stopped);

    // Step 4: Delete VM
    adapter.delete(&handle).await.expect("Failed to delete VM");

    state.delete_vm("test-vm-1").await.expect("Failed to delete VM from state");

    // Verify VM no longer exists
    let result = state.get_vm("test-vm-1").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), HyprError::VmNotFound { .. }));
}

#[tokio::test]
async fn test_state_persistence_across_sessions() {
    // Create temp directory for test artifacts
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("hypr-test-persistence.db");

    // Session 1: Create VM and persist
    {
        let state = StateManager::new(&db_path).await.expect("Failed to create state manager");

        let config = VmConfig {
            network_enabled: true,
            id: "persistent-vm".to_string(),
            name: "test-persistent".to_string(),
            resources: VmResources { cpus: 1, memory_mb: 256, balloon_enabled: true },
            kernel_path: Some(temp_dir.path().join("vmlinux")),
            kernel_args: vec![],
            initramfs_path: None,
            disks: vec![],
            network: NetworkConfig {
                network: "default".to_string(),
                ip_address: None,
                mac_address: Some("52:54:00:AB:CD:EF".to_string()),
                dns_servers: vec![],
            },
            ports: vec![],
            env: HashMap::new(),
            volumes: vec![],
            virtio_fs_mounts: vec![],
            gpu: None,
        };

        let vm = Vm {
            id: config.id.clone(),
            name: config.name.clone(),
            image_id: "alpine:latest".to_string(),
            status: VmStatus::Running,
            config,
            ip_address: Some("10.88.0.5".to_string()),
            pid: Some(99999),
            created_at: SystemTime::now(),
            started_at: Some(SystemTime::now()),
            stopped_at: None,
        };

        state.insert_vm(&vm).await.expect("Failed to insert VM");

        // Verify insertion
        let retrieved = state.get_vm("persistent-vm").await.expect("Failed to get VM");
        assert_eq!(retrieved.name, "test-persistent");
    }
    // StateManager dropped here, database connection closed

    // Session 2: Reopen database and verify VM still exists
    {
        let state = StateManager::new(&db_path).await.expect("Failed to reopen state manager");

        // VM should still exist
        let vm = state.get_vm("persistent-vm").await.expect("VM should persist across sessions");

        assert_eq!(vm.id, "persistent-vm");
        assert_eq!(vm.name, "test-persistent");
        assert_eq!(vm.image_id, "alpine:latest");
        assert_eq!(vm.status, VmStatus::Running);
        assert_eq!(vm.ip_address, Some("10.88.0.5".to_string()));

        // List all VMs
        let vms = state.list_vms().await.expect("Failed to list VMs");
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].id, "persistent-vm");

        // Clean up
        state.delete_vm("persistent-vm").await.expect("Failed to delete VM");
    }

    // temp_dir is automatically cleaned up when it goes out of scope
}

#[tokio::test]
async fn test_multiple_vms_concurrent_operations() {
    // Create temp directory for test artifacts
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let state = StateManager::new_in_memory().await.expect("Failed to create state manager");

    let adapter = Arc::new(MockAdapter::new(&temp_dir));

    // Create multiple VMs
    let vm_ids = vec!["vm-1", "vm-2", "vm-3"];

    for vm_id in &vm_ids {
        let config = VmConfig {
            network_enabled: true,
            id: vm_id.to_string(),
            name: format!("test-{}", vm_id),
            resources: VmResources { cpus: 1, memory_mb: 128, balloon_enabled: true },
            kernel_path: Some(temp_dir.path().join("vmlinux")),
            kernel_args: vec![],
            initramfs_path: None,
            disks: vec![],
            network: NetworkConfig {
                network: "default".to_string(),
                ip_address: None,
                mac_address: None,
                dns_servers: vec![],
            },
            ports: vec![],
            env: HashMap::new(),
            volumes: vec![],
            virtio_fs_mounts: vec![],
            gpu: None,
        };

        let handle = adapter.create(&config).await.expect("Failed to create VM");

        let vm = Vm {
            id: config.id.clone(),
            name: config.name.clone(),
            image_id: "test-image".to_string(),
            status: VmStatus::Running,
            config,
            ip_address: None,
            pid: handle.pid,
            created_at: SystemTime::now(),
            started_at: Some(SystemTime::now()),
            stopped_at: None,
        };

        state.insert_vm(&vm).await.expect("Failed to insert VM");
    }

    // List all VMs
    let vms = state.list_vms().await.expect("Failed to list VMs");
    assert_eq!(vms.len(), 3);

    // Verify each VM exists
    for vm_id in &vm_ids {
        let vm = state.get_vm(vm_id).await.expect("VM should exist");
        assert_eq!(vm.id, *vm_id);
        assert_eq!(vm.status, VmStatus::Running);
    }

    // Delete all VMs
    for vm_id in &vm_ids {
        state.delete_vm(vm_id).await.expect("Failed to delete VM");
    }

    // Verify all deleted
    let vms = state.list_vms().await.expect("Failed to list VMs");
    assert_eq!(vms.len(), 0);
}
