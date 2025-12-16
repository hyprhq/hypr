#[cfg(test)]
mod state_tests {
    use crate::error::HyprError;
    use crate::state::StateManager;
    use crate::types::{NetworkConfig, Vm, VmConfig, VmResources, VmStatus};
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_state_manager_init() {
        let manager = StateManager::new_in_memory().await.unwrap();
        // Should succeed without errors
        drop(manager);
    }

    #[tokio::test]
    async fn test_insert_and_get_vm() {
        let manager = StateManager::new_in_memory().await.unwrap();

        let vm = Vm {
            id: "vm-test-123".to_string(),
            name: "test-vm".to_string(),
            image_id: "image-123".to_string(),
            status: VmStatus::Creating,
            config: VmConfig {
                network_enabled: true,
                id: "vm-test-123".to_string(),
                name: "test-vm".to_string(),
                resources: VmResources::default(),
                kernel_path: None,
                kernel_args: vec![],
                initramfs_path: None,
                disks: vec![],
                network: NetworkConfig::default(),
                ports: vec![],
                env: Default::default(),
                volumes: vec![],
                gpu: None,
                virtio_fs_mounts: vec![],
            },
            ip_address: Some("10.88.0.5".to_string()),
            pid: Some(12345),
            created_at: SystemTime::now(),
            started_at: None,
            stopped_at: None,
        };

        // Insert
        manager.insert_vm(&vm).await.unwrap();

        // Get
        let retrieved = manager.get_vm("vm-test-123").await.unwrap();
        assert_eq!(retrieved.id, vm.id);
        assert_eq!(retrieved.name, vm.name);
        assert_eq!(retrieved.status, VmStatus::Creating);
    }

    #[tokio::test]
    async fn test_list_vms() {
        let manager = StateManager::new_in_memory().await.unwrap();

        // Initially empty
        let vms = manager.list_vms().await.unwrap();
        assert_eq!(vms.len(), 0);

        // Insert two VMs
        for i in 1..=2 {
            let vm = Vm {
                id: format!("vm-{}", i),
                name: format!("test-vm-{}", i),
                image_id: "image-123".to_string(),
                status: VmStatus::Running,
                config: VmConfig {
                    network_enabled: true,
                    id: format!("vm-{}", i),
                    name: format!("test-vm-{}", i),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: Default::default(),
                    volumes: vec![],
                    gpu: None,
                    initramfs_path: None,
                    virtio_fs_mounts: vec![],
                },
                ip_address: Some(format!("10.88.0.{}", i)),
                pid: Some(10000 + i),
                created_at: SystemTime::now(),
                started_at: Some(SystemTime::now()),
                stopped_at: None,
            };
            manager.insert_vm(&vm).await.unwrap();
        }

        // List should return 2
        let vms = manager.list_vms().await.unwrap();
        assert_eq!(vms.len(), 2);
    }

    #[tokio::test]
    async fn test_update_vm_status() {
        let manager = StateManager::new_in_memory().await.unwrap();

        let vm = Vm {
            id: "vm-test-456".to_string(),
            name: "test-vm".to_string(),
            image_id: "image-123".to_string(),
            status: VmStatus::Creating,
            config: VmConfig {
                network_enabled: true,
                id: "vm-test-456".to_string(),
                name: "test-vm".to_string(),
                resources: VmResources::default(),
                kernel_path: None,
                kernel_args: vec![],
                disks: vec![],
                network: NetworkConfig::default(),
                ports: vec![],
                env: Default::default(),
                volumes: vec![],
                gpu: None,
                initramfs_path: None,
                virtio_fs_mounts: vec![],
            },
            ip_address: None,
            pid: None,
            created_at: SystemTime::now(),
            started_at: None,
            stopped_at: None,
        };

        manager.insert_vm(&vm).await.unwrap();

        // Update status
        manager.update_vm_status("vm-test-456", VmStatus::Running).await.unwrap();

        // Verify update
        let updated = manager.get_vm("vm-test-456").await.unwrap();
        assert_eq!(updated.status, VmStatus::Running);
    }

    #[tokio::test]
    async fn test_delete_vm() {
        let manager = StateManager::new_in_memory().await.unwrap();

        let vm = Vm {
            id: "vm-test-789".to_string(),
            name: "test-vm".to_string(),
            image_id: "image-123".to_string(),
            status: VmStatus::Stopped,
            config: VmConfig {
                network_enabled: true,
                id: "vm-test-789".to_string(),
                name: "test-vm".to_string(),
                resources: VmResources::default(),
                kernel_path: None,
                kernel_args: vec![],
                disks: vec![],
                network: NetworkConfig::default(),
                ports: vec![],
                env: Default::default(),
                volumes: vec![],
                gpu: None,
                initramfs_path: None,
                virtio_fs_mounts: vec![],
            },
            ip_address: None,
            pid: None,
            created_at: SystemTime::now(),
            started_at: None,
            stopped_at: Some(SystemTime::now()),
        };

        manager.insert_vm(&vm).await.unwrap();
        manager.delete_vm("vm-test-789").await.unwrap();

        // Verify deletion
        let result = manager.get_vm("vm-test-789").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_vm_not_found() {
        let manager = StateManager::new_in_memory().await.unwrap();

        let result = manager.get_vm("nonexistent-vm").await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, HyprError::VmNotFound { .. }));
        }
    }

    // Note: Port mapping is now handled dynamically by gvproxy via HTTP API,
    // not persisted in the state manager. Port forwarding tests are in
    // the network/gvproxy module.
}
