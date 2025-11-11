#[cfg(test)]
mod tests {
    use crate::error::HyprError;
    use crate::network::port::PortMapping;
    use crate::state::StateManager;
    use crate::types::network::Protocol;
    use crate::types::{NetworkConfig, Vm, VmConfig, VmResources, VmStatus};
    use std::net::Ipv4Addr;
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
                id: "vm-test-123".to_string(),
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
                vsock_path: "/run/hypr/test.sock".into(),
            },
            ip_address: Some("100.64.0.5".to_string()),
            pid: Some(12345),
            vsock_path: Some("/run/hypr/test.sock".into()),
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
                    vsock_path: "/run/hypr/test.sock".into(),
                },
                ip_address: Some(format!("100.64.0.{}", i)),
                pid: Some(10000 + i),
                vsock_path: Some(format!("/run/hypr/vm-{}.sock", i).into()),
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
                vsock_path: "/run/hypr/test.sock".into(),
            },
            ip_address: None,
            pid: None,
            vsock_path: None,
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
                vsock_path: "/run/hypr/test.sock".into(),
            },
            ip_address: None,
            pid: None,
            vsock_path: None,
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

    // Port mapping tests

    #[tokio::test]
    #[ignore = "Port mapping StateManager methods not yet implemented"]
    async fn test_insert_and_list_port_mappings() {
        let manager = StateManager::new_in_memory().await.unwrap();

        let mapping1 = PortMapping::new(8080, Ipv4Addr::new(100, 64, 0, 10), 80, Protocol::Tcp);

        let mapping2 = PortMapping::with_vm_id(
            8443,
            Ipv4Addr::new(100, 64, 0, 11),
            443,
            Protocol::Tcp,
            "vm-123".to_string(),
        );

        // Insert mappings
        manager.insert_port_mapping(&mapping1).await.unwrap();
        manager.insert_port_mapping(&mapping2).await.unwrap();

        // List all mappings
        let mappings = manager.list_port_mappings().await.unwrap();
        assert_eq!(mappings.len(), 2);
    }

    #[tokio::test]
    #[ignore = "Port mapping StateManager methods not yet implemented"]
    async fn test_get_vm_port_mappings() {
        let manager = StateManager::new_in_memory().await.unwrap();

        let mapping1 = PortMapping::with_vm_id(
            8080,
            Ipv4Addr::new(100, 64, 0, 10),
            80,
            Protocol::Tcp,
            "vm-123".to_string(),
        );

        let mapping2 = PortMapping::with_vm_id(
            8443,
            Ipv4Addr::new(100, 64, 0, 10),
            443,
            Protocol::Tcp,
            "vm-123".to_string(),
        );

        let mapping3 = PortMapping::with_vm_id(
            9090,
            Ipv4Addr::new(100, 64, 0, 11),
            90,
            Protocol::Tcp,
            "vm-456".to_string(),
        );

        // Insert mappings
        manager.insert_port_mapping(&mapping1).await.unwrap();
        manager.insert_port_mapping(&mapping2).await.unwrap();
        manager.insert_port_mapping(&mapping3).await.unwrap();

        // Get mappings for vm-123
        let vm_mappings = manager.get_vm_port_mappings("vm-123").await.unwrap();
        assert_eq!(vm_mappings.len(), 2);

        // Get mappings for vm-456
        let vm_mappings = manager.get_vm_port_mappings("vm-456").await.unwrap();
        assert_eq!(vm_mappings.len(), 1);
    }

    #[tokio::test]
    #[ignore = "Port mapping StateManager methods not yet implemented"]
    async fn test_delete_port_mapping() {
        let manager = StateManager::new_in_memory().await.unwrap();

        let mapping = PortMapping::new(8080, Ipv4Addr::new(100, 64, 0, 10), 80, Protocol::Tcp);

        // Insert
        manager.insert_port_mapping(&mapping).await.unwrap();

        // Verify it exists
        let mappings = manager.list_port_mappings().await.unwrap();
        assert_eq!(mappings.len(), 1);

        // Delete
        manager.delete_port_mapping(8080, Protocol::Tcp).await.unwrap();

        // Verify it's gone
        let mappings = manager.list_port_mappings().await.unwrap();
        assert_eq!(mappings.len(), 0);
    }

    #[tokio::test]
    #[ignore = "Port mapping StateManager methods not yet implemented"]
    async fn test_delete_vm_port_mappings() {
        let manager = StateManager::new_in_memory().await.unwrap();

        let mapping1 = PortMapping::with_vm_id(
            8080,
            Ipv4Addr::new(100, 64, 0, 10),
            80,
            Protocol::Tcp,
            "vm-123".to_string(),
        );

        let mapping2 = PortMapping::with_vm_id(
            8443,
            Ipv4Addr::new(100, 64, 0, 10),
            443,
            Protocol::Tcp,
            "vm-123".to_string(),
        );

        let mapping3 = PortMapping::with_vm_id(
            9090,
            Ipv4Addr::new(100, 64, 0, 11),
            90,
            Protocol::Tcp,
            "vm-456".to_string(),
        );

        // Insert mappings
        manager.insert_port_mapping(&mapping1).await.unwrap();
        manager.insert_port_mapping(&mapping2).await.unwrap();
        manager.insert_port_mapping(&mapping3).await.unwrap();

        // Delete all mappings for vm-123
        manager.delete_vm_port_mappings("vm-123").await.unwrap();

        // Verify vm-123 mappings are gone
        let vm_mappings = manager.get_vm_port_mappings("vm-123").await.unwrap();
        assert_eq!(vm_mappings.len(), 0);

        // Verify vm-456 mapping still exists
        let vm_mappings = manager.get_vm_port_mappings("vm-456").await.unwrap();
        assert_eq!(vm_mappings.len(), 1);
    }

    #[tokio::test]
    #[ignore = "Port mapping StateManager methods not yet implemented"]
    async fn test_port_mapping_persistence() {
        // Create a temp file for the database
        let db_path = std::env::temp_dir().join(format!("hypr-test-{}.db", uuid::Uuid::new_v4()));

        {
            let manager = StateManager::new(&db_path).await.unwrap();

            let mapping = PortMapping::with_vm_id(
                8080,
                Ipv4Addr::new(100, 64, 0, 10),
                80,
                Protocol::Tcp,
                "vm-123".to_string(),
            );

            manager.insert_port_mapping(&mapping).await.unwrap();
        }

        // Reopen database
        {
            let manager = StateManager::new(&db_path).await.unwrap();
            let mappings = manager.list_port_mappings().await.unwrap();
            assert_eq!(mappings.len(), 1);
            assert_eq!(mappings[0].host_port, 8080);
            assert_eq!(mappings[0].vm_id, Some("vm-123".to_string()));
        }

        // Cleanup
        let _ = std::fs::remove_file(&db_path);
    }
}
