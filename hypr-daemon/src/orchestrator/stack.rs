//! Stack orchestration for multi-VM deployments.
//!
//! Provides high-level orchestration for deploying and managing stacks of VMs
//! from docker-compose files, including dependency resolution, network setup,
//! and lifecycle management.

use hypr_core::adapters::VmmAdapter;
use hypr_core::compose::{ComposeConverter, ComposeParser};
use hypr_core::registry::ImagePuller;
use hypr_core::types::vm::{DiskConfig, DiskFormat};
use hypr_core::{
    HyprError, Result, ServiceConfig, StackConfig, StateManager, Vm, VmHandle, VmStatus,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{error, info, instrument, warn};

/// State of a stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackState {
    /// Stack is being deployed.
    Deploying,
    /// Stack is fully running.
    Running,
    /// Stack deployment failed.
    Failed,
    /// Stack is stopped.
    Stopped,
    /// Stack is partially running.
    Partial,
}

/// Information about a service within a stack.
#[derive(Debug, Clone)]
pub struct ServiceStatus {
    /// Service name.
    pub name: String,
    /// VM ID for this service.
    pub vm_id: String,
    /// Current status.
    pub status: VmStatus,
    /// IP address assigned to this service.
    pub ip: Option<IpAddr>,
}

/// Information about a deployed stack.
#[derive(Debug, Clone)]
pub struct StackInfo {
    /// Stack ID (UUID).
    pub id: String,
    /// Stack name from compose file.
    pub name: String,
    /// Services in this stack.
    pub services: Vec<ServiceStatus>,
    /// Stack creation time.
    pub created_at: SystemTime,
    /// Overall stack state.
    pub state: StackState,
}

/// Simple IP allocator for stack VMs.
struct SimpleIpAllocator {
    next_ip: u32,
    allocated: HashMap<String, IpAddr>,
}

impl SimpleIpAllocator {
    fn new() -> Self {
        // Start from 10.88.0.2 (10.88.0.1 is gateway)
        Self { next_ip: 0x0A580002, allocated: HashMap::new() }
    }

    fn allocate(&mut self, vm_id: String) -> IpAddr {
        let ip_num = self.next_ip;
        self.next_ip += 1;

        let ip = IpAddr::V4(std::net::Ipv4Addr::from(ip_num));
        self.allocated.insert(vm_id, ip);
        ip
    }

    fn release(&mut self, vm_id: &str) {
        self.allocated.remove(vm_id);
    }
}

/// Stack orchestrator for managing multi-VM stacks.
pub struct StackOrchestrator {
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
    ip_allocator: tokio::sync::Mutex<SimpleIpAllocator>,
    stacks: tokio::sync::RwLock<HashMap<String, StackInfo>>,
}

impl StackOrchestrator {
    /// Create a new stack orchestrator.
    pub fn new(state: Arc<StateManager>, adapter: Arc<dyn VmmAdapter>) -> Self {
        Self {
            state,
            adapter,
            ip_allocator: tokio::sync::Mutex::new(SimpleIpAllocator::new()),
            stacks: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Deploy a stack from a docker-compose file.
    #[instrument(skip(self, compose_file_path), fields(path = %compose_file_path.as_ref().display()))]
    pub async fn deploy_stack(
        &self,
        compose_file_path: impl AsRef<Path> + std::fmt::Debug,
        stack_name: Option<String>,
        build: bool,
    ) -> Result<String> {
        info!("Deploying stack from compose file (build={})", build);

        let compose_path = compose_file_path.as_ref().to_path_buf();
        let compose_dir = compose_path.parent().unwrap_or(Path::new(".")).to_path_buf();

        // Parse compose file
        let compose = ComposeParser::parse_file(&compose_path)
            .map_err(|e| HyprError::Internal(format!("Failed to parse compose file: {}", e)))?;

        // Convert to stack config - use async version to build images if needed
        let stack_config =
            ComposeConverter::convert_async(compose, stack_name, compose_dir).await?;

        // Generate stack ID
        let stack_id = format!(
            "stack_{}",
            std::time::SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
        );

        info!(stack_id = %stack_id, stack_name = %stack_config.name, "Generated stack ID");

        // Create stack info
        let mut stack_info = StackInfo {
            id: stack_id.clone(),
            name: stack_config.name.clone(),
            services: Vec::new(),
            created_at: SystemTime::now(),
            state: StackState::Deploying,
        };

        // Store initial stack state
        {
            let mut stacks = self.stacks.write().await;
            stacks.insert(stack_id.clone(), stack_info.clone());
        }

        // Deploy the stack
        match self.deploy_stack_internal(&stack_config, &stack_id).await {
            Ok(services) => {
                stack_info.services = services;
                stack_info.state = StackState::Running;

                // Update stack state
                let mut stacks = self.stacks.write().await;
                stacks.insert(stack_id.clone(), stack_info);

                info!(stack_id = %stack_id, "Stack deployed successfully");
                Ok(stack_id)
            }
            Err(e) => {
                error!(stack_id = %stack_id, error = %e, "Stack deployment failed, rolling back");

                // Rollback
                if let Err(rollback_err) = self.rollback_stack(&stack_id).await {
                    warn!(error = %rollback_err, "Rollback encountered errors");
                }

                // Update stack state to failed
                stack_info.state = StackState::Failed;
                let mut stacks = self.stacks.write().await;
                stacks.insert(stack_id.clone(), stack_info);

                Err(e)
            }
        }
    }

    /// Internal deployment logic.
    async fn deploy_stack_internal(
        &self,
        stack_config: &StackConfig,
        stack_id: &str,
    ) -> Result<Vec<ServiceStatus>> {
        // Sort services by dependencies (topological sort)
        let ordered_services = self.topological_sort(&stack_config.services)?;

        let mut service_statuses = Vec::new();
        let mut created_vms = Vec::new();

        for service_name in ordered_services {
            let service =
                stack_config.services.iter().find(|s| s.name == service_name).ok_or_else(|| {
                    HyprError::Internal(format!("Service {} not found", service_name))
                })?;

            info!(service = %service.name, "Creating VM for service");

            // Allocate IP
            let mut allocator = self.ip_allocator.lock().await;
            let ip = allocator.allocate(service.vm_config.id.clone());
            drop(allocator);

            // Create VM config with allocated IP (will be passed to network setup)
            let mut vm_config = service.vm_config.clone();
            if let IpAddr::V4(ipv4) = ip {
                vm_config.network.ip_address = Some(ipv4);
            }

            // Get image reference from service config
            let image_ref = if !service.image.is_empty() {
                service.image.clone()
            } else {
                // Fallback: try to extract from disk path
                vm_config
                    .disks
                    .first()
                    .and_then(|d| d.path.parent())
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .map(|s| s.replace('_', ":"))
                    .unwrap_or_else(|| "unknown:latest".to_string())
            };

            // Parse name and tag
            let (image_name, image_tag) = if let Some(pos) = image_ref.rfind(':') {
                (&image_ref[..pos], &image_ref[pos + 1..])
            } else {
                (image_ref.as_str(), "latest")
            };

            // Ensure image is pulled (auto-pull from registry if not found locally)
            let image = match self.state.get_image_by_name_tag(image_name, image_tag).await {
                Ok(img) => {
                    info!(service = %service.name, image = %image_ref, "Image found locally");
                    img
                }
                Err(_) => {
                    // Image not found locally - pull from registry
                    info!(service = %service.name, image = %image_ref, "Pulling image from registry...");

                    let mut puller = ImagePuller::new().map_err(|e| {
                        HyprError::Internal(format!("Failed to create image puller: {}", e))
                    })?;

                    let image = puller.pull(&image_ref).await.map_err(|e| {
                        HyprError::Internal(format!(
                            "Failed to pull image {} for service {}: {}",
                            image_ref, service.name, e
                        ))
                    })?;

                    // Store in database
                    self.state.insert_image(&image).await?;
                    info!(service = %service.name, image = %image_ref, "Image pulled successfully");
                    image
                }
            };

            // Update disk path to use actual pulled image rootfs
            if !vm_config.disks.is_empty() {
                vm_config.disks[0] = DiskConfig {
                    path: image.rootfs_path.clone(),
                    readonly: true,
                    format: DiskFormat::Squashfs,
                };
            }

            // Build RuntimeManifest for runtime mode
            // Get entrypoint from service config or from image manifest
            let (entrypoint, workdir, image_env) = if !service.entrypoint.is_empty() {
                // Use explicit entrypoint from compose
                (service.entrypoint.clone(), service.workdir.clone(), HashMap::new())
            } else {
                // Use entrypoint from pulled image
                let mut ep = image.manifest.entrypoint.clone();
                if ep.is_empty() {
                    ep = image.manifest.cmd.clone();
                } else if !image.manifest.cmd.is_empty() {
                    ep.extend(image.manifest.cmd.clone());
                }
                (ep, image.manifest.workdir.clone(), image.manifest.env.clone())
            };

            if !entrypoint.is_empty() {
                use hypr_core::manifest::runtime_manifest::{
                    NetworkConfig as ManifestNetworkConfig, RuntimeManifest,
                };

                // Build environment variables: image env + compose env
                let mut env_vars: Vec<String> =
                    image_env.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
                for (k, v) in &vm_config.env {
                    env_vars.push(format!("{}={}", k, v));
                }

                // Build the manifest
                let mut manifest = RuntimeManifest::new(entrypoint.clone()).with_env(env_vars);

                // Set workdir if specified
                if !workdir.is_empty() {
                    manifest = manifest.with_workdir(workdir.clone());
                }

                // Add network configuration
                manifest = manifest.with_network(ManifestNetworkConfig {
                    ip: ip.to_string(),
                    netmask: "255.255.255.0".to_string(),
                    gateway: "10.88.0.1".to_string(),
                    dns: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
                });

                // Encode manifest and add to kernel args
                match manifest.encode() {
                    Ok(encoded) => {
                        vm_config.kernel_args.push(format!("manifest={}", encoded));
                        info!(
                            service = %service.name,
                            entrypoint = ?entrypoint,
                            "Injected RuntimeManifest into kernel cmdline"
                        );
                    }
                    Err(e) => {
                        error!(service = %service.name, error = %e, "Failed to encode RuntimeManifest");
                        return Err(HyprError::Internal(format!(
                            "Failed to encode RuntimeManifest: {}",
                            e
                        )));
                    }
                }
            }

            // Create VM via adapter
            let handle = self.adapter.create(&vm_config).await.map_err(|e| {
                error!(service = %service.name, error = %e, "Failed to create VM");
                e
            })?;

            // Create VM state
            let vm = Vm {
                id: vm_config.id.clone(),
                name: vm_config.name.clone(),
                image_id: format!("stack_{}", stack_id),
                status: VmStatus::Creating,
                config: vm_config.clone(),
                ip_address: Some(ip.to_string()),
                pid: handle.pid,
                created_at: SystemTime::now(),
                started_at: None,
                stopped_at: None,
            };

            // Save to state
            self.state.insert_vm(&vm).await?;

            // Start VM
            info!(service = %service.name, vm_id = %vm.id, "Starting VM");
            self.adapter.start(&handle).await.map_err(|e| {
                error!(service = %service.name, vm_id = %vm.id, error = %e, "Failed to start VM");
                e
            })?;

            created_vms.push((vm.id.clone(), handle));

            // Update status
            self.state.update_vm_status(&vm.id, VmStatus::Running).await?;

            service_statuses.push(ServiceStatus {
                name: service.name.clone(),
                vm_id: vm.id.clone(),
                status: VmStatus::Running,
                ip: Some(ip),
            });

            info!(service = %service.name, vm_id = %vm.id, ip = %ip, "Service started successfully");
        }

        Ok(service_statuses)
    }

    /// Destroy a stack and all its VMs.
    #[instrument(skip(self), fields(stack_id = %stack_id))]
    pub async fn destroy_stack(&self, stack_id: &str) -> Result<()> {
        info!("Destroying stack");

        // Get stack info
        let stack_info = {
            let stacks = self.stacks.read().await;
            stacks
                .get(stack_id)
                .cloned()
                .ok_or_else(|| HyprError::Internal(format!("Stack {} not found", stack_id)))?
        };

        // Stop and delete all VMs
        for service in &stack_info.services {
            info!(service = %service.name, vm_id = %service.vm_id, "Stopping and deleting VM");

            // Get VM from state
            if let Ok(vm) = self.state.get_vm(&service.vm_id).await {
                let handle = VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };

                // Stop VM (30 second timeout)
                let timeout = Duration::from_secs(30);
                if let Err(e) = self.adapter.stop(&handle, timeout).await {
                    warn!(vm_id = %vm.id, error = %e, "Failed to stop VM, will force kill");
                    // Try force kill
                    if let Err(e2) = self.adapter.delete(&handle).await {
                        error!(vm_id = %vm.id, error = %e2, "Failed to force delete VM");
                    }
                }

                // Delete VM
                if let Err(e) = self.adapter.delete(&handle).await {
                    error!(vm_id = %vm.id, error = %e, "Failed to delete VM");
                }

                // Release IP
                let mut allocator = self.ip_allocator.lock().await;
                allocator.release(&vm.id);

                // Delete from state
                if let Err(e) = self.state.delete_vm(&vm.id).await {
                    error!(vm_id = %vm.id, error = %e, "Failed to delete VM from state");
                }
            }
        }

        // Remove stack from tracking
        {
            let mut stacks = self.stacks.write().await;
            stacks.remove(stack_id);
        }

        info!(stack_id = %stack_id, "Stack destroyed successfully");
        Ok(())
    }

    /// Rollback a failed stack deployment.
    async fn rollback_stack(&self, stack_id: &str) -> Result<()> {
        warn!(stack_id = %stack_id, "Rolling back stack deployment");

        // Get all VMs for this stack
        let vms = self.state.list_vms().await?;
        let stack_vms: Vec<_> =
            vms.into_iter().filter(|vm| vm.image_id == format!("stack_{}", stack_id)).collect();

        // Delete all VMs
        for vm in stack_vms {
            let handle = VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };

            // Try to stop
            let _ = self.adapter.stop(&handle, Duration::from_secs(5)).await;

            // Delete
            if let Err(e) = self.adapter.delete(&handle).await {
                warn!(vm_id = %vm.id, error = %e, "Failed to delete VM during rollback");
            }

            // Release IP
            let mut allocator = self.ip_allocator.lock().await;
            allocator.release(&vm.id);

            // Delete from state
            if let Err(e) = self.state.delete_vm(&vm.id).await {
                warn!(vm_id = %vm.id, error = %e, "Failed to delete VM from state during rollback");
            }
        }

        Ok(())
    }

    /// List all stacks.
    pub async fn list_stacks(&self) -> Vec<StackInfo> {
        let stacks = self.stacks.read().await;
        stacks.values().cloned().collect()
    }

    /// Get a specific stack by ID.
    pub async fn get_stack(&self, stack_id: &str) -> Option<StackInfo> {
        let stacks = self.stacks.read().await;
        stacks.get(stack_id).cloned()
    }

    /// Perform topological sort on services based on dependencies.
    fn topological_sort(&self, services: &[ServiceConfig]) -> Result<Vec<String>> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();

        // Initialize
        for service in services {
            in_degree.insert(service.name.clone(), 0);
            adjacency.insert(service.name.clone(), Vec::new());
        }

        // Build graph
        for service in services {
            for dep in &service.depends_on {
                if !in_degree.contains_key(dep) {
                    return Err(HyprError::InvalidConfig {
                        reason: format!(
                            "Service {} depends on non-existent service {}",
                            service.name, dep
                        ),
                    });
                }

                // dep -> service edge
                adjacency.get_mut(dep).unwrap().push(service.name.clone());
                *in_degree.get_mut(&service.name).unwrap() += 1;
            }
        }

        // Topological sort using Kahn's algorithm
        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|(_, &count)| count == 0)
            .map(|(name, _)| name.clone())
            .collect();

        let mut result = Vec::new();

        while let Some(node) = queue.pop() {
            result.push(node.clone());

            for neighbor in &adjacency[&node] {
                let count = in_degree.get_mut(neighbor).unwrap();
                *count -= 1;
                if *count == 0 {
                    queue.push(neighbor.clone());
                }
            }
        }

        // Check for cycles
        if result.len() != services.len() {
            return Err(HyprError::InvalidConfig {
                reason: "Circular dependency detected in service dependencies".to_string(),
            });
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypr_core::{NetworkConfig, VmConfig, VmResources};

    // Tests are ignored until MockVmmAdapter is available for proper testing
    #[test]
    #[ignore]
    fn test_topological_sort_simple() {
        // let orchestrator =
        //     StackOrchestrator::new(Arc::new(create_test_state()), Arc::new(MockVmmAdapter));

        let _services =
            [create_test_service("web", vec!["db".to_string()]), create_test_service("db", vec![])];

        // let result = orchestrator.topological_sort(&services).unwrap();
        // assert_eq!(result, vec!["db".to_string(), "web".to_string()]);
    }

    #[test]
    #[ignore]
    fn test_topological_sort_complex() {
        // let orchestrator =
        //     StackOrchestrator::new(Arc::new(create_test_state()), Arc::new(MockVmmAdapter));

        let _services = [
            create_test_service("web", vec!["api".to_string(), "cache".to_string()]),
            create_test_service("api", vec!["db".to_string()]),
            create_test_service("cache", vec![]),
            create_test_service("db", vec![]),
        ];

        // let result = orchestrator.topological_sort(&services).unwrap();

        // db and cache have no dependencies, should come first
        // api depends on db, should come after db
        // web depends on api and cache, should come last
        // let db_idx = result.iter().position(|s| s == "db").unwrap();
        // let cache_idx = result.iter().position(|s| s == "cache").unwrap();
        // let api_idx = result.iter().position(|s| s == "api").unwrap();
        // let web_idx = result.iter().position(|s| s == "web").unwrap();

        // assert!(db_idx < api_idx);
        // assert!(api_idx < web_idx);
        // assert!(cache_idx < web_idx);
    }

    #[test]
    #[ignore]
    fn test_topological_sort_circular() {
        // let orchestrator =
        //     StackOrchestrator::new(Arc::new(create_test_state()), Arc::new(MockVmmAdapter));

        let _services = [
            create_test_service("a", vec!["b".to_string()]),
            create_test_service("b", vec!["c".to_string()]),
            create_test_service("c", vec!["a".to_string()]),
        ];

        // let result = orchestrator.topological_sort(&services);
        // assert!(result.is_err());
        // assert!(result.unwrap_err().to_string().contains("Circular dependency"));
    }

    #[test]
    #[ignore]
    fn test_topological_sort_missing_dependency() {
        // let orchestrator =
        //     StackOrchestrator::new(Arc::new(create_test_state()), Arc::new(MockVmmAdapter));

        let _services = [create_test_service("web", vec!["nonexistent".to_string()])];

        // let result = orchestrator.topological_sort(&services);
        // assert!(result.is_err());
        // assert!(result.unwrap_err().to_string().contains("non-existent"));
    }

    #[test]
    fn test_ip_allocator() {
        let mut allocator = SimpleIpAllocator::new();

        let ip1 = allocator.allocate("vm1".to_string());
        let ip2 = allocator.allocate("vm2".to_string());

        assert_ne!(ip1, ip2);
        assert_eq!(allocator.allocated.len(), 2);

        allocator.release("vm1");
        assert_eq!(allocator.allocated.len(), 1);
    }

    // Helper functions for tests - using async runtime for test setup
    #[allow(dead_code)]
    fn create_test_state() -> StateManager {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { StateManager::new(&":memory:".to_string()).await.unwrap() })
    }

    fn create_test_service(name: &str, depends_on: Vec<String>) -> ServiceConfig {
        ServiceConfig {
            name: name.to_string(),
            image: format!("{}:latest", name),
            vm_config: VmConfig {
                network_enabled: true,
                id: format!("{}_vm", name),
                name: name.to_string(),
                resources: VmResources { cpus: 1, memory_mb: 512, balloon_enabled: true },
                kernel_path: Some("/tmp/kernel".into()),
                kernel_args: vec![],
                initramfs_path: None,
                disks: vec![],
                network: NetworkConfig {
                    network: "default".to_string(),
                    mac_address: None,
                    ip_address: None,
                    dns_servers: vec![],
                },
                ports: vec![],
                env: std::collections::HashMap::new(),
                volumes: vec![],
                gpu: None,
                virtio_fs_mounts: vec![],
            },
            depends_on,
            healthcheck: None,
            entrypoint: vec![],
            workdir: String::new(),
        }
    }
}
