//! gRPC server implementation

use crate::network_manager::NetworkManager;
use crate::orchestrator::StackOrchestrator;
use base64::Engine;
use hypr_api::hypr::v1::hypr_service_server::{HyprService, HyprServiceServer};
use hypr_api::hypr::v1::{self as proto, *};
use hypr_core::adapters::VmmAdapter;
use hypr_core::registry::ImagePuller;
use hypr_core::{HyprError, Result, StateManager, Vm, VmConfig, VmHandle, VmStatus};

/// Alias for core VmConfig to avoid confusion with proto VmConfig
type CoreVmConfig = VmConfig;
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{info, instrument, warn};

/// gRPC service implementation
#[allow(dead_code)]
pub struct HyprServiceImpl {
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
    network_mgr: Arc<NetworkManager>,
    orchestrator: Arc<StackOrchestrator>,
}

impl HyprServiceImpl {
    pub fn new(
        state: Arc<StateManager>,
        adapter: Arc<dyn VmmAdapter>,
        network_mgr: Arc<NetworkManager>,
    ) -> Self {
        let orchestrator = Arc::new(StackOrchestrator::new(state.clone(), adapter.clone()));
        Self { state, adapter, network_mgr, orchestrator }
    }
}

#[tonic::async_trait]
impl HyprService for HyprServiceImpl {
    #[instrument(skip(self), fields(name = %request.get_ref().name))]
    async fn create_vm(
        &self,
        request: Request<CreateVmRequest>,
    ) -> std::result::Result<Response<CreateVmResponse>, Status> {
        info!("gRPC: CreateVM");

        let req = request.into_inner();

        // Convert proto → domain types
        let config = req.config.ok_or_else(|| Status::invalid_argument("config required"))?;
        let mut vm_config: VmConfig =
            config.try_into().map_err(|e: HyprError| Status::invalid_argument(e.to_string()))?;

        // Load image to get entrypoint/cmd for runtime manifest
        let image_ref = &req.image;
        let (image_name, image_tag) = if let Some(pos) = image_ref.rfind(':') {
            (&image_ref[..pos], &image_ref[pos + 1..])
        } else {
            (image_ref.as_str(), "latest")
        };

        let image = self
            .state
            .get_image_by_name_tag(image_name, image_tag)
            .await
            .map_err(|e| Status::not_found(format!("Image not found: {}", e)))?;

        // 1. Allocate IP for VM (needed before building manifest)
        let vm_ip = self
            .network_mgr
            .allocate_ip(&vm_config.id)
            .await
            .map_err(|e| Status::internal(format!("Failed to allocate IP: {}", e)))?;

        info!("Allocated IP {} for VM {}", vm_ip, vm_config.id);

        // Store IP in config for adapter
        vm_config.network.ip_address = Some(vm_ip);

        // 2. Build RuntimeManifest from image manifest
        let mut entrypoint = image.manifest.entrypoint.clone();
        if entrypoint.is_empty() {
            entrypoint = image.manifest.cmd.clone();
        } else if !image.manifest.cmd.is_empty() {
            // Entrypoint + cmd as args (Docker behavior)
            entrypoint.extend(image.manifest.cmd.clone());
        }

        if !entrypoint.is_empty() {
            use hypr_core::manifest::runtime_manifest::{
                NetworkConfig as ManifestNetworkConfig, RuntimeManifest,
            };

            // Build environment variables (merge image env with config env)
            let mut env_vars: Vec<String> =
                image.manifest.env.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            // Add/override with config env vars
            for (k, v) in &vm_config.env {
                env_vars.push(format!("{}={}", k, v));
            }

            // Build the manifest
            let mut manifest = RuntimeManifest::new(entrypoint.clone()).with_env(env_vars);

            // Set workdir if specified
            if !image.manifest.workdir.is_empty() {
                manifest = manifest.with_workdir(image.manifest.workdir.clone());
            }

            // Set user if specified in image
            if let Some(ref user) = image.manifest.user {
                manifest = manifest.with_user(user.clone());
            }

            // Set network configuration
            // Gateway is platform-specific (same as IPAM)
            #[cfg(target_os = "linux")]
            let gateway = "10.88.0.1";
            #[cfg(target_os = "macos")]
            let gateway = "192.168.64.1";
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let gateway = "10.88.0.1";

            manifest = manifest.with_network(ManifestNetworkConfig {
                ip: vm_ip.to_string(),
                netmask: "255.255.255.0".to_string(),
                gateway: gateway.to_string(),
                dns: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            });

            // Encode manifest and add to kernel args
            match manifest.encode() {
                Ok(encoded) => {
                    vm_config.kernel_args.push(format!("manifest={}", encoded));
                    info!(
                        "Injected RuntimeManifest into kernel cmdline (entrypoint: {:?})",
                        entrypoint
                    );
                }
                Err(e) => {
                    // Cleanup: release IP
                    let _ = self.network_mgr.release_ip(&vm_config.id).await;
                    return Err(Status::internal(format!("Failed to encode manifest: {}", e)));
                }
            }
        }

        // 3. Create VM via adapter
        let handle =
            self.adapter.create(&vm_config).await.map_err(|e| Status::internal(e.to_string()))?;

        // 4. Setup port forwarding for each exposed port
        for port_cfg in &vm_config.ports {
            if let Err(e) = self
                .network_mgr
                .add_port_forward(
                    port_cfg.host_port,
                    vm_ip,
                    port_cfg.vm_port,
                    port_cfg.protocol,
                    vm_config.id.clone(),
                )
                .await
            {
                // Cleanup: release IP and delete VM
                let _ = self.network_mgr.release_ip(&vm_config.id).await;
                let _ = self.adapter.delete(&handle).await;

                return Err(Status::internal(format!("Failed to setup port forwarding: {}", e)));
            }

            info!(
                "Port forwarding: localhost:{} -> {}:{} ({})",
                port_cfg.host_port, vm_ip, port_cfg.vm_port, port_cfg.protocol
            );
        }

        // 5. Register service in DNS (use VM name or ID)
        let service_name =
            if !vm_config.name.is_empty() { vm_config.name.clone() } else { vm_config.id.clone() };

        let ports_for_dns: Vec<_> =
            vm_config.ports.iter().map(|p| (p.vm_port, p.protocol)).collect();

        if let Err(e) = self.network_mgr.register_service(&service_name, vm_ip, ports_for_dns).await
        {
            // Non-fatal: log but don't fail VM creation
            info!("Warning: Failed to register service in DNS: {}", e);
        }

        // Create VM state
        let vm = Vm {
            id: vm_config.id.clone(),
            name: vm_config.name.clone(),
            image_id: req.image,
            status: VmStatus::Creating,
            config: vm_config,
            ip_address: Some(vm_ip.to_string()),
            pid: handle.pid,
            created_at: SystemTime::now(),
            started_at: None,
            stopped_at: None,
        };

        // Save to state
        self.state.insert_vm(&vm).await.map_err(|e| Status::internal(e.to_string()))?;

        // Convert domain → proto
        let response = CreateVmResponse { vm: Some(vm.into()) };

        Ok(Response::new(response))
    }

    #[instrument(skip(self), fields(vm_id = %request.get_ref().id))]
    async fn start_vm(
        &self,
        request: Request<StartVmRequest>,
    ) -> std::result::Result<Response<StartVmResponse>, Status> {
        info!("gRPC: StartVM");

        let req = request.into_inner();

        // Get VM from state
        let vm = self.state.get_vm(&req.id).await.map_err(|e| Status::not_found(e.to_string()))?;

        // Create handle for adapter
        let handle = hypr_core::VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };

        // Start via adapter
        self.adapter.start(&handle).await.map_err(|e| Status::internal(e.to_string()))?;

        // Update state
        self.state
            .update_vm_status(&req.id, VmStatus::Running)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Fetch updated VM
        let vm = self.state.get_vm(&req.id).await.map_err(|e| Status::internal(e.to_string()))?;

        let response = StartVmResponse { vm: Some(vm.into()) };

        Ok(Response::new(response))
    }

    #[instrument(skip(self), fields(vm_id = %request.get_ref().id))]
    async fn stop_vm(
        &self,
        request: Request<StopVmRequest>,
    ) -> std::result::Result<Response<StopVmResponse>, Status> {
        info!("gRPC: StopVM");

        let req = request.into_inner();
        let timeout = Duration::from_secs(req.timeout_sec.unwrap_or(30) as u64);

        // Get VM from state
        let vm = self.state.get_vm(&req.id).await.map_err(|e| Status::not_found(e.to_string()))?;

        // Create handle for adapter
        let handle = hypr_core::VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };

        // Stop via adapter
        self.adapter.stop(&handle, timeout).await.map_err(|e| Status::internal(e.to_string()))?;

        // Update state
        self.state
            .update_vm_status(&req.id, VmStatus::Stopped)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Fetch updated VM
        let vm = self.state.get_vm(&req.id).await.map_err(|e| Status::internal(e.to_string()))?;

        let response = StopVmResponse { vm: Some(vm.into()) };

        Ok(Response::new(response))
    }

    #[instrument(skip(self), fields(vm_id = %request.get_ref().id))]
    async fn delete_vm(
        &self,
        request: Request<DeleteVmRequest>,
    ) -> std::result::Result<Response<DeleteVmResponse>, Status> {
        info!("gRPC: DeleteVM");

        let req = request.into_inner();

        // Get VM from state
        let vm = self.state.get_vm(&req.id).await.map_err(|e| Status::not_found(e.to_string()))?;

        // If force=false and VM is running, reject
        if !req.force && vm.status == VmStatus::Running {
            return Err(Status::failed_precondition(
                "VM is running. Stop it first or use force=true",
            ));
        }

        // If VM is running (force=true), kill it first
        if vm.status == VmStatus::Running {
            info!("Force killing running VM before deletion");
            let handle = hypr_core::VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };
            if let Err(e) = self.adapter.kill(&handle).await {
                warn!("Failed to kill VM process: {}", e);
            }
        }

        // 1. Remove port forwarding
        if let Err(e) = self.network_mgr.remove_vm_port_forwards(&vm.id).await {
            info!("Warning: Failed to remove port forwards: {}", e);
        }

        // 2. Unregister from DNS
        let service_name = if !vm.name.is_empty() { &vm.name } else { &vm.id };
        if let Err(e) = self.network_mgr.unregister_service(service_name).await {
            info!("Warning: Failed to unregister service: {}", e);
        }

        // 3. Release IP (use VM ID, not IP address)
        if let Err(e) = self.network_mgr.release_ip(&vm.id).await {
            info!("Warning: Failed to release IP: {}", e);
        }

        // Create handle for adapter
        let handle = hypr_core::VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };

        // Delete via adapter
        self.adapter.delete(&handle).await.map_err(|e| Status::internal(e.to_string()))?;

        // Delete from state (use vm.id, not req.id - req.id might be partial/name)
        self.state.delete_vm(&vm.id).await.map_err(|e| Status::internal(e.to_string()))?;

        // 5. Clean up log file
        let log_path = hypr_core::paths::vm_log_path(&vm.id);
        if log_path.exists() {
            if let Err(e) = std::fs::remove_file(&log_path) {
                info!("Warning: Failed to remove log file: {}", e);
            }
        }

        let response = DeleteVmResponse { success: true };

        Ok(Response::new(response))
    }

    #[instrument(skip(self))]
    async fn list_vms(
        &self,
        _request: Request<ListVmsRequest>,
    ) -> std::result::Result<Response<ListVmsResponse>, Status> {
        info!("gRPC: ListVMs");

        let mut vms = self.state.list_vms().await.map_err(|e| Status::internal(e.to_string()))?;

        // Update VM status by checking if process is still running
        for vm in &mut vms {
            if vm.status == hypr_core::VmStatus::Running {
                if let Some(pid) = vm.pid {
                    // Check if process exists
                    let running = std::process::Command::new("ps")
                        .arg("-p")
                        .arg(pid.to_string())
                        .output()
                        .map(|output| output.status.success())
                        .unwrap_or(false);

                    if !running {
                        vm.status = hypr_core::VmStatus::Stopped;
                        // Update in database
                        let _ =
                            self.state.update_vm_status(&vm.id, hypr_core::VmStatus::Stopped).await;
                    }
                }
            }
        }

        let response = ListVmsResponse { vms: vms.into_iter().map(|vm| vm.into()).collect() };

        Ok(Response::new(response))
    }

    #[instrument(skip(self), fields(vm_id = %request.get_ref().id))]
    async fn get_vm(
        &self,
        request: Request<GetVmRequest>,
    ) -> std::result::Result<Response<GetVmResponse>, Status> {
        info!("gRPC: GetVM");

        let req = request.into_inner();

        let vm = self.state.get_vm(&req.id).await.map_err(|e| Status::not_found(e.to_string()))?;

        let response = GetVmResponse { vm: Some(vm.into()) };

        Ok(Response::new(response))
    }

    #[instrument(skip(self))]
    async fn list_images(
        &self,
        _request: Request<ListImagesRequest>,
    ) -> std::result::Result<Response<ListImagesResponse>, Status> {
        info!("gRPC: ListImages");

        let images = self.state.list_images().await.map_err(|e| Status::internal(e.to_string()))?;

        let response =
            ListImagesResponse { images: images.into_iter().map(|img| img.into()).collect() };

        Ok(Response::new(response))
    }

    #[instrument(skip(self), fields(name = %request.get_ref().name, tag = %request.get_ref().tag))]
    async fn get_image(
        &self,
        request: Request<GetImageRequest>,
    ) -> std::result::Result<Response<GetImageResponse>, Status> {
        info!("gRPC: GetImage");

        let req = request.into_inner();

        // Determine the tag (default to "latest" if empty)
        let tag = if req.tag.is_empty() { "latest".to_string() } else { req.tag };

        // First try to get image from local database
        if let Ok(image) = self.state.get_image_by_name_tag(&req.name, &tag).await {
            let response = GetImageResponse { image: Some(image.into()) };
            return Ok(Response::new(response));
        }

        // Image not found locally - auto-pull from registry (Docker-like behavior)
        info!("Image {}:{} not found locally, pulling from registry...", req.name, tag);

        // Build full image reference
        let image_ref = format!("{}:{}", req.name, tag);

        // Pull from registry
        let mut puller = hypr_core::registry::ImagePuller::new()
            .map_err(|e| Status::internal(format!("Failed to create image puller: {}", e)))?;

        let image = puller
            .pull(&image_ref)
            .await
            .map_err(|e| Status::not_found(format!("Failed to pull image {}: {}", image_ref, e)))?;

        // Store in database
        self.state
            .insert_image(&image)
            .await
            .map_err(|e| Status::internal(format!("Failed to store pulled image: {}", e)))?;

        info!("Image {}:{} pulled and stored successfully", image.name, image.tag);

        let response = GetImageResponse { image: Some(image.into()) };
        Ok(Response::new(response))
    }

    #[instrument(skip(self), fields(image_id = %request.get_ref().id))]
    async fn delete_image(
        &self,
        request: Request<DeleteImageRequest>,
    ) -> std::result::Result<Response<DeleteImageResponse>, Status> {
        info!("gRPC: DeleteImage");

        let req = request.into_inner();

        // Check if image is in use by any VMs before deletion
        if !req.force {
            let vms = self.state.list_vms().await.map_err(|e| Status::internal(e.to_string()))?;

            if vms.iter().any(|vm| vm.image_id == req.id) {
                return Err(Status::failed_precondition(
                    "Image is in use by VMs. Use force=true to delete anyway",
                ));
            }
        }

        self.state.delete_image(&req.id).await.map_err(|e| Status::internal(e.to_string()))?;

        let response = DeleteImageResponse { success: true };

        Ok(Response::new(response))
    }

    #[instrument(skip(self))]
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> std::result::Result<Response<HealthResponse>, Status> {
        info!("gRPC: Health");

        let mut details = HashMap::new();
        details.insert("adapter".to_string(), self.adapter.name().to_string());

        let response = HealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            details,
        };

        Ok(Response::new(response))
    }

    type StreamLogsStream =
        Pin<Box<dyn Stream<Item = std::result::Result<LogEntry, Status>> + Send>>;

    type DeployStackStream =
        Pin<Box<dyn Stream<Item = std::result::Result<DeployStackEvent, Status>> + Send>>;

    type RunVMStream = Pin<Box<dyn Stream<Item = std::result::Result<RunVmEvent, Status>> + Send>>;

    #[instrument(skip(self), fields(image = %request.get_ref().image))]
    async fn run_vm(
        &self,
        request: Request<RunVmRequest>,
    ) -> std::result::Result<Response<Self::RunVMStream>, Status> {
        info!("gRPC: RunVM (streaming)");

        let req = request.into_inner();
        let image_ref = req.image.clone();
        let vm_name = req.name.filter(|s| !s.is_empty());
        let config = req.config;

        // Create channel for progress events
        let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<RunVmEvent, Status>>(100);

        // Clone what we need for the spawned task
        let state = self.state.clone();
        let adapter = self.adapter.clone();
        let network_mgr = self.network_mgr.clone();

        tokio::spawn(async move {
            let result = run_vm_with_progress(
                &state,
                &adapter,
                &network_mgr,
                &image_ref,
                vm_name,
                config,
                &tx,
            )
            .await;

            if let Err(e) = result {
                let event = RunVmEvent {
                    event: Some(run_vm_event::Event::Error(RunError { message: e.to_string() })),
                };
                let _ = tx.send(Ok(event)).await;
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::RunVMStream))
    }

    #[instrument(skip(self), fields(vm_id = %request.get_ref().vm_id))]
    async fn stream_logs(
        &self,
        request: Request<StreamLogsRequest>,
    ) -> std::result::Result<Response<Self::StreamLogsStream>, Status> {
        info!("gRPC: StreamLogs");

        let req = request.into_inner();
        let vm_id = req.vm_id.clone();
        let follow = req.follow;
        let tail = req.tail as usize;

        // Verify VM exists
        let _vm = self
            .state
            .get_vm(&vm_id)
            .await
            .map_err(|_| Status::not_found(format!("VM {} not found", vm_id)))?;

        // Get log file path
        let log_path = hypr_core::paths::vm_log_path(&vm_id);

        if !log_path.exists() {
            return Err(Status::not_found(format!("Log file not found for VM {}", vm_id)));
        }

        // Create async channel for streaming
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // Spawn task to read logs and send to channel
        let log_path_clone = log_path.clone();
        tokio::spawn(async move {
            if let Err(e) = stream_log_file(log_path_clone, tx, tail, follow).await {
                warn!("Error streaming logs: {}", e);
            }
        });

        // Convert channel receiver to stream
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);

        Ok(Response::new(Box::pin(stream) as Self::StreamLogsStream))
    }

    #[instrument(skip(self))]
    async fn deploy_stack(
        &self,
        request: Request<DeployStackRequest>,
    ) -> std::result::Result<Response<Self::DeployStackStream>, Status> {
        info!("gRPC: DeployStack (streaming)");

        let req = request.into_inner();

        let compose_path = PathBuf::from(&req.compose_file);
        let stack_name = req.stack_name.filter(|s| !s.is_empty());
        let build = req.build;

        // Create channel for progress events
        let (tx, rx) =
            tokio::sync::mpsc::channel::<std::result::Result<DeployStackEvent, Status>>(100);

        // Clone orchestrator for the spawned task
        let orchestrator = self.orchestrator.clone();

        // Spawn deployment task
        tokio::spawn(async move {
            match orchestrator
                .deploy_stack_with_progress(compose_path, stack_name, build, tx.clone())
                .await
            {
                Ok(stack_id) => {
                    // Get final stack info
                    if let Some(stack_info) = orchestrator.get_stack(&stack_id).await {
                        let event = DeployStackEvent {
                            event: Some(deploy_stack_event::Event::Complete(DeployComplete {
                                stack: Some(stack_info.into()),
                            })),
                        };
                        let _ = tx.send(Ok(event)).await;
                    }
                }
                Err(e) => {
                    let event = DeployStackEvent {
                        event: Some(deploy_stack_event::Event::Error(DeployError {
                            service: String::new(),
                            message: e.to_string(),
                        })),
                    };
                    let _ = tx.send(Ok(event)).await;
                }
            }
        });

        // Convert channel receiver to stream
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);

        Ok(Response::new(Box::pin(stream) as Self::DeployStackStream))
    }

    #[instrument(skip(self))]
    async fn destroy_stack(
        &self,
        request: Request<DestroyStackRequest>,
    ) -> std::result::Result<Response<DestroyStackResponse>, Status> {
        info!("gRPC: DestroyStack");

        let req = request.into_inner();

        self.orchestrator
            .destroy_stack(&req.stack_name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let response = DestroyStackResponse { success: true };

        Ok(Response::new(response))
    }

    #[instrument(skip(self))]
    async fn list_stacks(
        &self,
        _request: Request<ListStacksRequest>,
    ) -> std::result::Result<Response<ListStacksResponse>, Status> {
        info!("gRPC: ListStacks");

        let stacks = self.orchestrator.list_stacks().await;

        let response =
            ListStacksResponse { stacks: stacks.into_iter().map(|s| s.into()).collect() };

        Ok(Response::new(response))
    }

    #[instrument(skip(self))]
    async fn get_stack(
        &self,
        request: Request<GetStackRequest>,
    ) -> std::result::Result<Response<GetStackResponse>, Status> {
        info!("gRPC: GetStack");

        let req = request.into_inner();

        let stack = self
            .orchestrator
            .get_stack(&req.stack_name)
            .await
            .ok_or_else(|| Status::not_found(format!("Stack {} not found", req.stack_name)))?;

        let response = GetStackResponse { stack: Some(stack.into()) };

        Ok(Response::new(response))
    }
}

/// Start the gRPC API server on Unix socket
#[allow(dead_code)]
#[instrument(skip(state, adapter, network_mgr))]
pub async fn start_api_server(
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
    network_mgr: Arc<NetworkManager>,
) -> Result<()> {
    let socket_path = "/tmp/hypr.sock";

    info!("Starting gRPC API server on {}", socket_path);

    // Remove old socket if exists
    let _ = std::fs::remove_file(socket_path);

    // Bind Unix socket
    let uds = UnixListener::bind(socket_path)
        .map_err(|e| HyprError::Internal(format!("Failed to bind socket: {}", e)))?;

    // SECURITY: Socket permissions control who can communicate with the daemon.
    // Using 0o660 restricts access to owner (root) and the 'hypr' group.
    // Users who need to use `hypr` CLI without sudo should be added to the 'hypr' group:
    //   sudo groupadd hypr && sudo usermod -aG hypr $USER
    //
    // Note: 0o666 (world-writable) was previously used but is a security risk because
    // anyone on the system could control VMs or mount host directories.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| HyprError::Internal(format!("Failed to set socket permissions: {}", e)))?;

    // Try to set group ownership to 'hypr' group if it exists
    // This allows non-root users in the hypr group to use the CLI
    {
        use std::ffi::CString;
        if let Ok(socket_cstr) = CString::new(socket_path) {
            // Try to get the 'hypr' group ID, create it if it doesn't exist
            let hypr_group = CString::new("hypr").unwrap();
            unsafe {
                let mut grp = libc::getgrnam(hypr_group.as_ptr());

                // Auto-create group if it doesn't exist
                if grp.is_null() {
                    info!("Creating 'hypr' group...");
                    let status = std::process::Command::new("groupadd").arg("hypr").status();

                    match status {
                        Ok(exit) if exit.success() => {
                            info!("Created 'hypr' group");
                            // Refresh group lookup
                            grp = libc::getgrnam(hypr_group.as_ptr());
                        }
                        Ok(exit) => {
                            warn!("Failed to create 'hypr' group (exit code: {:?})", exit.code());
                        }
                        Err(e) => {
                            warn!("Failed to run groupadd: {}", e);
                        }
                    }
                }

                if !grp.is_null() {
                    let gid = (*grp).gr_gid;
                    // chown socket to root:hypr
                    if libc::chown(socket_cstr.as_ptr(), 0, gid) == 0 {
                        info!("Socket ownership set to root:hypr");
                    } else {
                        warn!("Failed to set socket group to 'hypr', users may need sudo");
                    }
                } else {
                    warn!("Group 'hypr' not found and could not be created, users may need sudo");
                }
            }
        }
    }

    let uds_stream = UnixListenerStream::new(uds);

    // Create service
    let service = HyprServiceImpl::new(state, adapter, network_mgr);

    info!("gRPC server listening on {}", socket_path);

    // Start server
    Server::builder()
        .add_service(HyprServiceServer::new(service))
        .serve_with_incoming(uds_stream)
        .await
        .map_err(|e| HyprError::Internal(format!("Server error: {}", e)))?;

    Ok(())
}

/// Stream log file contents to a channel.
///
/// Supports:
/// - `tail`: Show only last N lines (0 = all)
/// - `follow`: Continue watching for new content (like tail -f)
async fn stream_log_file(
    log_path: PathBuf,
    tx: tokio::sync::mpsc::Sender<std::result::Result<LogEntry, Status>>,
    tail: usize,
    follow: bool,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let file = tokio::fs::File::open(&log_path).await?;
    let mut reader = BufReader::new(file);

    // If tail is specified, we need to read the file to find the last N lines
    if tail > 0 {
        // Read entire file to count lines and find offset for last N
        let mut all_lines = Vec::new();
        let mut line = String::new();
        while reader.read_line(&mut line).await? > 0 {
            all_lines.push(line.clone());
            line.clear();
        }

        // Send only the last `tail` lines
        let start = if all_lines.len() > tail { all_lines.len() - tail } else { 0 };
        for log_line in all_lines[start..].iter() {
            let entry = LogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
                line: log_line.trim_end().to_string(),
                stream: "stdout".to_string(),
            };
            if tx.send(Ok(entry)).await.is_err() {
                return Ok(()); // Client disconnected
            }
        }
    } else {
        // Read all lines from the beginning
        let mut line = String::new();
        while reader.read_line(&mut line).await? > 0 {
            let entry = LogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
                line: line.trim_end().to_string(),
                stream: "stdout".to_string(),
            };
            if tx.send(Ok(entry)).await.is_err() {
                return Ok(()); // Client disconnected
            }
            line.clear();
        }
    }

    // If follow mode, keep watching for new content
    if follow {
        // Get current position
        let mut pos = reader.seek(std::io::SeekFrom::Current(0)).await?;

        loop {
            // Check for new content
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Re-check file size
            let metadata = tokio::fs::metadata(&log_path).await?;
            let new_len = metadata.len();

            if new_len > pos {
                // New content available - seek to position and read
                reader.seek(std::io::SeekFrom::Start(pos)).await?;

                let mut line = String::new();
                while reader.read_line(&mut line).await? > 0 {
                    let entry = LogEntry {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64,
                        line: line.trim_end().to_string(),
                        stream: "stdout".to_string(),
                    };
                    if tx.send(Ok(entry)).await.is_err() {
                        return Ok(()); // Client disconnected
                    }
                    line.clear();
                }

                pos = reader.seek(std::io::SeekFrom::Current(0)).await?;
            }
        }
    }

    Ok(())
}

/// Type alias for run progress sender
type RunProgressSender = tokio::sync::mpsc::Sender<std::result::Result<RunVmEvent, Status>>;

/// Send run progress event
async fn send_run_progress(tx: &RunProgressSender, stage: &str, message: &str) {
    let event = RunVmEvent {
        event: Some(run_vm_event::Event::Progress(RunProgress {
            stage: stage.to_string(),
            message: message.to_string(),
            current: 0,
            total: 0,
        })),
    };
    let _ = tx.send(Ok(event)).await;
}

/// Run VM with streaming progress
async fn run_vm_with_progress(
    state: &Arc<StateManager>,
    adapter: &Arc<dyn VmmAdapter>,
    network_mgr: &Arc<NetworkManager>,
    image_ref: &str,
    vm_name: Option<String>,
    proto_config: Option<proto::VmConfig>,
    tx: &RunProgressSender,
) -> Result<()> {
    // Parse image reference
    let (image_name, image_tag) = if let Some(pos) = image_ref.rfind(':') {
        (&image_ref[..pos], &image_ref[pos + 1..])
    } else {
        (image_ref, "latest")
    };

    // Stage 1: Resolve image
    send_run_progress(tx, "resolving", &format!("Resolving image {}:{}", image_name, image_tag))
        .await;

    let image = match state.get_image_by_name_tag(image_name, image_tag).await {
        Ok(img) => {
            send_run_progress(
                tx,
                "cached",
                &format!("Using cached image {}:{}", image_name, image_tag),
            )
            .await;
            img
        }
        Err(_) => {
            // Need to pull
            send_run_progress(tx, "pulling", &format!("Pulling {}:{}", image_name, image_tag))
                .await;

            let mut puller = ImagePuller::new().map_err(|e| {
                HyprError::Internal(format!("Failed to create image puller: {}", e))
            })?;

            let image = puller.pull(image_ref).await.map_err(|e| {
                HyprError::Internal(format!("Failed to pull image {}: {}", image_ref, e))
            })?;

            state.insert_image(&image).await?;
            send_run_progress(tx, "pulled", &format!("Image {}:{} ready", image_name, image_tag))
                .await;
            image
        }
    };

    // Stage 2: Create VM
    send_run_progress(tx, "creating", "Creating VM...").await;

    // Generate VM ID and name
    let vm_id = format!("vm-{}", uuid::Uuid::new_v4());
    let final_vm_name = vm_name.unwrap_or_else(|| format!("vm-{}", &vm_id[3..11]));

    // Build VM config from proto or defaults
    let (cpus, memory_mb) = if let Some(ref cfg) = proto_config {
        let r = cfg.resources.as_ref();
        (r.map(|r| r.cpus).unwrap_or(2), r.map(|r| r.memory_mb).unwrap_or(512))
    } else {
        (2, 512)
    };

    let mut vm_config = CoreVmConfig {
        id: String::new(),
        name: String::new(),
        resources: hypr_core::VmResources { cpus, memory_mb, balloon_enabled: true },
        kernel_path: None,
        kernel_args: vec![],
        initramfs_path: None,
        disks: vec![],
        network: hypr_core::types::network::NetworkConfig::default(),
        ports: vec![],
        env: std::collections::HashMap::new(),
        volumes: vec![],
        gpu: None,
        virtio_fs_mounts: vec![],
        network_enabled: true,
    };

    vm_config.id = vm_id.clone();
    vm_config.name = final_vm_name.clone();

    // Set disk from image
    vm_config.disks = vec![hypr_core::types::vm::DiskConfig {
        path: image.rootfs_path.clone(),
        readonly: true,
        format: hypr_core::types::vm::DiskFormat::Squashfs,
    }];

    // Allocate IP
    let vm_ip = network_mgr
        .allocate_ip(&vm_config.id)
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to allocate IP: {}", e)))?;
    vm_config.network.ip_address = Some(vm_ip);

    // Build RuntimeManifest
    let mut entrypoint = image.manifest.entrypoint.clone();
    if entrypoint.is_empty() {
        entrypoint = image.manifest.cmd.clone();
    } else if !image.manifest.cmd.is_empty() {
        entrypoint.extend(image.manifest.cmd.clone());
    }

    if !entrypoint.is_empty() {
        use hypr_core::manifest::runtime_manifest::{
            NetworkConfig as ManifestNetworkConfig, RuntimeManifest,
        };

        let env_vars: Vec<String> =
            image.manifest.env.iter().map(|(k, v)| format!("{}={}", k, v)).collect();

        let mut manifest = RuntimeManifest::new(entrypoint).with_env(env_vars);
        if !image.manifest.workdir.is_empty() {
            manifest = manifest.with_workdir(image.manifest.workdir.clone());
        }
        manifest = manifest.with_network(ManifestNetworkConfig {
            ip: vm_ip.to_string(),
            netmask: "255.255.255.0".to_string(),
            gateway: "10.88.0.1".to_string(),
            dns: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        });

        if let Ok(encoded) = manifest.encode() {
            vm_config.kernel_args.push(format!("manifest={}", encoded));
        }
    }

    // Create via adapter
    let handle = adapter.create(&vm_config).await?;

    // Save to state
    let vm = Vm {
        id: vm_config.id.clone(),
        name: vm_config.name.clone(),
        image_id: image.id.clone(),
        status: VmStatus::Creating,
        config: vm_config.clone(),
        ip_address: Some(vm_ip.to_string()),
        pid: handle.pid,
        created_at: SystemTime::now(),
        started_at: None,
        stopped_at: None,
    };
    state.insert_vm(&vm).await?;

    // Stage 3: Start VM
    send_run_progress(tx, "starting", "Starting VM...").await;
    adapter.start(&handle).await?;
    state.update_vm_status(&vm_config.id, VmStatus::Running).await?;

    // Done
    send_run_progress(tx, "running", &format!("VM {} running at {}", final_vm_name, vm_ip)).await;

    // Send complete event
    let final_vm = state.get_vm(&vm_config.id).await?;
    let event = RunVmEvent {
        event: Some(run_vm_event::Event::Complete(RunComplete { vm: Some(final_vm.into()) })),
    };
    let _ = tx.send(Ok(event)).await;

    Ok(())
}
