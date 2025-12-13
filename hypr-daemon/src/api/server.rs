//! gRPC server implementation

use crate::network_manager::NetworkManager;
use crate::orchestrator::StackOrchestrator;
use base64::Engine;
use hypr_api::hypr::v1::hypr_service_server::{HyprService, HyprServiceServer};
use hypr_api::hypr::v1::{self as proto, *};
use hypr_core::adapters::VmmAdapter;
use hypr_core::events::{Event, EventBus, EventType};
use hypr_core::metrics::MetricsCollector;
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
    metrics_collector: Arc<MetricsCollector>,
    event_bus: Arc<EventBus>,
}

impl HyprServiceImpl {
    pub fn new(
        state: Arc<StateManager>,
        adapter: Arc<dyn VmmAdapter>,
        network_mgr: Arc<NetworkManager>,
    ) -> Self {
        let orchestrator =
            Arc::new(StackOrchestrator::new(state.clone(), adapter.clone(), network_mgr.clone()));
        let metrics_collector = Arc::new(MetricsCollector::new());
        let event_bus = Arc::new(EventBus::new());
        Self { state, adapter, network_mgr, orchestrator, metrics_collector, event_bus }
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

            // Set network configuration using platform-aware defaults
            let net_defaults = hypr_core::network_defaults();
            manifest = manifest.with_network(ManifestNetworkConfig {
                ip: vm_ip.to_string(),
                netmask: net_defaults.netmask_str.to_string(),
                gateway: net_defaults.gateway.to_string(),
                dns: net_defaults.dns_servers.iter().map(|s| (*s).to_string()).collect(),
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

        // Start metrics collection for this VM
        let metrics_vsock_path = self.adapter.metrics_vsock_path(&handle);
        self.metrics_collector.start_vm_metrics(vm.id.clone(), metrics_vsock_path);

        // Update state
        self.state
            .update_vm_status(&req.id, VmStatus::Running)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Publish VM started event
        self.event_bus.publish(
            Event::new(EventType::VmStarted, &vm.id, &format!("VM {} started", vm.name))
                .with_metadata("name", &vm.name),
        );

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

        // Stop metrics collection for this VM
        self.metrics_collector.stop_vm_metrics(&req.id).await;

        // Update state
        self.state
            .update_vm_status(&req.id, VmStatus::Stopped)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Publish VM stopped event
        self.event_bus.publish(
            Event::new(EventType::VmStopped, &vm.id, &format!("VM {} stopped", vm.name))
                .with_metadata("name", &vm.name),
        );

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

    // =========================================================================
    // Network Operations
    // =========================================================================

    #[instrument(skip(self), fields(name = %request.get_ref().name))]
    async fn create_network(
        &self,
        request: Request<CreateNetworkRequest>,
    ) -> std::result::Result<Response<CreateNetworkResponse>, Status> {
        info!("gRPC: CreateNetwork");

        let req = request.into_inner();

        // Check if network with this name already exists
        let existing =
            self.state.list_networks().await.map_err(|e| Status::internal(e.to_string()))?;

        if existing.iter().any(|n| n.name == req.name) {
            return Err(Status::already_exists(format!("Network {} already exists", req.name)));
        }

        // Generate unique ID
        let id = uuid::Uuid::new_v4().to_string();

        // Parse or auto-generate subnet
        // For now, we'll use a simple scheme: vbr1, vbr2, etc. with 10.89.x.0/24
        let network_num = existing.len() + 1; // +1 because default is vbr0
        let cidr = req.subnet.unwrap_or_else(|| format!("10.{}.0.0/16", 88 + network_num));

        // Parse gateway from CIDR or use provided
        let gateway_str = req.gateway.unwrap_or_else(|| {
            // Extract base from CIDR and set gateway to .1
            if let Some(slash_pos) = cidr.find('/') {
                let base = &cidr[..slash_pos];
                if let Some(last_dot) = base.rfind('.') {
                    return format!("{}.1", &base[..last_dot]);
                }
            }
            format!("10.{}.0.1", 88 + network_num)
        });

        let gateway: std::net::Ipv4Addr =
            gateway_str.parse().map_err(|_| Status::invalid_argument("Invalid gateway IP"))?;

        let bridge_name = format!("vbr{}", network_num);

        let network = hypr_core::Network {
            id: id.clone(),
            name: req.name.clone(),
            driver: hypr_core::types::NetworkDriver::Bridge,
            cidr: cidr.clone(),
            gateway,
            bridge_name: bridge_name.clone(),
            created_at: std::time::SystemTime::now(),
        };

        // Store in database
        self.state.insert_network(&network).await.map_err(|e| Status::internal(e.to_string()))?;

        // TODO: Actually create the bridge interface (Linux only)
        // For now, this just stores the network metadata

        let proto_network = proto::Network {
            id,
            name: req.name,
            driver: "bridge".to_string(),
            cidr,
            gateway: gateway_str,
            bridge_name,
            created_at: network
                .created_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };

        Ok(Response::new(CreateNetworkResponse { network: Some(proto_network) }))
    }

    #[instrument(skip(self), fields(name = %request.get_ref().name))]
    async fn delete_network(
        &self,
        request: Request<DeleteNetworkRequest>,
    ) -> std::result::Result<Response<DeleteNetworkResponse>, Status> {
        info!("gRPC: DeleteNetwork");

        let req = request.into_inner();

        // Don't allow deleting the default network
        if req.name == "default" || req.name == "bridge" {
            return Err(Status::failed_precondition("Cannot delete the default network"));
        }

        // Find network by name
        let networks =
            self.state.list_networks().await.map_err(|e| Status::internal(e.to_string()))?;

        let network = networks
            .iter()
            .find(|n| n.name == req.name)
            .ok_or_else(|| Status::not_found(format!("Network {} not found", req.name)))?;

        // Check if network is in use (unless force)
        if !req.force {
            let vms = self.state.list_vms().await.map_err(|e| Status::internal(e.to_string()))?;

            // Check if any VM is using this network
            // For now, all VMs use the default network, so this check is placeholder
            let in_use = vms.iter().any(|vm| vm.config.network.network == req.name);
            if in_use {
                return Err(Status::failed_precondition(format!(
                    "Network {} is in use. Use force=true to delete anyway",
                    req.name
                )));
            }
        }

        // Delete from database
        self.state
            .delete_network(&network.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // TODO: Actually delete the bridge interface (Linux only)

        Ok(Response::new(DeleteNetworkResponse { success: true }))
    }

    #[instrument(skip(self))]
    async fn list_networks(
        &self,
        _request: Request<ListNetworksRequest>,
    ) -> std::result::Result<Response<ListNetworksResponse>, Status> {
        info!("gRPC: ListNetworks");

        let networks =
            self.state.list_networks().await.map_err(|e| Status::internal(e.to_string()))?;

        // Always include the default network (even if not in DB)
        let mut proto_networks: Vec<proto::Network> = networks
            .into_iter()
            .map(|n| proto::Network {
                id: n.id,
                name: n.name,
                driver: n.driver.to_string(),
                cidr: n.cidr,
                gateway: n.gateway.to_string(),
                bridge_name: n.bridge_name,
                created_at: n
                    .created_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            })
            .collect();

        // Add default network if not present
        if !proto_networks.iter().any(|n| n.name == "bridge" || n.name == "default") {
            let defaults = hypr_core::network::defaults::defaults();
            proto_networks.insert(
                0,
                proto::Network {
                    id: "default".to_string(),
                    name: "bridge".to_string(),
                    driver: "bridge".to_string(),
                    cidr: hypr_core::network::defaults::cidr().to_string(),
                    gateway: defaults.gateway.to_string(),
                    bridge_name: if cfg!(target_os = "linux") {
                        "vbr0".to_string()
                    } else {
                        "vmnet".to_string()
                    },
                    created_at: 0, // System default
                },
            );
        }

        Ok(Response::new(ListNetworksResponse { networks: proto_networks }))
    }

    #[instrument(skip(self), fields(name = %request.get_ref().name))]
    async fn get_network(
        &self,
        request: Request<GetNetworkRequest>,
    ) -> std::result::Result<Response<GetNetworkResponse>, Status> {
        info!("gRPC: GetNetwork");

        let req = request.into_inner();

        // Special case for default network
        if req.name == "bridge" || req.name == "default" {
            let defaults = hypr_core::network::defaults::defaults();
            return Ok(Response::new(GetNetworkResponse {
                network: Some(proto::Network {
                    id: "default".to_string(),
                    name: "bridge".to_string(),
                    driver: "bridge".to_string(),
                    cidr: hypr_core::network::defaults::cidr().to_string(),
                    gateway: defaults.gateway.to_string(),
                    bridge_name: if cfg!(target_os = "linux") {
                        "vbr0".to_string()
                    } else {
                        "vmnet".to_string()
                    },
                    created_at: 0,
                }),
            }));
        }

        // Look up custom network
        let networks =
            self.state.list_networks().await.map_err(|e| Status::internal(e.to_string()))?;

        let network = networks
            .into_iter()
            .find(|n| n.name == req.name)
            .ok_or_else(|| Status::not_found(format!("Network {} not found", req.name)))?;

        Ok(Response::new(GetNetworkResponse {
            network: Some(proto::Network {
                id: network.id,
                name: network.name,
                driver: network.driver.to_string(),
                cidr: network.cidr,
                gateway: network.gateway.to_string(),
                bridge_name: network.bridge_name,
                created_at: network
                    .created_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            }),
        }))
    }

    // =========================================================================
    // VM Metrics (Real-time monitoring)
    // =========================================================================

    type StreamVMMetricsStream =
        Pin<Box<dyn Stream<Item = std::result::Result<VmMetrics, Status>> + Send + 'static>>;

    async fn stream_vm_metrics(
        &self,
        request: Request<StreamVmMetricsRequest>,
    ) -> std::result::Result<Response<Self::StreamVMMetricsStream>, Status> {
        let req = request.into_inner();
        let vm_id = req.vm_id.clone();
        let interval_ms = if req.interval_ms == 0 { 1000 } else { req.interval_ms };

        // Verify VM exists
        self.state
            .get_vm(&vm_id)
            .await
            .map_err(|_| Status::not_found(format!("VM {} not found", vm_id)))?;

        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let metrics_collector = self.metrics_collector.clone();

        // Spawn metrics streaming task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(interval_ms as u64));
            loop {
                interval.tick().await;

                // Get real metrics from collector
                let metrics = if let Some(vm_metrics) = metrics_collector.get_metrics(&vm_id).await
                {
                    VmMetrics {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64,
                        cpu_percent: vm_metrics.cpu_percent,
                        memory_used_bytes: vm_metrics.raw.memory_used_kb * 1024,
                        memory_total_bytes: vm_metrics.raw.memory_total_kb * 1024,
                        disk_read_bytes: vm_metrics.raw.disk_read_bytes,
                        disk_write_bytes: vm_metrics.raw.disk_write_bytes,
                        network_rx_bytes: vm_metrics.raw.net_rx_bytes,
                        network_tx_bytes: vm_metrics.raw.net_tx_bytes,
                        pids: vm_metrics.raw.process_count,
                    }
                } else {
                    // No metrics yet, send zeros
                    VmMetrics {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64,
                        cpu_percent: 0.0,
                        memory_used_bytes: 0,
                        memory_total_bytes: 0,
                        disk_read_bytes: 0,
                        disk_write_bytes: 0,
                        network_rx_bytes: 0,
                        network_tx_bytes: 0,
                        pids: 0,
                    }
                };

                if tx.send(Ok(metrics)).await.is_err() {
                    break; // Client disconnected
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    // =========================================================================
    // Exec (Interactive PTY)
    // =========================================================================

    type ExecStream =
        Pin<Box<dyn Stream<Item = std::result::Result<ExecResponse, Status>> + Send + 'static>>;

    async fn exec(
        &self,
        request: Request<tonic::Streaming<ExecRequest>>,
    ) -> std::result::Result<Response<Self::ExecStream>, Status> {
        let mut in_stream = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let state = self.state.clone();
        let adapter = self.adapter.clone();

        tokio::spawn(async move {
            // Wait for ExecStart message
            let start_msg = match in_stream.next().await {
                Some(Ok(req)) => match req.message {
                    Some(exec_request::Message::Start(start)) => start,
                    _ => {
                        let _ = tx
                            .send(Err(Status::invalid_argument("First message must be ExecStart")))
                            .await;
                        return;
                    }
                },
                _ => {
                    let _ = tx.send(Err(Status::invalid_argument("No ExecStart received"))).await;
                    return;
                }
            };

            // Get VM and vsock path
            let vm = match state.get_vm(&start_msg.vm_id).await {
                Ok(vm) => vm,
                Err(_) => {
                    let _ = tx.send(Err(Status::not_found("VM not found"))).await;
                    return;
                }
            };

            let vsock_path =
                adapter.vsock_path(&VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None });

            // Send started confirmation
            let session_id = uuid::Uuid::new_v4().to_string();
            let _ = tx
                .send(Ok(ExecResponse {
                    message: Some(exec_response::Message::Started(ExecStarted {
                        session_id: session_id.clone(),
                    })),
                }))
                .await;

            // Connect to vsock and relay I/O
            // TODO: Implement actual vsock connection using kestrel exec protocol
            // For now, this is a placeholder that will be implemented with console multiplexing
            match tokio::net::UnixStream::connect(&vsock_path).await {
                Ok(stream) => {
                    let (mut reader, mut writer) = stream.into_split();

                    // Spawn reader task
                    let tx_clone = tx.clone();
                    let reader_task = tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await {
                                Ok(0) => break, // EOF
                                Ok(n) => {
                                    let _ = tx_clone
                                        .send(Ok(ExecResponse {
                                            message: Some(exec_response::Message::Stdout(
                                                buf[..n].to_vec(),
                                            )),
                                        }))
                                        .await;
                                }
                                Err(_) => break,
                            }
                        }
                    });

                    // Process input from client
                    while let Some(Ok(req)) = in_stream.next().await {
                        match req.message {
                            Some(exec_request::Message::Input(input)) => {
                                if tokio::io::AsyncWriteExt::write_all(&mut writer, &input.data)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Some(exec_request::Message::Resize(resize)) => {
                                // TODO: Send SIGWINCH to guest process
                                let _ = resize;
                            }
                            Some(exec_request::Message::Signal(sig)) => {
                                // TODO: Send signal to guest process
                                let _ = sig;
                            }
                            _ => {}
                        }
                    }

                    reader_task.abort();
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("Failed to connect to VM: {}", e))))
                        .await;
                }
            }

            // Send exit code
            let _ = tx
                .send(Ok(ExecResponse { message: Some(exec_response::Message::ExitCode(0)) }))
                .await;
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    // =========================================================================
    // Image History
    // =========================================================================

    async fn get_image_history(
        &self,
        request: Request<GetImageHistoryRequest>,
    ) -> std::result::Result<Response<GetImageHistoryResponse>, Status> {
        let req = request.into_inner();

        // Get the image
        let images = self.state.list_images().await.map_err(|e| Status::internal(e.to_string()))?;

        let image = images
            .into_iter()
            .find(|i| i.id == req.image_id)
            .ok_or_else(|| Status::not_found("Image not found"))?;

        // Convert stored history to proto format
        let layers: Vec<ImageLayer> = image
            .manifest
            .history
            .iter()
            .map(|h| ImageLayer {
                id: h.id.clone(),
                created_by: h.created_by.clone(),
                size_bytes: h.size_bytes,
                created_at: h.created_at,
                comment: h.comment.clone(),
                empty_layer: h.empty_layer,
            })
            .collect();

        Ok(Response::new(GetImageHistoryResponse { layers }))
    }

    // =========================================================================
    // Image Pull (Streaming)
    // =========================================================================

    type PullImageStream =
        Pin<Box<dyn Stream<Item = std::result::Result<PullEvent, Status>> + Send + 'static>>;

    async fn pull_image(
        &self,
        request: Request<PullImageRequest>,
    ) -> std::result::Result<Response<Self::PullImageStream>, Status> {
        let req = request.into_inner();
        let image_ref = req.image;
        let state = self.state.clone();

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        tokio::spawn(async move {
            // Send initial progress
            let _ = tx
                .send(Ok(PullEvent {
                    event: Some(pull_event::Event::Progress(PullProgress {
                        layer_id: String::new(),
                        status: "pulling".to_string(),
                        current: 0,
                        total: 0,
                    })),
                }))
                .await;

            // Create puller and pull image
            let mut puller = match ImagePuller::new() {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx
                        .send(Ok(PullEvent {
                            event: Some(pull_event::Event::Error(PullError {
                                message: e.to_string(),
                            })),
                        }))
                        .await;
                    return;
                }
            };

            match puller.pull(&image_ref).await {
                Ok(image) => {
                    // Save to state
                    if let Err(e) = state.insert_image(&image).await {
                        let _ = tx
                            .send(Ok(PullEvent {
                                event: Some(pull_event::Event::Error(PullError {
                                    message: format!("Failed to save image: {}", e),
                                })),
                            }))
                            .await;
                        return;
                    }

                    // Send complete
                    let _ = tx
                        .send(Ok(PullEvent {
                            event: Some(pull_event::Event::Complete(PullComplete {
                                image: Some(image.into()),
                            })),
                        }))
                        .await;
                }
                Err(e) => {
                    let _ = tx
                        .send(Ok(PullEvent {
                            event: Some(pull_event::Event::Error(PullError {
                                message: e.to_string(),
                            })),
                        }))
                        .await;
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    // =========================================================================
    // Image Build (Streaming)
    // =========================================================================

    type BuildImageStream =
        Pin<Box<dyn Stream<Item = std::result::Result<BuildEvent, Status>> + Send + 'static>>;

    async fn build_image(
        &self,
        request: Request<BuildImageRequest>,
    ) -> std::result::Result<Response<Self::BuildImageStream>, Status> {
        use hypr_core::builder::{build_image as core_build_image, register_image, BuildOptions};

        let req = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        let context_path = PathBuf::from(&req.context_path);
        let dockerfile =
            if req.dockerfile.is_empty() { "Dockerfile".to_string() } else { req.dockerfile };
        let tag = req.tag.clone();
        let build_args = req.build_args.clone();
        let target = req.target.clone().filter(|t| !t.is_empty());
        let no_cache = req.no_cache;
        let cache_from = req.cache_from.clone();
        let state = self.state.clone();

        // Parse tag into name and version
        let (image_name, image_tag) = if tag.contains(':') {
            let parts: Vec<&str> = tag.rsplitn(2, ':').collect();
            (parts[1].to_string(), parts[0].to_string())
        } else if tag.is_empty() {
            // Default to context directory name
            let name =
                context_path.file_name().and_then(|n| n.to_str()).unwrap_or("image").to_string();
            (name, "latest".to_string())
        } else {
            (tag.clone(), "latest".to_string())
        };

        tokio::spawn(async move {
            // Validate context exists
            if !context_path.exists() {
                let _ = tx
                    .send(Ok(BuildEvent {
                        event: Some(build_event::Event::Error(BuildError {
                            step_number: 0,
                            message: format!(
                                "Context path does not exist: {}",
                                context_path.display()
                            ),
                        })),
                    }))
                    .await;
                return;
            }

            let dockerfile_path = context_path.join(&dockerfile);
            if !dockerfile_path.exists() {
                let _ = tx
                    .send(Ok(BuildEvent {
                        event: Some(build_event::Event::Error(BuildError {
                            step_number: 0,
                            message: format!("Dockerfile not found: {}", dockerfile_path.display()),
                        })),
                    }))
                    .await;
                return;
            }

            // Send build started event
            let _ = tx
                .send(Ok(BuildEvent {
                    event: Some(build_event::Event::Step(BuildStep {
                        step_number: 0,
                        total_steps: 0,
                        instruction: format!("Starting build for {}:{}", image_name, image_tag),
                        cached: false,
                    })),
                }))
                .await;

            // Build options from request
            let options = BuildOptions {
                context_path: context_path.clone(),
                dockerfile,
                name: image_name.clone(),
                tag: image_tag.clone(),
                build_args,
                target,
                no_cache,
                cache_from,
            };

            // Execute the build using centralized API
            let build_result = match core_build_image(options).await {
                Ok(result) => result,
                Err(e) => {
                    let _ = tx
                        .send(Ok(BuildEvent {
                            event: Some(build_event::Event::Error(BuildError {
                                step_number: 0,
                                message: format!("Build failed: {}", e),
                            })),
                        }))
                        .await;
                    return;
                }
            };

            // Send build output event
            let _ = tx
                .send(Ok(BuildEvent {
                    event: Some(build_event::Event::Output(BuildOutput {
                        line: format!(
                            "Build completed in {:.1}s ({} layers, {} cached)",
                            build_result.duration_secs,
                            build_result.total_layers,
                            build_result.cached_layers
                        ),
                        stream: "stdout".to_string(),
                    })),
                }))
                .await;

            // Register the image in the database
            let image = match register_image(
                &build_result,
                &image_name,
                &image_tag,
                true, // overwrite existing
                &state,
            )
            .await
            {
                Ok(img) => img,
                Err(e) => {
                    let _ = tx
                        .send(Ok(BuildEvent {
                            event: Some(build_event::Event::Error(BuildError {
                                step_number: 0,
                                message: format!("Failed to register image: {}", e),
                            })),
                        }))
                        .await;
                    return;
                }
            };

            // Send completion event with image details
            let _ = tx
                .send(Ok(BuildEvent {
                    event: Some(build_event::Event::Complete(BuildComplete {
                        image: Some(image.into()),
                    })),
                }))
                .await;
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    // =========================================================================
    // Stack Service Logs
    // =========================================================================

    type StreamStackServiceLogsStream =
        Pin<Box<dyn Stream<Item = std::result::Result<LogEntry, Status>> + Send + 'static>>;

    async fn stream_stack_service_logs(
        &self,
        request: Request<StreamStackServiceLogsRequest>,
    ) -> std::result::Result<Response<Self::StreamStackServiceLogsStream>, Status> {
        let req = request.into_inner();

        // Get stack
        let stack = self
            .state
            .get_stack(&req.stack_name)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        // Find service in stack
        let service =
            stack.services.iter().find(|s| s.name == req.service_name).ok_or_else(|| {
                Status::not_found(format!("Service {} not found in stack", req.service_name))
            })?;

        // Stream logs from the service's VM
        let log_path = hypr_core::paths::logs_dir().join(format!("{}.log", service.vm_id));

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        let tail = req.tail as usize;
        let follow = req.follow;

        tokio::spawn(async move {
            if let Err(e) = stream_log_file(log_path, tx, tail, follow).await {
                warn!("Log streaming error: {}", e);
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    // =========================================================================
    // Volume Operations
    // =========================================================================

    async fn create_volume(
        &self,
        request: Request<CreateVolumeRequest>,
    ) -> std::result::Result<Response<CreateVolumeResponse>, Status> {
        let req = request.into_inner();

        // Generate volume ID
        let volume_id = format!("vol-{}", uuid::Uuid::new_v4());

        // Create volume directory
        let volumes_dir = hypr_core::paths::data_dir().join("volumes");
        let volume_path = volumes_dir.join(&volume_id);

        tokio::fs::create_dir_all(&volume_path)
            .await
            .map_err(|e| Status::internal(format!("Failed to create volume: {}", e)))?;

        // Create volume record
        let volume = hypr_core::types::volume::Volume {
            id: volume_id.clone(),
            name: req.name.clone(),
            volume_type: hypr_core::types::volume::VolumeType::Bind,
            path: volume_path.clone(),
            size_bytes: 0,
            created_at: SystemTime::now(),
        };

        self.state.insert_volume(&volume).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateVolumeResponse {
            volume: Some(proto::Volume {
                id: volume_id,
                name: req.name,
                driver: "local".to_string(),
                path: volume_path.to_string_lossy().to_string(),
                size_bytes: 0,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                used_by: vec![],
                labels: req.labels,
            }),
        }))
    }

    async fn delete_volume(
        &self,
        request: Request<DeleteVolumeRequest>,
    ) -> std::result::Result<Response<DeleteVolumeResponse>, Status> {
        let req = request.into_inner();

        // Get volume
        let volume =
            self.state.get_volume(&req.name).await.map_err(|e| Status::not_found(e.to_string()))?;

        // Delete from filesystem
        if volume.path.exists() {
            tokio::fs::remove_dir_all(&volume.path)
                .await
                .map_err(|e| Status::internal(format!("Failed to delete volume: {}", e)))?;
        }

        // Delete from state
        self.state.delete_volume(&req.name).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeleteVolumeResponse { success: true }))
    }

    async fn list_volumes(
        &self,
        _request: Request<ListVolumesRequest>,
    ) -> std::result::Result<Response<ListVolumesResponse>, Status> {
        let volumes =
            self.state.list_volumes().await.map_err(|e| Status::internal(e.to_string()))?;

        let proto_volumes: Vec<proto::Volume> = volumes
            .into_iter()
            .map(|v| proto::Volume {
                id: v.id,
                name: v.name,
                driver: "local".to_string(),
                path: v.path.to_string_lossy().to_string(),
                size_bytes: v.size_bytes,
                created_at: v.created_at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                    as i64,
                used_by: vec![],
                labels: HashMap::new(),
            })
            .collect();

        Ok(Response::new(ListVolumesResponse { volumes: proto_volumes }))
    }

    async fn get_volume(
        &self,
        request: Request<GetVolumeRequest>,
    ) -> std::result::Result<Response<GetVolumeResponse>, Status> {
        let req = request.into_inner();

        let volume =
            self.state.get_volume(&req.name).await.map_err(|e| Status::not_found(e.to_string()))?;

        Ok(Response::new(GetVolumeResponse {
            volume: Some(proto::Volume {
                id: volume.id,
                name: volume.name,
                driver: "local".to_string(),
                path: volume.path.to_string_lossy().to_string(),
                size_bytes: volume.size_bytes,
                created_at: volume
                    .created_at
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                used_by: vec![],
                labels: HashMap::new(),
            }),
        }))
    }

    async fn prune_volumes(
        &self,
        _request: Request<PruneVolumesRequest>,
    ) -> std::result::Result<Response<PruneVolumesResponse>, Status> {
        let volumes =
            self.state.list_volumes().await.map_err(|e| Status::internal(e.to_string()))?;

        let deleted = Vec::new();
        let reclaimed: u64 = 0;

        // TODO: Check which volumes are in use
        for volume in volumes {
            // For now, skip deletion - need to implement usage tracking
            let _ = volume;
        }

        Ok(Response::new(PruneVolumesResponse {
            volumes_deleted: deleted,
            space_reclaimed: reclaimed,
        }))
    }

    // =========================================================================
    // System Stats
    // =========================================================================

    async fn get_system_stats(
        &self,
        _request: Request<GetSystemStatsRequest>,
    ) -> std::result::Result<Response<GetSystemStatsResponse>, Status> {
        // Get counts
        let vms = self.state.list_vms().await.map_err(|e| Status::internal(e.to_string()))?;
        let images = self.state.list_images().await.map_err(|e| Status::internal(e.to_string()))?;
        let stacks = self.state.list_stacks().await.map_err(|e| Status::internal(e.to_string()))?;
        let networks =
            self.state.list_networks().await.map_err(|e| Status::internal(e.to_string()))?;
        let volumes =
            self.state.list_volumes().await.map_err(|e| Status::internal(e.to_string()))?;

        let running_vms = vms.iter().filter(|v| v.status == VmStatus::Running).count() as u32;
        let stopped_vms = vms.iter().filter(|v| v.status == VmStatus::Stopped).count() as u32;

        // Calculate resource allocation
        let total_cpus: u32 = vms
            .iter()
            .filter(|v| v.status == VmStatus::Running)
            .map(|v| v.config.resources.cpus)
            .sum();
        let total_memory: u64 = vms
            .iter()
            .filter(|v| v.status == VmStatus::Running)
            .map(|v| v.config.resources.memory_mb as u64)
            .sum();

        // Calculate disk usage
        let images_size: u64 = images.iter().map(|i| i.size_bytes).sum();
        let volumes_size: u64 = volumes.iter().map(|v| v.size_bytes).sum();

        // Get cache and logs directory sizes
        let cache_size = dir_size(&hypr_core::paths::cache_dir()).await;
        let logs_size = dir_size(&hypr_core::paths::logs_dir()).await;

        Ok(Response::new(GetSystemStatsResponse {
            total_vms: vms.len() as u32,
            running_vms,
            stopped_vms,
            total_cpus_allocated: total_cpus,
            total_memory_allocated_mb: total_memory,
            total_disk_used_bytes: images_size + volumes_size + cache_size + logs_size,
            images_disk_used_bytes: images_size,
            volumes_disk_used_bytes: volumes_size,
            cache_disk_used_bytes: cache_size,
            logs_disk_used_bytes: logs_size,
            total_images: images.len() as u32,
            total_stacks: stacks.len() as u32,
            total_networks: networks.len() as u32,
            total_volumes: volumes.len() as u32,
        }))
    }

    // =========================================================================
    // Settings
    // =========================================================================

    async fn get_settings(
        &self,
        _request: Request<GetSettingsRequest>,
    ) -> std::result::Result<Response<GetSettingsResponse>, Status> {
        Ok(Response::new(GetSettingsResponse {
            settings: Some(proto::Settings {
                default_cpus: 2,
                default_memory_mb: 512,
                auto_start_daemon: true,
                start_at_login: false,
                log_level: "info".to_string(),
                max_concurrent_builds: 4,
                cache_size_limit_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
                log_retention_days: 7,
                telemetry_enabled: false,
                data_dir: hypr_core::paths::data_dir().to_string_lossy().to_string(),
                runtime_dir: hypr_core::paths::runtime_dir().to_string_lossy().to_string(),
                socket_path: "/tmp/hypr.sock".to_string(),
            }),
        }))
    }

    async fn update_settings(
        &self,
        request: Request<UpdateSettingsRequest>,
    ) -> std::result::Result<Response<UpdateSettingsResponse>, Status> {
        let req = request.into_inner();

        // TODO: Persist settings to config file
        // For now, just return the settings back
        Ok(Response::new(UpdateSettingsResponse { settings: req.settings }))
    }

    // =========================================================================
    // Event Subscription
    // =========================================================================

    type SubscribeEventsStream =
        Pin<Box<dyn Stream<Item = std::result::Result<HyprEvent, Status>> + Send + 'static>>;

    async fn subscribe_events(
        &self,
        request: Request<SubscribeEventsRequest>,
    ) -> std::result::Result<Response<Self::SubscribeEventsStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        // Subscribe to event bus with filters
        let mut subscriber = self.event_bus.subscribe(req.event_types);

        // Spawn task to forward events
        tokio::spawn(async move {
            while let Some(event) = subscriber.recv().await {
                // Convert internal Event to proto HyprEvent
                let hypr_event = HyprEvent {
                    timestamp: event.timestamp,
                    r#type: event.event_type,
                    resource_type: event.resource_type,
                    resource_id: event.resource_id,
                    action: event.action,
                    message: event.message,
                    metadata: event.metadata,
                };

                if tx.send(Ok(hypr_event)).await.is_err() {
                    break; // Client disconnected
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    // =========================================================================
    // Templates (P0)
    // =========================================================================

    async fn list_templates(
        &self,
        request: Request<ListTemplatesRequest>,
    ) -> std::result::Result<Response<ListTemplatesResponse>, Status> {
        info!("gRPC: ListTemplates");

        let req = request.into_inner();
        let registry = hypr_core::templates::TemplateRegistry::new();

        let templates: Vec<&hypr_core::templates::Template> =
            if let Some(ref category) = req.category {
                if let Some(cat) = hypr_core::templates::TemplateCategory::parse(category) {
                    registry.list_by_category(cat)
                } else {
                    registry.list()
                }
            } else if let Some(ref search) = req.search {
                registry.search(search)
            } else {
                registry.list()
            };

        let proto_templates: Vec<proto::Template> = templates
            .into_iter()
            .map(|t| proto::Template {
                id: t.id.clone(),
                name: t.name.clone(),
                description: t.description.clone(),
                category: t.category.as_str().to_string(),
                image: t.image.clone(),
                default_resources: Some(proto::VmResources {
                    cpus: t.default_resources.cpus,
                    memory_mb: t.default_resources.memory_mb,
                    balloon_enabled: t.default_resources.balloon_enabled,
                }),
                default_ports: t
                    .default_ports
                    .iter()
                    .map(|p| proto::PortMapping {
                        host_port: p.host_port as u32,
                        guest_port: p.vm_port as u32,
                        protocol: match p.protocol {
                            hypr_core::types::network::Protocol::Tcp => "tcp".to_string(),
                            hypr_core::types::network::Protocol::Udp => "udp".to_string(),
                        },
                    })
                    .collect(),
                default_env: t.default_env.clone(),
                tags: t.tags.clone(),
                icon_url: t.icon_url.clone().unwrap_or_default(),
                builtin: t.builtin,
            })
            .collect();

        Ok(Response::new(ListTemplatesResponse { templates: proto_templates }))
    }

    async fn get_template(
        &self,
        request: Request<GetTemplateRequest>,
    ) -> std::result::Result<Response<GetTemplateResponse>, Status> {
        info!("gRPC: GetTemplate");

        let req = request.into_inner();
        let registry = hypr_core::templates::TemplateRegistry::new();

        let template = registry
            .get(&req.id)
            .ok_or_else(|| Status::not_found(format!("Template {} not found", req.id)))?;

        let proto_template = proto::Template {
            id: template.id.clone(),
            name: template.name.clone(),
            description: template.description.clone(),
            category: template.category.as_str().to_string(),
            image: template.image.clone(),
            default_resources: Some(proto::VmResources {
                cpus: template.default_resources.cpus,
                memory_mb: template.default_resources.memory_mb,
                balloon_enabled: template.default_resources.balloon_enabled,
            }),
            default_ports: template
                .default_ports
                .iter()
                .map(|p| proto::PortMapping {
                    host_port: p.host_port as u32,
                    guest_port: p.vm_port as u32,
                    protocol: match p.protocol {
                        hypr_core::types::network::Protocol::Tcp => "tcp".to_string(),
                        hypr_core::types::network::Protocol::Udp => "udp".to_string(),
                    },
                })
                .collect(),
            default_env: template.default_env.clone(),
            tags: template.tags.clone(),
            icon_url: template.icon_url.clone().unwrap_or_default(),
            builtin: template.builtin,
        };

        Ok(Response::new(GetTemplateResponse { template: Some(proto_template) }))
    }

    type CreateFromTemplateStream =
        Pin<Box<dyn Stream<Item = std::result::Result<RunVmEvent, Status>> + Send + 'static>>;

    async fn create_from_template(
        &self,
        request: Request<CreateFromTemplateRequest>,
    ) -> std::result::Result<Response<Self::CreateFromTemplateStream>, Status> {
        info!("gRPC: CreateFromTemplate");

        let req = request.into_inner();
        let registry = hypr_core::templates::TemplateRegistry::new();

        let template = registry
            .get(&req.template_id)
            .ok_or_else(|| Status::not_found(format!("Template {} not found", req.template_id)))?
            .clone();

        // Merge template env with request env (request overrides template)
        let mut env = template.default_env.clone();
        env.extend(req.env);

        // Merge ports
        let mut ports: Vec<proto::PortMapping> = template
            .default_ports
            .iter()
            .map(|p| proto::PortMapping {
                host_port: p.host_port as u32,
                guest_port: p.vm_port as u32,
                protocol: match p.protocol {
                    hypr_core::types::network::Protocol::Tcp => "tcp".to_string(),
                    hypr_core::types::network::Protocol::Udp => "udp".to_string(),
                },
            })
            .collect();
        ports.extend(req.ports);

        // Build config from template
        let resources = req.resources.unwrap_or(proto::VmResources {
            cpus: template.default_resources.cpus,
            memory_mb: template.default_resources.memory_mb,
            balloon_enabled: template.default_resources.balloon_enabled,
        });

        let config = proto::VmConfig {
            id: String::new(),
            name: String::new(),
            resources: Some(resources),
            disks: vec![],
            network: None,
            ports,
            env,
            volumes: vec![],
            kernel_args: vec![],
            kernel_path: None,
            gpu: None,
            vsock_path: String::new(),
        };

        // Create channel for progress events
        let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<RunVmEvent, Status>>(100);

        // Clone what we need for the spawned task
        let state = self.state.clone();
        let adapter = self.adapter.clone();
        let network_mgr = self.network_mgr.clone();
        let image = template.image;
        let vm_name = req.name;

        tokio::spawn(async move {
            let result = run_vm_with_progress(
                &state,
                &adapter,
                &network_mgr,
                &image,
                vm_name,
                Some(config),
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
        Ok(Response::new(Box::pin(stream) as Self::CreateFromTemplateStream))
    }

    // =========================================================================
    // Snapshots (P0)
    // =========================================================================

    async fn create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> std::result::Result<Response<proto::Snapshot>, Status> {
        info!("gRPC: CreateSnapshot");

        let req = request.into_inner();

        let snapshot_type = match req.snapshot_type {
            x if x == proto::SnapshotType::Disk as i32 => hypr_core::snapshots::SnapshotType::Disk,
            x if x == proto::SnapshotType::Full as i32 => hypr_core::snapshots::SnapshotType::Full,
            _ => hypr_core::snapshots::SnapshotType::Disk,
        };

        let manager = hypr_core::snapshots::SnapshotManager::new(self.state.clone());

        let snapshot = manager
            .create(&req.vm_id, &req.name, snapshot_type, req.description, req.labels)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(snapshot_to_proto(&snapshot)))
    }

    async fn restore_snapshot(
        &self,
        request: Request<RestoreSnapshotRequest>,
    ) -> std::result::Result<Response<proto::Vm>, Status> {
        info!("gRPC: RestoreSnapshot");

        let req = request.into_inner();

        let manager = hypr_core::snapshots::SnapshotManager::new(self.state.clone());

        let vm = manager
            .restore(&req.snapshot_id, req.new_vm_name.as_deref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // If start_after_restore is requested, start the VM
        if req.start_after_restore {
            let handle = hypr_core::VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };
            self.adapter.start(&handle).await.map_err(|e| Status::internal(e.to_string()))?;
            self.state
                .update_vm_status(&vm.id, VmStatus::Running)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }

        let updated_vm =
            self.state.get_vm(&vm.id).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(updated_vm.into()))
    }

    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> std::result::Result<Response<ListSnapshotsResponse>, Status> {
        info!("gRPC: ListSnapshots");

        let req = request.into_inner();

        let snapshots = self
            .state
            .list_snapshots(req.vm_id.as_deref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Filter by name prefix if provided
        let filtered: Vec<_> = if let Some(ref name_prefix) = req.name {
            snapshots.into_iter().filter(|s| s.name.starts_with(name_prefix)).collect()
        } else {
            snapshots
        };

        let proto_snapshots: Vec<proto::Snapshot> =
            filtered.iter().map(snapshot_to_proto).collect();

        Ok(Response::new(ListSnapshotsResponse { snapshots: proto_snapshots }))
    }

    async fn get_snapshot(
        &self,
        request: Request<GetSnapshotRequest>,
    ) -> std::result::Result<Response<GetSnapshotResponse>, Status> {
        info!("gRPC: GetSnapshot");

        let req = request.into_inner();

        let snapshot =
            self.state.get_snapshot(&req.id).await.map_err(|e| Status::not_found(e.to_string()))?;

        Ok(Response::new(GetSnapshotResponse { snapshot: Some(snapshot_to_proto(&snapshot)) }))
    }

    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> std::result::Result<Response<DeleteSnapshotResponse>, Status> {
        info!("gRPC: DeleteSnapshot");

        let req = request.into_inner();

        let manager = hypr_core::snapshots::SnapshotManager::new(self.state.clone());

        manager.delete(&req.id).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeleteSnapshotResponse { success: true }))
    }

    // =========================================================================
    // Metrics History (P1)
    // =========================================================================

    async fn get_metrics_history(
        &self,
        request: Request<GetMetricsHistoryRequest>,
    ) -> std::result::Result<Response<GetMetricsHistoryResponse>, Status> {
        info!("gRPC: GetMetricsHistory");

        let req = request.into_inner();

        let resolution = hypr_core::metrics::MetricsResolution::from_i32(req.resolution)
            .unwrap_or(hypr_core::metrics::MetricsResolution::Raw);

        let history = hypr_core::metrics::MetricsHistory::new(self.state.clone());

        let data_points = history
            .query(&req.vm_id, req.start_time, req.end_time, resolution)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_points: Vec<proto::MetricsDataPoint> = data_points
            .into_iter()
            .map(|p| proto::MetricsDataPoint {
                timestamp: p.timestamp,
                cpu_percent: p.cpu_percent,
                memory_percent: p.memory_percent,
                memory_used_bytes: p.memory_used_bytes,
                net_rx_rate: p.net_rx_rate,
                net_tx_rate: p.net_tx_rate,
                disk_read_rate: p.disk_read_rate,
                disk_write_rate: p.disk_write_rate,
            })
            .collect();

        Ok(Response::new(GetMetricsHistoryResponse {
            vm_id: req.vm_id,
            data_points: proto_points,
            resolution: resolution.to_i32(),
        }))
    }

    // =========================================================================
    // Process Explorer (P1)
    // =========================================================================

    async fn list_vm_processes(
        &self,
        request: Request<ListVmProcessesRequest>,
    ) -> std::result::Result<Response<ListVmProcessesResponse>, Status> {
        info!("gRPC: ListVMProcesses");

        let req = request.into_inner();

        // Get VM to find vsock path
        let vm =
            self.state.get_vm(&req.vm_id).await.map_err(|e| Status::not_found(e.to_string()))?;

        let vsock_path = self.adapter.vsock_path(&hypr_core::VmHandle {
            id: vm.id.clone(),
            pid: vm.pid,
            socket_path: None,
        });

        let sort_by = req
            .sort_by
            .as_deref()
            .and_then(hypr_core::process::ProcessSortBy::parse)
            .unwrap_or_default();

        let descending = req.descending.unwrap_or(true);
        let limit = req.limit.map(|l| l as usize);

        let explorer = hypr_core::process::ProcessExplorer::new();

        let processes = explorer
            .list_processes(&vsock_path, sort_by, descending, limit)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_processes: Vec<proto::VmProcess> =
            processes.into_iter().map(vm_process_to_proto).collect();

        Ok(Response::new(ListVmProcessesResponse {
            vm_id: req.vm_id,
            processes: proto_processes,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                as i64,
        }))
    }

    async fn get_vm_process(
        &self,
        request: Request<GetVmProcessRequest>,
    ) -> std::result::Result<Response<proto::VmProcess>, Status> {
        info!("gRPC: GetVMProcess");

        let req = request.into_inner();

        // Get VM to find vsock path
        let vm =
            self.state.get_vm(&req.vm_id).await.map_err(|e| Status::not_found(e.to_string()))?;

        let vsock_path = self.adapter.vsock_path(&hypr_core::VmHandle {
            id: vm.id.clone(),
            pid: vm.pid,
            socket_path: None,
        });

        let explorer = hypr_core::process::ProcessExplorer::new();

        let process = explorer
            .get_process(&vsock_path, req.pid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(vm_process_to_proto(process)))
    }

    async fn signal_vm_process(
        &self,
        request: Request<SignalVmProcessRequest>,
    ) -> std::result::Result<Response<SignalVmProcessResponse>, Status> {
        info!("gRPC: SignalVMProcess");

        let req = request.into_inner();

        // Get VM to find vsock path
        let vm =
            self.state.get_vm(&req.vm_id).await.map_err(|e| Status::not_found(e.to_string()))?;

        let vsock_path = self.adapter.vsock_path(&hypr_core::VmHandle {
            id: vm.id.clone(),
            pid: vm.pid,
            socket_path: None,
        });

        let explorer = hypr_core::process::ProcessExplorer::new();

        explorer
            .signal_process(&vsock_path, req.pid, req.signal)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SignalVmProcessResponse { success: true }))
    }
}

/// Convert a VM process to proto format.
fn vm_process_to_proto(p: hypr_core::process::VMProcess) -> proto::VmProcess {
    proto::VmProcess {
        pid: p.pid,
        ppid: p.ppid,
        name: p.name,
        command: p.command,
        user: p.user,
        cpu_percent: p.cpu_percent,
        memory_percent: p.memory_percent,
        memory_rss: p.memory_rss,
        memory_vsz: p.memory_vsz,
        state: p.state,
        start_time: p.start_time,
        cpu_time_ms: p.cpu_time_ms,
    }
}

/// Convert a snapshot to proto format.
fn snapshot_to_proto(snapshot: &hypr_core::snapshots::Snapshot) -> proto::Snapshot {
    proto::Snapshot {
        id: snapshot.id.clone(),
        vm_id: snapshot.vm_id.clone(),
        name: snapshot.name.clone(),
        description: snapshot.description.clone().unwrap_or_default(),
        size_bytes: snapshot.size_bytes,
        created_at: snapshot
            .created_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        state: snapshot.state.as_str().to_string(),
        labels: snapshot.labels.clone(),
        snapshot_type: match snapshot.snapshot_type {
            hypr_core::snapshots::SnapshotType::Disk => proto::SnapshotType::Disk as i32,
            hypr_core::snapshots::SnapshotType::Full => proto::SnapshotType::Full as i32,
        },
    }
}

/// Calculate directory size recursively
async fn dir_size(path: &std::path::Path) -> u64 {
    let mut size = 0u64;
    if let Ok(mut entries) = tokio::fs::read_dir(path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                if metadata.is_file() {
                    size += metadata.len();
                } else if metadata.is_dir() {
                    size += Box::pin(dir_size(&entry.path())).await;
                }
            }
        }
    }
    size
}

/// Start the gRPC API server on the default Unix socket (/tmp/hypr.sock)
#[allow(dead_code)]
#[instrument(skip(state, adapter, network_mgr))]
pub async fn start_api_server(
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
    network_mgr: Arc<NetworkManager>,
) -> Result<()> {
    start_api_server_at(state, adapter, network_mgr, "/tmp/hypr.sock".to_string()).await
}

/// Start the gRPC API server on a custom Unix socket path
#[allow(dead_code)]
#[instrument(skip(state, adapter, network_mgr))]
pub async fn start_api_server_at(
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
    network_mgr: Arc<NetworkManager>,
    socket_path: String,
) -> Result<()> {
    info!("Starting gRPC API server on {}", socket_path);

    // Remove old socket if exists
    let _ = std::fs::remove_file(&socket_path);

    // Bind Unix socket
    let uds = UnixListener::bind(&socket_path)
        .map_err(|e| HyprError::Internal(format!("Failed to bind socket: {}", e)))?;

    // SECURITY: Socket permissions control who can communicate with the daemon.
    // Using 0o660 restricts access to owner (root) and the 'hypr' group.
    // Users who need to use `hypr` CLI without sudo should be added to the 'hypr' group:
    //   sudo groupadd hypr && sudo usermod -aG hypr $USER
    //
    // Note: 0o666 (world-writable) was previously used but is a security risk because
    // anyone on the system could control VMs or mount host directories.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| HyprError::Internal(format!("Failed to set socket permissions: {}", e)))?;

    // Try to set group ownership to 'hypr' group if it exists
    // This allows non-root users in the hypr group to use the CLI
    {
        use std::ffi::CString;
        if let Ok(socket_cstr) = CString::new(socket_path.as_str()) {
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

        // Set network configuration using platform-aware defaults
        let net_defaults = hypr_core::network_defaults();
        manifest = manifest.with_network(ManifestNetworkConfig {
            ip: vm_ip.to_string(),
            netmask: net_defaults.netmask_str.to_string(),
            gateway: net_defaults.gateway.to_string(),
            dns: net_defaults.dns_servers.iter().map(|s| (*s).to_string()).collect(),
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
