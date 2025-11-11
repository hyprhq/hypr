//! gRPC server implementation

use hypr_api::hypr::v1::hypr_service_server::{HyprService, HyprServiceServer};
use hypr_api::hypr::v1::*;
use hypr_core::adapters::VmmAdapter;
use hypr_core::{HyprError, Result, StateManager, Vm, VmConfig, VmStatus};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

/// gRPC service implementation
#[allow(dead_code)]
pub struct HyprServiceImpl {
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
}

impl HyprServiceImpl {
    pub fn new(state: Arc<StateManager>, adapter: Arc<dyn VmmAdapter>) -> Self {
        Self { state, adapter }
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
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("config required"))?;
        let vm_config: VmConfig = config
            .try_into()
            .map_err(|e: HyprError| Status::invalid_argument(e.to_string()))?;

        // Create VM via adapter
        let handle = self
            .adapter
            .create(&vm_config)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Create VM state
        let vm = Vm {
            id: vm_config.id.clone(),
            name: vm_config.name.clone(),
            image_id: "temp".to_string(), // TODO: extract from config
            status: VmStatus::Creating,
            config: vm_config,
            ip_address: None,
            pid: handle.pid,
            vsock_path: handle.socket_path,
            created_at: SystemTime::now(),
            started_at: None,
            stopped_at: None,
        };

        // Save to state
        self.state
            .insert_vm(&vm)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Convert domain → proto
        let response = CreateVmResponse {
            vm: Some(vm.into()),
        };

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
        let vm = self
            .state
            .get_vm(&req.id)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        // Create handle for adapter
        let handle = hypr_core::VmHandle {
            id: vm.id.clone(),
            pid: vm.pid,
            socket_path: vm.vsock_path.clone(),
        };

        // Start via adapter
        self.adapter
            .start(&handle)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Update state
        self.state
            .update_vm_status(&req.id, VmStatus::Running)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Fetch updated VM
        let vm = self
            .state
            .get_vm(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let response = StartVmResponse {
            vm: Some(vm.into()),
        };

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
        let vm = self
            .state
            .get_vm(&req.id)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        // Create handle for adapter
        let handle = hypr_core::VmHandle {
            id: vm.id.clone(),
            pid: vm.pid,
            socket_path: vm.vsock_path.clone(),
        };

        // Stop via adapter
        self.adapter
            .stop(&handle, timeout)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Update state
        self.state
            .update_vm_status(&req.id, VmStatus::Stopped)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Fetch updated VM
        let vm = self
            .state
            .get_vm(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let response = StopVmResponse {
            vm: Some(vm.into()),
        };

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
        let vm = self
            .state
            .get_vm(&req.id)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        // If force=false and VM is running, reject
        if !req.force && vm.status == VmStatus::Running {
            return Err(Status::failed_precondition(
                "VM is running. Stop it first or use force=true",
            ));
        }

        // Create handle for adapter
        let handle = hypr_core::VmHandle {
            id: vm.id.clone(),
            pid: vm.pid,
            socket_path: vm.vsock_path.clone(),
        };

        // Delete via adapter
        self.adapter
            .delete(&handle)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Delete from state
        self.state
            .delete_vm(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let response = DeleteVmResponse { success: true };

        Ok(Response::new(response))
    }

    #[instrument(skip(self))]
    async fn list_vms(
        &self,
        _request: Request<ListVmsRequest>,
    ) -> std::result::Result<Response<ListVmsResponse>, Status> {
        info!("gRPC: ListVMs");

        let vms = self
            .state
            .list_vms()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let response = ListVmsResponse {
            vms: vms.into_iter().map(|vm| vm.into()).collect(),
        };

        Ok(Response::new(response))
    }

    #[instrument(skip(self), fields(vm_id = %request.get_ref().id))]
    async fn get_vm(
        &self,
        request: Request<GetVmRequest>,
    ) -> std::result::Result<Response<GetVmResponse>, Status> {
        info!("gRPC: GetVM");

        let req = request.into_inner();

        let vm = self
            .state
            .get_vm(&req.id)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        let response = GetVmResponse {
            vm: Some(vm.into()),
        };

        Ok(Response::new(response))
    }

    #[instrument(skip(self))]
    async fn list_images(
        &self,
        _request: Request<ListImagesRequest>,
    ) -> std::result::Result<Response<ListImagesResponse>, Status> {
        info!("gRPC: ListImages");

        let images = self
            .state
            .list_images()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let response = ListImagesResponse {
            images: images.into_iter().map(|img| img.into()).collect(),
        };

        Ok(Response::new(response))
    }

    #[instrument(skip(self), fields(image_id = %request.get_ref().id))]
    async fn delete_image(
        &self,
        request: Request<DeleteImageRequest>,
    ) -> std::result::Result<Response<DeleteImageResponse>, Status> {
        info!("gRPC: DeleteImage");

        let req = request.into_inner();

        // TODO: Check if image is in use by any VMs
        if !req.force {
            let vms = self
                .state
                .list_vms()
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            if vms.iter().any(|vm| vm.image_id == req.id) {
                return Err(Status::failed_precondition(
                    "Image is in use by VMs. Use force=true to delete anyway",
                ));
            }
        }

        self.state
            .delete_image(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

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
}

/// Start the gRPC API server on Unix socket
#[allow(dead_code)]
#[instrument(skip(state, adapter))]
pub async fn start_api_server(
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
) -> Result<()> {
    let socket_path = "/tmp/hypr.sock";

    info!("Starting gRPC API server on {}", socket_path);

    // Remove old socket if exists
    let _ = std::fs::remove_file(socket_path);

    // Bind Unix socket
    let uds = UnixListener::bind(socket_path)
        .map_err(|e| HyprError::Internal(format!("Failed to bind socket: {}", e)))?;

    let uds_stream = UnixListenerStream::new(uds);

    // Create service
    let service = HyprServiceImpl::new(state, adapter);

    info!("gRPC server listening on {}", socket_path);

    // Start server
    Server::builder()
        .add_service(HyprServiceServer::new(service))
        .serve_with_incoming(uds_stream)
        .await
        .map_err(|e| HyprError::Internal(format!("Server error: {}", e)))?;

    Ok(())
}
