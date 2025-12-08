//! gRPC client for HYPR daemon

use anyhow::{Context, Result};
use hypr_api::hypr::v1::hypr_service_client::HyprServiceClient;
use hypr_api::hypr::v1::*;
use hypr_core::{Stack, Vm, VmConfig};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// HYPR gRPC client
pub struct HyprClient {
    client: HyprServiceClient<Channel>,
}

impl HyprClient {
    /// Connect to the HYPR daemon via Unix socket
    pub async fn connect() -> Result<Self> {
        let socket_path = "/tmp/hypr.sock";

        // Create a dummy URI (required by tonic but not used for Unix sockets)
        let channel = Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(service_fn(move |_: Uri| UnixStream::connect(socket_path)))
            .await
            .context("Failed to connect to hyprd. Is the daemon running?")?;

        let client = HyprServiceClient::new(channel);

        Ok(Self { client })
    }

    /// Create a new VM
    pub async fn create_vm(&mut self, config: VmConfig, image: String) -> Result<Vm> {
        let request = tonic::Request::new(CreateVmRequest {
            name: config.name.clone(),
            config: Some(config.into()),
            image,
        });

        let response = self.client.create_vm(request).await?;
        let vm = response.into_inner().vm.ok_or_else(|| anyhow::anyhow!("No VM in response"))?;

        Ok(vm.try_into()?)
    }

    /// Start a VM
    pub async fn start_vm(&mut self, id: &str) -> Result<Vm> {
        let request = tonic::Request::new(StartVmRequest { id: id.to_string() });

        let response = self.client.start_vm(request).await?;
        let vm = response.into_inner().vm.ok_or_else(|| anyhow::anyhow!("No VM in response"))?;

        Ok(vm.try_into()?)
    }

    /// Stop a VM
    pub async fn stop_vm(&mut self, id: &str, timeout_sec: Option<u32>) -> Result<Vm> {
        let request = tonic::Request::new(StopVmRequest { id: id.to_string(), timeout_sec });

        let response = self.client.stop_vm(request).await?;
        let vm = response.into_inner().vm.ok_or_else(|| anyhow::anyhow!("No VM in response"))?;

        Ok(vm.try_into()?)
    }

    /// Delete a VM
    pub async fn delete_vm(&mut self, id: &str, force: bool) -> Result<bool> {
        let request = tonic::Request::new(DeleteVmRequest { id: id.to_string(), force });

        let response = self.client.delete_vm(request).await?;
        Ok(response.into_inner().success)
    }

    /// List all VMs
    pub async fn list_vms(&mut self) -> Result<Vec<Vm>> {
        let request = tonic::Request::new(ListVmsRequest { filter: None });

        let response = self.client.list_vms(request).await?;
        let vms = response
            .into_inner()
            .vms
            .into_iter()
            .map(|vm| vm.try_into())
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(vms)
    }

    /// Get a specific VM
    #[allow(dead_code)]
    pub async fn get_vm(&mut self, id: &str) -> Result<Vm> {
        let request = tonic::Request::new(GetVmRequest { id: id.to_string() });

        let response = self.client.get_vm(request).await?;
        let vm = response.into_inner().vm.ok_or_else(|| anyhow::anyhow!("No VM in response"))?;

        Ok(vm.try_into()?)
    }

    /// Get an image by name and tag
    pub async fn get_image(&mut self, name: &str, tag: &str) -> Result<hypr_core::Image> {
        let request =
            tonic::Request::new(GetImageRequest { name: name.to_string(), tag: tag.to_string() });

        let response = self.client.get_image(request).await?;
        let image =
            response.into_inner().image.ok_or_else(|| anyhow::anyhow!("No image in response"))?;

        Ok(image.try_into()?)
    }

    /// Delete an image
    #[allow(dead_code)]
    pub async fn delete_image(&mut self, id: &str, force: bool) -> Result<bool> {
        let request = tonic::Request::new(DeleteImageRequest { id: id.to_string(), force });

        let response = self.client.delete_image(request).await?;
        Ok(response.into_inner().success)
    }

    /// Check daemon health
    pub async fn health(&mut self) -> Result<(String, String)> {
        let request = tonic::Request::new(HealthRequest {});

        let response = self.client.health(request).await?;
        let health = response.into_inner();

        Ok((health.status, health.version))
    }

    /// Deploy a stack from a compose file
    pub async fn deploy_stack(
        &mut self,
        compose_file: &str,
        stack_name: Option<String>,
        detach: bool,
        force_recreate: bool,
        build: bool,
    ) -> Result<Stack> {
        let request = tonic::Request::new(DeployStackRequest {
            compose_file: compose_file.to_string(),
            stack_name,
            detach,
            force_recreate,
            build,
        });

        let response = self.client.deploy_stack(request).await?;
        let stack =
            response.into_inner().stack.ok_or_else(|| anyhow::anyhow!("No stack in response"))?;

        Ok(stack.try_into()?)
    }

    /// Destroy a stack
    pub async fn destroy_stack(&mut self, stack_name: &str, force: bool) -> Result<bool> {
        let request =
            tonic::Request::new(DestroyStackRequest { stack_name: stack_name.to_string(), force });

        let response = self.client.destroy_stack(request).await?;
        Ok(response.into_inner().success)
    }

    /// List all stacks
    pub async fn list_stacks(&mut self) -> Result<Vec<Stack>> {
        let request = tonic::Request::new(ListStacksRequest { filter: None });

        let response = self.client.list_stacks(request).await?;
        let stacks = response
            .into_inner()
            .stacks
            .into_iter()
            .map(|s| s.try_into())
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(stacks)
    }

    /// Get a specific stack
    pub async fn get_stack(&mut self, stack_name: &str) -> Result<Stack> {
        let request = tonic::Request::new(GetStackRequest { stack_name: stack_name.to_string() });

        let response = self.client.get_stack(request).await?;
        let stack =
            response.into_inner().stack.ok_or_else(|| anyhow::anyhow!("No stack in response"))?;

        Ok(stack.try_into()?)
    }

    /// Stream logs from a VM
    pub async fn stream_logs(
        &mut self,
        vm_id: &str,
        follow: bool,
        tail: u32,
    ) -> Result<tonic::Streaming<LogEntry>> {
        let request = tonic::Request::new(StreamLogsRequest {
            vm_id: vm_id.to_string(),
            follow,
            tail,
            since: None,
        });

        let response = self.client.stream_logs(request).await?;
        Ok(response.into_inner())
    }
}
