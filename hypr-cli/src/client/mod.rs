//! gRPC client for HYPR daemon

use anyhow::{Context, Result};
use hypr_api::hypr::v1::hypr_service_client::HyprServiceClient;
use hypr_api::hypr::v1::{self as proto, *};
use hypr_core::{Stack, Vm, VmConfig};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// Image information returned from daemon
pub struct ImageInfo {
    pub id: String,
    pub name: String,
    pub tag: String,
}

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

    /// Run a VM with streaming progress (image pull + create + start)
    pub async fn run_vm<F>(
        &mut self,
        image: &str,
        name: Option<String>,
        config: Option<proto::VmConfig>,
        mut on_progress: F,
    ) -> Result<Vm>
    where
        F: FnMut(&str, &str) + Send,  // (stage, message)
    {
        let request = tonic::Request::new(RunVmRequest {
            image: image.to_string(),
            name,
            config,
        });

        let mut stream = self.client.run_vm(request).await?.into_inner();
        let mut final_vm: Option<Vm> = None;

        while let Some(event) = stream.message().await? {
            match event.event {
                Some(run_vm_event::Event::Progress(progress)) => {
                    on_progress(&progress.stage, &progress.message);
                }
                Some(run_vm_event::Event::Complete(complete)) => {
                    if let Some(vm) = complete.vm {
                        final_vm = Some(vm.try_into()?);
                    }
                }
                Some(run_vm_event::Event::Error(error)) => {
                    return Err(anyhow::anyhow!("Run failed: {}", error.message));
                }
                None => {}
            }
        }

        final_vm.ok_or_else(|| anyhow::anyhow!("No VM returned"))
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

    /// Get an image by name and tag (auto-pulls from registry if not found locally)
    pub async fn get_image(&mut self, name: &str, tag: &str) -> Result<hypr_core::Image> {
        let request = tonic::Request::new(GetImageRequest {
            name: name.to_string(),
            tag: tag.to_string(),
            pull: true, // Auto-pull from registry if not found locally
        });

        let response = self.client.get_image(request).await?;
        let image =
            response.into_inner().image.ok_or_else(|| anyhow::anyhow!("No image in response"))?;

        Ok(image.try_into()?)
    }

    /// List all images
    pub async fn list_images(&mut self) -> Result<Vec<ImageInfo>> {
        let request = tonic::Request::new(ListImagesRequest { filter: None });

        let response = self.client.list_images(request).await?;
        let images = response
            .into_inner()
            .images
            .into_iter()
            .map(|img| ImageInfo { id: img.id, name: img.name, tag: img.tag })
            .collect();

        Ok(images)
    }

    /// Delete an image
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

    /// Deploy a stack from a compose file with streaming progress
    pub async fn deploy_stack<F>(
        &mut self,
        compose_file: &str,
        stack_name: Option<String>,
        detach: bool,
        force_recreate: bool,
        build: bool,
        mut on_progress: F,
    ) -> Result<Stack>
    where
        F: FnMut(&str, &str, &str) + Send, // (service, stage, message)
    {
        let request = tonic::Request::new(DeployStackRequest {
            compose_file: compose_file.to_string(),
            stack_name,
            detach,
            force_recreate,
            build,
        });

        let mut stream = self.client.deploy_stack(request).await?.into_inner();

        let mut final_stack: Option<Stack> = None;

        while let Some(event) = stream.message().await? {
            match event.event {
                Some(deploy_stack_event::Event::Progress(progress)) => {
                    on_progress(&progress.service, &progress.stage, &progress.message);
                }
                Some(deploy_stack_event::Event::Complete(complete)) => {
                    if let Some(stack) = complete.stack {
                        final_stack = Some(stack.try_into()?);
                    }
                }
                Some(deploy_stack_event::Event::Error(error)) => {
                    return Err(anyhow::anyhow!(
                        "Deploy failed for {}: {}",
                        if error.service.is_empty() { "stack" } else { &error.service },
                        error.message
                    ));
                }
                None => {}
            }
        }

        final_stack.ok_or_else(|| anyhow::anyhow!("No stack returned from deployment"))
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
