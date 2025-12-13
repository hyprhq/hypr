//! gRPC client for HYPR daemon

use anyhow::{Context, Result};
use hypr_api::hypr::v1::hypr_service_client::HyprServiceClient;
use hypr_api::hypr::v1::{self as proto, *};
use hypr_core::{Stack, Vm, VmConfig};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
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
    /// Connect to the HYPR daemon via Unix socket at default path
    pub async fn connect() -> Result<Self> {
        Self::connect_at("/tmp/hypr.sock").await
    }

    /// Connect to the HYPR daemon via Unix socket at a custom path
    pub async fn connect_at(socket_path: &str) -> Result<Self> {
        let path = socket_path.to_string();

        // Create a dummy URI (required by tonic but not used for Unix sockets)
        let channel = Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move { UnixStream::connect(path).await }
            }))
            .await
            .context("Failed to connect to hyprd. Is the daemon running?")?;

        let client = HyprServiceClient::new(channel);

        Ok(Self { client })
    }

    /// Create a new VM (use run_vm for streaming progress)
    #[allow(dead_code)]
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
        F: FnMut(&str, &str) + Send, // (stage, message)
    {
        let request = tonic::Request::new(RunVmRequest { image: image.to_string(), name, config });

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

    // Network operations

    /// List all networks
    pub async fn list_networks(&mut self) -> Result<Vec<Network>> {
        let request = tonic::Request::new(ListNetworksRequest { filter: None });
        let response = self.client.list_networks(request).await?;
        Ok(response.into_inner().networks)
    }

    /// Create a new network
    pub async fn create_network(
        &mut self,
        name: &str,
        subnet: Option<&str>,
        gateway: Option<&str>,
        _driver: &str,
    ) -> Result<Network> {
        let request = tonic::Request::new(CreateNetworkRequest {
            name: name.to_string(),
            driver: Some("bridge".to_string()),
            subnet: subnet.map(String::from),
            gateway: gateway.map(String::from),
        });
        let response = self.client.create_network(request).await?;
        response.into_inner().network.ok_or_else(|| anyhow::anyhow!("No network returned"))
    }

    /// Delete a network
    pub async fn delete_network(&mut self, name: &str, force: bool) -> Result<bool> {
        let request = tonic::Request::new(DeleteNetworkRequest { name: name.to_string(), force });
        let response = self.client.delete_network(request).await?;
        Ok(response.into_inner().success)
    }

    /// Get network details
    pub async fn get_network(&mut self, name: &str) -> Result<Network> {
        let request = tonic::Request::new(GetNetworkRequest { name: name.to_string() });
        let response = self.client.get_network(request).await?;
        response.into_inner().network.ok_or_else(|| anyhow::anyhow!("Network not found"))
    }

    /// Build an image with streaming progress
    #[allow(clippy::too_many_arguments)]
    pub async fn build_image<F>(
        &mut self,
        context_path: &str,
        dockerfile: &str,
        tag: &str,
        build_args: HashMap<String, String>,
        target: Option<String>,
        no_cache: bool,
        cache_from: Vec<String>,
        mut on_event: F,
    ) -> Result<hypr_core::Image>
    where
        F: FnMut(BuildEventKind) + Send,
    {
        let request = tonic::Request::new(BuildImageRequest {
            context_path: context_path.to_string(),
            dockerfile: dockerfile.to_string(),
            tag: tag.to_string(),
            build_args,
            target,
            no_cache,
            pull: false,
            cache_from,
        });

        let mut stream = self.client.build_image(request).await?.into_inner();
        let mut final_image: Option<hypr_core::Image> = None;

        while let Some(event) = stream.message().await? {
            match event.event {
                Some(build_event::Event::Step(step)) => {
                    on_event(BuildEventKind::Step {
                        step_number: step.step_number,
                        total_steps: step.total_steps,
                        instruction: step.instruction,
                        cached: step.cached,
                    });
                }
                Some(build_event::Event::Output(output)) => {
                    on_event(BuildEventKind::Output { line: output.line, stream: output.stream });
                }
                Some(build_event::Event::Complete(complete)) => {
                    if let Some(img) = complete.image {
                        final_image = Some(img.try_into()?);
                    }
                }
                Some(build_event::Event::Error(error)) => {
                    return Err(anyhow::anyhow!(
                        "Build failed at step {}: {}",
                        error.step_number,
                        error.message
                    ));
                }
                None => {}
            }
        }

        final_image.ok_or_else(|| anyhow::anyhow!("No image returned from build"))
    }
}

/// Build event kinds for streaming UI updates
#[derive(Debug)]
pub enum BuildEventKind {
    Step {
        step_number: u32,
        total_steps: u32,
        instruction: String,
        cached: bool,
    },
    Output {
        line: String,
        #[allow(dead_code)] // Reserved for future use (stdout vs stderr)
        stream: String,
    },
}

/// Ensure the daemon is running, spawning an ephemeral instance if needed.
/// Returns the socket path to connect to.
pub async fn ensure_daemon() -> Result<String> {
    let default_socket = "/tmp/hypr.sock";

    // Try to connect to existing daemon
    if Path::new(default_socket).exists() {
        if let Ok(mut client) = HyprClient::connect().await {
            // Verify it's responsive
            if client.health().await.is_ok() {
                return Ok(default_socket.to_string());
            }
        }
    }

    // No daemon running - spawn ephemeral instance
    let pid = std::process::id();
    let ephemeral_socket = format!("/tmp/hypr-{}.sock", pid);

    // Find hyprd binary (same directory as hypr CLI)
    let hyprd_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("hyprd")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("hyprd"));

    // Spawn ephemeral daemon
    let mut child = std::process::Command::new(&hyprd_path)
        .args([
            "--ephemeral",
            "--socket",
            &ephemeral_socket,
            "--idle-timeout",
            "60",
            "--skip-dns",
            "--skip-reconcile",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("Failed to spawn ephemeral daemon: {}", hyprd_path.display()))?;

    // Wait for socket to appear (up to 5 seconds)
    for _ in 0..50 {
        if Path::new(&ephemeral_socket).exists() {
            // Give it a moment to start accepting connections
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Verify it's responsive
            if let Ok(mut client) = HyprClient::connect_at(&ephemeral_socket).await {
                if client.health().await.is_ok() {
                    // Detach the child process so it continues after CLI exits
                    std::mem::forget(child);
                    return Ok(ephemeral_socket);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Clean up failed spawn
    let _ = child.kill();
    Err(anyhow::anyhow!(
        "Failed to start ephemeral daemon (socket {} not created)",
        ephemeral_socket
    ))
}
