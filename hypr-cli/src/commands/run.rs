//! `hypr run` command

use crate::client::HyprClient;
use anyhow::Result;
use hypr_core::types::network::{NetworkConfig, Protocol};
use hypr_core::types::vm::{DiskConfig, DiskFormat};
use hypr_core::{VmConfig, VmResources};
use std::path::PathBuf;

/// Run a VM from an image
pub async fn run(
    image: &str,
    name: Option<String>,
    cpus: Option<u32>,
    memory_mb: Option<u32>,
    ports: Vec<(u16, u16)>,
    env: Vec<(String, String)>,
) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    // Generate VM ID and name
    let vm_id = format!("vm-{}", uuid::Uuid::new_v4());
    let vm_name = name.unwrap_or_else(|| format!("vm-{}", &vm_id[3..11]));

    // Build VM config
    let config = VmConfig {
        id: vm_id.clone(),
        name: vm_name.clone(),
        resources: VmResources {
            cpus: cpus.unwrap_or(2),
            memory_mb: memory_mb.unwrap_or(512),
        },
        kernel_path: None, // Use default
        kernel_args: vec![],
        disks: vec![
            // Root disk (image rootfs)
            DiskConfig {
                path: PathBuf::from(format!("/var/lib/hypr/images/{}/rootfs.squashfs", image)),
                readonly: true,
                format: DiskFormat::Squashfs,
            },
        ],
        network: NetworkConfig::default(),
        ports: ports
            .into_iter()
            .map(|(host, guest)| hypr_core::PortMapping {
                host_port: host,
                vm_port: guest,
                protocol: Protocol::Tcp,
            })
            .collect(),
        env: env.into_iter().collect(),
        volumes: vec![],
        gpu: None,
        vsock_path: PathBuf::from(format!("/tmp/hypr-{}.vsock", vm_id)),
    };

    println!("Creating VM '{}'...", vm_name);
    let vm = client.create_vm(config).await?;
    println!("VM created: {}", vm.id);

    println!("Starting VM...");
    let vm = client.start_vm(&vm.id).await?;
    println!("VM started: {}", vm.name);

    if let Some(ip) = vm.ip_address {
        println!("IP address: {}", ip);
    }

    Ok(())
}
