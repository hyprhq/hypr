//! `hypr run` command

use crate::client::HyprClient;
use anyhow::Result;
use hypr_core::types::network::{NetworkConfig, Protocol};
use hypr_core::types::vm::{DiskConfig, DiskFormat};
use hypr_core::{VmConfig, VmResources};

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

    // Parse image name and tag (e.g., "nginx:latest" or "nginx")
    let (image_name, image_tag) = if let Some((name, tag)) = image.split_once(':') {
        (name, tag)
    } else {
        (image, "latest")
    };

    // Resolve image to get actual rootfs path
    let image_info = client
        .get_image(image_name, image_tag)
        .await
        .map_err(|e| anyhow::anyhow!("Image not found: {}:{} - {}", image_name, image_tag, e))?;

    // Generate VM ID and name
    let vm_id = format!("vm-{}", uuid::Uuid::new_v4());
    let vm_name = name.unwrap_or_else(|| format!("vm-{}", &vm_id[3..11]));

    // Combine user-specified ports with EXPOSE ports from image
    let mut port_mappings = ports
        .into_iter()
        .map(|(host, guest)| hypr_core::PortMapping {
            host_port: host,
            vm_port: guest,
            protocol: Protocol::Tcp,
        })
        .collect::<Vec<_>>();

    // Auto-map EXPOSE ports if no ports were manually specified
    if port_mappings.is_empty() {
        for exposed_port in &image_info.manifest.exposed_ports {
            port_mappings.push(hypr_core::PortMapping {
                host_port: *exposed_port,
                vm_port: *exposed_port,
                protocol: Protocol::Tcp,
            });
            println!("Auto-mapping port {} (from EXPOSE)", exposed_port);
        }
    }

    // Build VM config
    let config = VmConfig {
        network_enabled: true,
        id: vm_id.clone(),
        name: vm_name.clone(),
        resources: VmResources { cpus: cpus.unwrap_or(2), memory_mb: memory_mb.unwrap_or(512) },
        kernel_path: None, // Use default
        kernel_args: vec![],
        initramfs_path: None, // Only used for build VMs
        disks: vec![
            // Root disk (use actual image rootfs path from database)
            DiskConfig {
                path: image_info.rootfs_path.clone(),
                readonly: true,
                format: DiskFormat::Squashfs,
            },
        ],
        network: NetworkConfig::default(),
        ports: port_mappings,
        env: env.into_iter().collect(),
        volumes: vec![],
        gpu: None,
        virtio_fs_mounts: vec![],
    };

    println!("Creating VM '{}'...", vm_name);
    let image_ref = format!("{}:{}", image_name, image_tag);
    let vm = client.create_vm(config, image_ref).await?;
    println!("VM created: {}", vm.id);

    println!("Starting VM...");
    let vm = client.start_vm(&vm.id).await?;
    println!("VM started: {}", vm.name);

    if let Some(ip) = vm.ip_address {
        println!("IP address: {}", ip);
    }

    Ok(())
}
