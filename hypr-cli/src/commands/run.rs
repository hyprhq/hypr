//! `hypr run` command

use crate::client::HyprClient;
use anyhow::Result;
use hypr_core::adapters::vfio::detect_gpus;
use hypr_core::types::network::{NetworkConfig, Protocol};
#[cfg(target_os = "linux")]
use hypr_core::types::vm::GpuVendor;
use hypr_core::types::vm::{DiskConfig, DiskFormat, GpuConfig};
use hypr_core::{VmConfig, VmResources};

/// Run a VM from an image
pub async fn run(
    image: &str,
    name: Option<String>,
    cpus: Option<u32>,
    memory_mb: Option<u32>,
    ports: Vec<(u16, u16)>,
    env: Vec<(String, String)>,
    gpu_option: Option<String>,
) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    // Parse image name and tag (e.g., "nginx:latest" or "nginx")
    let (image_name, image_tag) =
        if let Some((name, tag)) = image.split_once(':') { (name, tag) } else { (image, "latest") };

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

    // Configure GPU if requested
    let gpu_config = resolve_gpu_config(gpu_option)?;
    if gpu_config.is_some() {
        println!("GPU passthrough enabled");
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
        gpu: gpu_config,
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

/// Resolve GPU configuration from CLI option.
///
/// - `None` = no GPU requested
/// - `Some("")` = auto-detect first available GPU
/// - `Some("0000:01:00.0")` = specific PCI address (Linux only)
fn resolve_gpu_config(gpu_option: Option<String>) -> Result<Option<GpuConfig>> {
    let gpu_str = match gpu_option {
        None => return Ok(None), // No GPU requested
        Some(s) => s,
    };

    // Auto-detect GPU if no specific address provided
    if gpu_str.is_empty() {
        return auto_detect_gpu();
    }

    // Linux: Specific PCI address provided
    #[cfg(target_os = "linux")]
    {
        // Validate PCI address format
        if !is_valid_pci_address(&gpu_str) {
            return Err(anyhow::anyhow!(
                "Invalid PCI address format: '{}'. Expected format: 0000:01:00.0",
                gpu_str
            ));
        }

        // Find the GPU with this address
        let gpus = detect_gpus()?;
        let gpu = gpus.iter().find(|g| g.pci_address == gpu_str);

        match gpu {
            Some(g) => {
                println!("Using GPU: {} ({})", g.model, g.pci_address);
                Ok(Some(GpuConfig {
                    vendor: g.vendor,
                    pci_address: Some(g.pci_address.clone()),
                    model: g.model.clone(),
                    use_sriov: false,
                    gpu_memory_mb: g.memory_mb,
                    gpudirect_clique: None,
                }))
            }
            None => Err(anyhow::anyhow!(
                "GPU not found at PCI address: {}. Run 'hypr gpu list' to see available GPUs.",
                gpu_str
            )),
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS doesn't use PCI addresses
        Err(anyhow::anyhow!(
            "Specifying PCI address is not supported on macOS. Use --gpu without an address."
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow::anyhow!("GPU passthrough not supported on this platform"))
    }
}

/// Auto-detect the first available GPU.
fn auto_detect_gpu() -> Result<Option<GpuConfig>> {
    let gpus = detect_gpus()?;

    if gpus.is_empty() {
        #[cfg(target_os = "macos")]
        {
            #[cfg(target_arch = "aarch64")]
            return Err(anyhow::anyhow!("No GPU detected (unexpected on Apple Silicon)"));
            #[cfg(not(target_arch = "aarch64"))]
            return Err(anyhow::anyhow!("GPU passthrough not available on Intel Macs"));
        }

        #[cfg(target_os = "linux")]
        return Err(anyhow::anyhow!(
            "No GPUs detected. Run 'hypr gpu list' to check availability."
        ));

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(anyhow::anyhow!("GPU passthrough not supported on this platform"));
    }

    #[cfg(target_os = "linux")]
    {
        // Skip boot VGA devices by default, prefer vfio-ready devices
        let gpu = gpus.iter().filter(|g| !g.is_boot_vga).max_by_key(|g| {
            // Prefer vfio-ready, then NVIDIA, then by memory
            let vfio_score = if g.is_vfio_ready { 1000 } else { 0 };
            let vendor_score = match g.vendor {
                GpuVendor::Nvidia => 100,
                GpuVendor::Amd => 50,
                _ => 0,
            };
            let memory_score = g.memory_mb.unwrap_or(0) / 1024; // GB
            vfio_score + vendor_score + memory_score
        });

        match gpu {
            Some(g) => {
                println!("Auto-selected GPU: {} ({})", g.model, g.pci_address);
                Ok(Some(GpuConfig {
                    vendor: g.vendor,
                    pci_address: Some(g.pci_address.clone()),
                    model: g.model.clone(),
                    use_sriov: false,
                    gpu_memory_mb: g.memory_mb,
                    gpudirect_clique: None,
                }))
            }
            None => Err(anyhow::anyhow!(
                "No suitable GPU found (all detected GPUs are boot VGA devices). \
                 Use 'hypr gpu list' and specify a PCI address explicitly."
            )),
        }
    }

    #[cfg(target_os = "macos")]
    {
        let gpu = &gpus[0];
        println!("Using Metal GPU: {}", gpu.model);
        Ok(Some(GpuConfig {
            vendor: gpu.vendor,
            pci_address: None,
            model: gpu.model.clone(),
            use_sriov: false,
            gpu_memory_mb: gpu.memory_mb,
            gpudirect_clique: None,
        }))
    }
}

/// Validate PCI address format (0000:01:00.0).
#[cfg(target_os = "linux")]
fn is_valid_pci_address(addr: &str) -> bool {
    // Simple validation: DDDD:BB:SS.F format
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 3 {
        return false;
    }

    // Domain (4 hex digits)
    if parts[0].len() != 4 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    // Bus (2 hex digits)
    if parts[1].len() != 2 || !parts[1].chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    // Slot.Function (SS.F)
    let slot_func: Vec<&str> = parts[2].split('.').collect();
    if slot_func.len() != 2 {
        return false;
    }

    // Slot (2 hex digits)
    if slot_func[0].len() != 2 || !slot_func[0].chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    // Function (1 digit, 0-7)
    if slot_func[1].len() != 1 {
        return false;
    }
    if let Ok(func) = slot_func[1].parse::<u8>() {
        func <= 7
    } else {
        false
    }
}
