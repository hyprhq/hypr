//! `hypr run` command

use crate::client::HyprClient;
use anyhow::Result;
use colored::Colorize;
use hypr_api::hypr::v1::{PortMapping as ProtoPortMapping, VmConfig as ProtoVmConfig, VmResources};
use hypr_core::adapters::vfio::detect_gpus;
#[cfg(target_os = "linux")]
use hypr_core::types::vm::GpuVendor;
use hypr_core::types::vm::GpuConfig;
use std::io::{self, Write};

/// Run a VM from an image
pub async fn run(
    image: &str,
    name: Option<String>,
    cpus: Option<u32>,
    memory_mb: Option<u32>,
    ports: Vec<(u16, u16)>,
    _env: Vec<(String, String)>,
    gpu_option: Option<String>,
) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    // Configure GPU if requested (print warning but daemon handles it)
    let _gpu_config = resolve_gpu_config(gpu_option)?;

    // Build proto config with resources
    let port_mappings: Vec<ProtoPortMapping> = ports
        .into_iter()
        .map(|(host, guest)| ProtoPortMapping {
            host_port: host as u32,
            guest_port: guest as u32,
            protocol: "tcp".to_string(),
        })
        .collect();

    let config = ProtoVmConfig {
        id: String::new(),
        name: String::new(),
        resources: Some(VmResources {
            cpus: cpus.unwrap_or(2),
            memory_mb: memory_mb.unwrap_or(512),
            balloon_enabled: true,
        }),
        kernel_path: None,
        disks: vec![],
        network: None,
        ports: port_mappings,
        env: std::collections::HashMap::new(),
        volumes: vec![],
        kernel_args: vec![],
        gpu: None,
        vsock_path: String::new(),
    };

    // Run with streaming progress
    let vm = client
        .run_vm(image, name, Some(config), |stage, message| {
            let symbol = match stage {
                "resolving" => "→".cyan(),
                "cached" => "✓".green(),
                "pulling" => "↓".yellow(),
                "pulled" => "✓".green(),
                "creating" => "◐".yellow(),
                "starting" => "◐".yellow(),
                "running" => "✓".green(),
                _ => "•".dimmed(),
            };

            print!("\r\x1b[K");
            print!("{} {}", symbol.bold(), message);
            io::stdout().flush().ok();

            if stage == "running" || stage == "cached" || stage == "pulled" {
                println!();
            }
        })
        .await?;

    println!();
    println!("{} VM running: {}", "✓".green().bold(), vm.name.bold());
    if let Some(ip) = vm.ip_address {
        println!("  IP: {}", ip.cyan());
    }
    println!("  ID: {}", vm.id.dimmed());

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
