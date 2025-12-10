//! `hypr gpu` command

use anyhow::Result;
use hypr_core::adapters::vfio::detect_gpus;

/// List all detected GPUs on the system.
///
/// On Linux: Shows NVIDIA/AMD/Intel GPUs with VFIO passthrough status.
/// On macOS ARM64: Shows Apple Silicon GPU with Metal support.
/// On macOS Intel: Shows empty (no GPU passthrough support).
pub fn list() -> Result<()> {
    let gpus = detect_gpus()?;

    if gpus.is_empty() {
        #[cfg(target_os = "macos")]
        {
            #[cfg(target_arch = "aarch64")]
            println!("No GPUs detected (unexpected on Apple Silicon)");
            #[cfg(not(target_arch = "aarch64"))]
            println!("No GPU passthrough support on Intel Macs");
        }

        #[cfg(target_os = "linux")]
        println!("No GPUs detected");

        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        println!("{:<15} {:<10} {:<30} {:<12} {:<10} {:<8}",
            "PCI ADDRESS", "VENDOR", "MODEL", "DRIVER", "IOMMU", "STATUS");
        println!("{}", "-".repeat(95));

        for gpu in &gpus {
            let vendor_str = format!("{:?}", gpu.vendor);
            let driver = gpu.driver.as_deref().unwrap_or("-");
            let iommu = gpu.iommu_group.as_deref().unwrap_or("-");
            let status = if gpu.is_boot_vga {
                "boot-vga"
            } else if gpu.is_vfio_ready {
                "vfio-ready"
            } else {
                "available"
            };

            println!("{:<15} {:<10} {:<30} {:<12} {:<10} {:<8}",
                gpu.pci_address, vendor_str, truncate(&gpu.model, 30), driver, iommu, status);
        }
    }

    #[cfg(target_os = "macos")]
    {
        println!("{:<10} {:<40} {:<15} {:<10}",
            "VENDOR", "MODEL", "MEMORY", "STATUS");
        println!("{}", "-".repeat(80));

        for gpu in &gpus {
            let vendor_str = format!("{:?}", gpu.vendor);
            let memory = gpu.memory_mb
                .map(|mb| format_memory(mb))
                .unwrap_or_else(|| "-".to_string());
            let status = if gpu.available { "available" } else { "unavailable" };

            println!("{:<10} {:<40} {:<15} {:<10}",
                vendor_str, truncate(&gpu.model, 40), memory, status);
        }
    }

    println!();
    println!("Total: {} GPU(s)", gpus.len());

    #[cfg(target_os = "linux")]
    {
        let vfio_ready = gpus.iter().filter(|g| g.is_vfio_ready).count();
        let boot_vga = gpus.iter().filter(|g| g.is_boot_vga).count();

        if boot_vga > 0 {
            println!("Note: {} GPU(s) marked as boot-vga (cannot unbind without --force)", boot_vga);
        }
        if vfio_ready > 0 {
            println!("Note: {} GPU(s) already bound to vfio-pci", vfio_ready);
        }
    }

    #[cfg(target_os = "macos")]
    {
        #[cfg(target_arch = "aarch64")]
        println!("Tip: Use `hypr run --gpu <image>` to enable Metal GPU in VM");
        #[cfg(not(target_arch = "aarch64"))]
        println!("Note: GPU passthrough not available on Intel Macs");
    }

    Ok(())
}

/// Truncate string to max length with ellipsis.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Format memory in human-readable form.
fn format_memory(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.1} GB", mb as f64 / 1024.0)
    } else {
        format!("{} MB", mb)
    }
}
