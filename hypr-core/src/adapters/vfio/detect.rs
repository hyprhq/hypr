//! GPU detection for Linux systems.
//!
//! Scans /sys/bus/pci/devices for display controllers and GPUs.

use crate::adapters::vfio::device::{vendor, PciDevice, PCI_DEVICES_PATH};
use crate::error::{HyprError, Result};
use crate::types::vm::GpuVendor;
use std::fs;
use tracing::debug;

/// Detected GPU information.
#[derive(Debug, Clone)]
pub struct DetectedGpu {
    /// PCI address (e.g., "0000:01:00.0")
    pub pci_address: String,
    /// GPU vendor
    pub vendor: GpuVendor,
    /// Human-readable model name
    pub model: String,
    /// GPU memory in MB (if detectable)
    pub memory_mb: Option<u64>,
    /// Current driver binding
    pub driver: Option<String>,
    /// IOMMU group ID
    pub iommu_group: Option<String>,
    /// Is this the boot VGA device?
    pub is_boot_vga: bool,
    /// Is device already bound to vfio-pci?
    pub is_vfio_ready: bool,
}

/// Detect all GPUs on the system.
///
/// Scans /sys/bus/pci/devices for devices with GPU class codes.
pub fn detect_gpus() -> Result<Vec<DetectedGpu>> {
    let pci_path = std::path::PathBuf::from(PCI_DEVICES_PATH);
    if !pci_path.exists() {
        return Err(HyprError::GpuUnavailable {
            reason: format!("PCI sysfs not found at {}", PCI_DEVICES_PATH),
        });
    }

    let mut gpus = Vec::new();

    for entry in
        fs::read_dir(&pci_path).map_err(|e| HyprError::IoError { path: pci_path.clone(), source: e })?
    {
        let entry = entry.map_err(|e| HyprError::Internal(e.to_string()))?;
        let address = entry.file_name().to_string_lossy().to_string();

        // Try to load device info
        let device = match PciDevice::from_address(&address) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Skip non-GPU devices
        if !device.is_gpu() {
            continue;
        }

        let vendor = match device.gpu_vendor() {
            Some(v) => v,
            None => continue, // Unknown vendor, skip
        };

        let model = lookup_gpu_model(&device.vendor_id, &device.device_id);
        let memory_mb = detect_gpu_memory(&device);

        debug!(
            address = %address,
            vendor = ?vendor,
            model = %model,
            driver = ?device.driver,
            is_boot_vga = %device.is_boot_vga,
            "Detected GPU"
        );

        gpus.push(DetectedGpu {
            pci_address: address,
            vendor,
            model,
            memory_mb,
            driver: device.driver.clone(),
            iommu_group: device.iommu_group.clone(),
            is_boot_vga: device.is_boot_vga,
            is_vfio_ready: device.is_vfio_bound(),
        });
    }

    // Sort by PCI address
    gpus.sort_by(|a, b| a.pci_address.cmp(&b.pci_address));

    Ok(gpus)
}

/// Look up GPU model name from vendor:device ID.
///
/// This is a basic lookup table for common GPUs. In production,
/// you'd want to use the PCI ID database or query the device directly.
fn lookup_gpu_model(vendor_id: &str, device_id: &str) -> String {
    match vendor_id {
        vendor::NVIDIA => lookup_nvidia_model(device_id),
        vendor::AMD => lookup_amd_model(device_id),
        vendor::INTEL => lookup_intel_model(device_id),
        _ => format!("Unknown GPU [{}:{}]", vendor_id, device_id),
    }
}

fn lookup_nvidia_model(device_id: &str) -> String {
    // Common NVIDIA device IDs
    // Full list: https://pci-ids.ucw.cz/read/PC/10de
    match device_id {
        // Data center / HPC
        "20b0" => "NVIDIA A100-SXM4-40GB".to_string(),
        "20b2" => "NVIDIA A100-SXM4-80GB".to_string(),
        "20b5" => "NVIDIA A100-PCIE-40GB".to_string(),
        "20f1" => "NVIDIA A100-PCIE-80GB".to_string(),
        "2330" => "NVIDIA H100 PCIe".to_string(),
        "2331" => "NVIDIA H100 SXM".to_string(),
        "26b1" => "NVIDIA L4".to_string(),
        "26b5" => "NVIDIA L40".to_string(),
        "1db1" => "NVIDIA Tesla V100-SXM2-16GB".to_string(),
        "1db4" => "NVIDIA Tesla V100-PCIE-16GB".to_string(),
        "1db6" => "NVIDIA Tesla V100-PCIE-32GB".to_string(),
        "1e04" => "NVIDIA Tesla T4".to_string(),

        // Consumer RTX 40 series
        "2684" => "NVIDIA RTX 4090".to_string(),
        "2685" => "NVIDIA RTX 4090 D".to_string(),
        "2702" => "NVIDIA RTX 4080 Super".to_string(),
        "2704" => "NVIDIA RTX 4080".to_string(),
        "2705" => "NVIDIA RTX 4070 Ti Super".to_string(),
        "2782" => "NVIDIA RTX 4070 Ti".to_string(),
        "2783" => "NVIDIA RTX 4070 Super".to_string(),
        "2786" => "NVIDIA RTX 4070".to_string(),

        // Consumer RTX 30 series
        "2204" => "NVIDIA RTX 3090".to_string(),
        "2206" => "NVIDIA RTX 3080".to_string(),
        "2208" => "NVIDIA RTX 3080 Ti".to_string(),
        "2216" => "NVIDIA RTX 3080 12GB".to_string(),
        "2482" => "NVIDIA RTX 3070 Ti".to_string(),
        "2484" => "NVIDIA RTX 3070".to_string(),
        "2503" => "NVIDIA RTX 3060 Ti".to_string(),
        "2504" => "NVIDIA RTX 3060".to_string(),

        _ => format!("NVIDIA GPU [{}]", device_id),
    }
}

fn lookup_amd_model(device_id: &str) -> String {
    // Common AMD device IDs
    match device_id {
        // Data center
        "740c" => "AMD Instinct MI250X".to_string(),
        "740f" => "AMD Instinct MI210".to_string(),
        "7408" => "AMD Instinct MI250".to_string(),
        "738c" => "AMD Instinct MI100".to_string(),

        // Consumer RX 7000 series
        "744c" => "AMD Radeon RX 7900 XTX".to_string(),
        "7448" => "AMD Radeon RX 7900 XT".to_string(),
        "7480" => "AMD Radeon RX 7800 XT".to_string(),
        "7470" => "AMD Radeon RX 7700 XT".to_string(),

        // Consumer RX 6000 series
        "73bf" => "AMD Radeon RX 6900 XT".to_string(),
        "73a5" => "AMD Radeon RX 6800 XT".to_string(),
        "73df" => "AMD Radeon RX 6700 XT".to_string(),
        "73ff" => "AMD Radeon RX 6600 XT".to_string(),

        _ => format!("AMD GPU [{}]", device_id),
    }
}

fn lookup_intel_model(device_id: &str) -> String {
    // Intel Arc / Data Center GPUs
    match device_id {
        // Data center
        "0bd5" => "Intel Data Center GPU Max 1550".to_string(),
        "0bd6" => "Intel Data Center GPU Max 1100".to_string(),

        // Arc consumer
        "56a0" => "Intel Arc A770".to_string(),
        "56a1" => "Intel Arc A750".to_string(),
        "56a5" => "Intel Arc A580".to_string(),
        "5690" => "Intel Arc A770M".to_string(),

        _ => format!("Intel GPU [{}]", device_id),
    }
}

/// Try to detect GPU memory size.
///
/// For NVIDIA GPUs, we can sometimes read this from sysfs or nvidia-smi.
fn detect_gpu_memory(device: &PciDevice) -> Option<u64> {
    // Try reading from resource file (BAR sizes)
    let resource_path = device.sysfs_path.join("resource");
    if let Ok(content) = fs::read_to_string(&resource_path) {
        // Parse resource lines to find largest BAR
        let mut max_size = 0u64;
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let (Ok(start), Ok(end)) = (
                    u64::from_str_radix(parts[0].trim_start_matches("0x"), 16),
                    u64::from_str_radix(parts[1].trim_start_matches("0x"), 16),
                ) {
                    let size = end.saturating_sub(start);
                    if size > max_size {
                        max_size = size;
                    }
                }
            }
        }
        if max_size > 1024 * 1024 * 1024 {
            // Only report if > 1GB (likely VRAM)
            return Some(max_size / (1024 * 1024));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvidia_lookup() {
        assert_eq!(lookup_nvidia_model("2204"), "NVIDIA RTX 3090");
        assert_eq!(lookup_nvidia_model("1e04"), "NVIDIA Tesla T4");
        assert!(lookup_nvidia_model("ffff").contains("ffff"));
    }

    #[test]
    fn test_amd_lookup() {
        assert_eq!(lookup_amd_model("744c"), "AMD Radeon RX 7900 XTX");
        assert!(lookup_amd_model("ffff").contains("ffff"));
    }

    #[test]
    fn test_intel_lookup() {
        assert_eq!(lookup_intel_model("56a0"), "Intel Arc A770");
        assert!(lookup_intel_model("ffff").contains("ffff"));
    }
}
