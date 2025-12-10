//! PCI device abstraction for VFIO passthrough.

use crate::error::{HyprError, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Sysfs paths for PCI devices.
pub const PCI_DEVICES_PATH: &str = "/sys/bus/pci/devices";

/// Regular expression to validate PCI address format: 0000:01:00.0
static PCI_ADDRESS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
        .expect("Invalid PCI address regex")
});

/// PCI device class codes for GPUs.
pub mod class {
    /// VGA compatible controller (0x030000)
    pub const VGA_CONTROLLER: &str = "0x030000";
    /// 3D controller (0x030200) - NVIDIA compute GPUs
    pub const CONTROLLER_3D: &str = "0x030200";
    /// Display controller (0x038000)
    pub const DISPLAY_CONTROLLER: &str = "0x038000";
}

/// Known GPU vendor IDs.
pub mod vendor {
    pub const NVIDIA: &str = "10de";
    pub const AMD: &str = "1002";
    pub const INTEL: &str = "8086";
}

/// PCI device information.
#[derive(Debug, Clone)]
pub struct PciDevice {
    /// PCI address (e.g., "0000:01:00.0")
    pub address: String,
    /// Vendor ID (e.g., "10de" for NVIDIA)
    pub vendor_id: String,
    /// Device ID (e.g., "2204" for RTX 3090)
    pub device_id: String,
    /// Device class (e.g., "0x030000" for VGA)
    pub class: String,
    /// Current driver (None if unbound)
    pub driver: Option<String>,
    /// IOMMU group ID
    pub iommu_group: Option<String>,
    /// NUMA node (-1 if not applicable)
    pub numa_node: i32,
    /// Is this the boot VGA device?
    pub is_boot_vga: bool,
    /// Sysfs path to this device
    pub sysfs_path: PathBuf,
}

impl PciDevice {
    /// Read device information from sysfs.
    pub fn from_address(address: &str) -> Result<Self> {
        if !is_valid_pci_address(address) {
            return Err(HyprError::InvalidConfig {
                reason: format!(
                    "Invalid PCI address format: {} (expected: 0000:01:00.0)",
                    address
                ),
            });
        }

        let sysfs_path = PathBuf::from(PCI_DEVICES_PATH).join(address);
        if !sysfs_path.exists() {
            return Err(HyprError::GpuUnavailable {
                reason: format!("PCI device not found: {}", address),
            });
        }

        let vendor_id = read_sysfs_value(&sysfs_path.join("vendor"))?
            .trim_start_matches("0x")
            .to_lowercase();
        let device_id = read_sysfs_value(&sysfs_path.join("device"))?
            .trim_start_matches("0x")
            .to_lowercase();
        let class = read_sysfs_value(&sysfs_path.join("class"))?;

        let driver = read_driver(&sysfs_path);
        let iommu_group = read_iommu_group(&sysfs_path);
        let numa_node = read_numa_node(&sysfs_path);
        let is_boot_vga = check_boot_vga(&sysfs_path);

        debug!(
            address = %address,
            vendor = %vendor_id,
            device = %device_id,
            driver = ?driver,
            iommu_group = ?iommu_group,
            is_boot_vga = %is_boot_vga,
            "Read PCI device info"
        );

        Ok(Self {
            address: address.to_string(),
            vendor_id,
            device_id,
            class,
            driver,
            iommu_group,
            numa_node,
            is_boot_vga,
            sysfs_path,
        })
    }

    /// Check if this device is a GPU (VGA, 3D controller, or display controller).
    pub fn is_gpu(&self) -> bool {
        self.class.starts_with("0x0300") || // VGA compatible
        self.class.starts_with("0x0302") || // 3D controller
        self.class.starts_with("0x0380") // Display controller
    }

    /// Check if this device is an audio controller (often paired with GPUs).
    pub fn is_audio(&self) -> bool {
        self.class.starts_with("0x0403") // Audio device
    }

    /// Get the GPU vendor as an enum.
    pub fn gpu_vendor(&self) -> Option<crate::types::vm::GpuVendor> {
        match self.vendor_id.as_str() {
            vendor::NVIDIA => Some(crate::types::vm::GpuVendor::Nvidia),
            vendor::AMD => Some(crate::types::vm::GpuVendor::Amd),
            vendor::INTEL => Some(crate::types::vm::GpuVendor::Intel),
            _ => None,
        }
    }

    /// Check if device is currently bound to vfio-pci.
    pub fn is_vfio_bound(&self) -> bool {
        self.driver.as_ref().is_some_and(|d| d == "vfio-pci")
    }

    /// Get a human-readable device name.
    pub fn display_name(&self) -> String {
        let vendor_name = match self.vendor_id.as_str() {
            vendor::NVIDIA => "NVIDIA",
            vendor::AMD => "AMD",
            vendor::INTEL => "Intel",
            _ => "Unknown",
        };

        format!("{} [{}:{}]", vendor_name, self.vendor_id, self.device_id)
    }
}

/// Validate PCI address format.
pub fn is_valid_pci_address(address: &str) -> bool {
    PCI_ADDRESS_REGEX.is_match(address)
}

/// Read a value from a sysfs file.
fn read_sysfs_value(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|e| HyprError::IoError { path: path.to_path_buf(), source: e })
}

/// Read the current driver binding for a device.
fn read_driver(device_path: &Path) -> Option<String> {
    let driver_link = device_path.join("driver");
    if !driver_link.exists() {
        return None;
    }

    fs::read_link(&driver_link)
        .ok()
        .and_then(|target| target.file_name().map(|n| n.to_string_lossy().to_string()))
}

/// Read the IOMMU group for a device.
fn read_iommu_group(device_path: &Path) -> Option<String> {
    let iommu_link = device_path.join("iommu_group");
    if !iommu_link.exists() {
        return None;
    }

    fs::read_link(&iommu_link)
        .ok()
        .and_then(|target| target.file_name().map(|n| n.to_string_lossy().to_string()))
}

/// Read the NUMA node for a device.
fn read_numa_node(device_path: &Path) -> i32 {
    let numa_path = device_path.join("numa_node");
    fs::read_to_string(&numa_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(-1)
}

/// Check if this is the boot VGA device.
///
/// The boot VGA device is the GPU that was used during system boot.
/// Unbinding this device can hang the host system.
fn check_boot_vga(device_path: &Path) -> bool {
    let boot_vga_path = device_path.join("boot_vga");
    fs::read_to_string(&boot_vga_path)
        .ok()
        .is_some_and(|s| s.trim() == "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_address_validation() {
        assert!(is_valid_pci_address("0000:01:00.0"));
        assert!(is_valid_pci_address("0000:ff:1f.7"));
        assert!(is_valid_pci_address("ABCD:12:34.5"));

        assert!(!is_valid_pci_address("01:00.0")); // Missing domain
        assert!(!is_valid_pci_address("0000:01:00")); // Missing function
        assert!(!is_valid_pci_address("0000:01:00.8")); // Invalid function (max 7)
        assert!(!is_valid_pci_address("invalid"));
    }
}
