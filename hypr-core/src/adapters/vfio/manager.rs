//! VFIO device manager for GPU passthrough.
//!
//! Handles binding PCI devices to the vfio-pci driver for passthrough to VMs.

use crate::adapters::vfio::device::{is_valid_pci_address, PciDevice, PCI_DEVICES_PATH};
use crate::adapters::vfio::iommu::{validate_iommu_groups, IommuGroup};
use crate::error::{HyprError, Result};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Path to VFIO device nodes.
const VFIO_DEV_PATH: &str = "/dev/vfio";

/// VFIO-PCI driver name.
const VFIO_PCI_DRIVER: &str = "vfio-pci";

/// Options for device binding operations.
#[derive(Debug, Clone, Default)]
pub struct BindOptions {
    /// Allow unbinding the boot VGA device (dangerous - can hang system)
    pub force_boot_vga: bool,

    /// Device allowlist (vendor:device patterns, e.g., "10de:*" for all NVIDIA)
    pub allowlist: Vec<String>,

    /// Automatically include all devices in IOMMU groups
    pub include_iommu_group_devices: bool,
}

/// Manages VFIO device passthrough operations.
#[derive(Debug, Default)]
pub struct VfioManager {
    /// Cached device info (address -> original driver for restore)
    original_drivers: HashMap<String, Option<String>>,
}

impl VfioManager {
    /// Create a new VFIO manager.
    pub fn new() -> Self {
        Self { original_drivers: HashMap::new() }
    }

    /// Validate devices for passthrough.
    ///
    /// # Checks Performed
    ///
    /// 1. PCI address format validation
    /// 2. Device existence in sysfs
    /// 3. Allowlist matching (if configured)
    /// 4. IOMMU group integrity (all devices in group must be included)
    /// 5. Boot VGA protection (unless `force_boot_vga` is set)
    ///
    /// # Returns
    ///
    /// List of IOMMU groups containing the devices.
    pub fn validate_devices(
        &self,
        pci_addresses: &[String],
        options: &BindOptions,
    ) -> Result<Vec<IommuGroup>> {
        if pci_addresses.is_empty() {
            return Ok(Vec::new());
        }

        info!(devices = ?pci_addresses, "Validating VFIO devices");

        // Validate each device
        for addr in pci_addresses {
            // Format validation
            if !is_valid_pci_address(addr) {
                return Err(HyprError::InvalidConfig {
                    reason: format!(
                        "Invalid PCI address format: {} (expected: 0000:01:00.0)",
                        addr
                    ),
                });
            }

            // Load device info
            let device = PciDevice::from_address(addr)?;

            // Boot VGA protection
            if device.is_boot_vga && !options.force_boot_vga {
                return Err(HyprError::GpuNotBound {
                    pci_address: addr.clone(),
                    hint: format!(
                        "Device {} is the boot VGA device (driving your display). \
                         Unbinding it will hang your system!\n\n\
                         If you really want to do this:\n\
                         1. Switch to a different console (Ctrl+Alt+F2)\n\
                         2. Use --force-gpu flag\n\
                         3. Be prepared to hard-reboot if display freezes\n\n\
                         Better approach: Use a secondary GPU for passthrough.",
                        addr
                    ),
                });
            }

            // Allowlist check
            if !options.allowlist.is_empty() {
                let device_id = format!("{}:{}", device.vendor_id, device.device_id);
                let vendor_wildcard = format!("{}:*", device.vendor_id);

                let matches = options.allowlist.iter().any(|pattern| {
                    pattern.eq_ignore_ascii_case(&device_id)
                        || pattern.eq_ignore_ascii_case(&vendor_wildcard)
                });

                if !matches {
                    return Err(HyprError::GpuNotBound {
                        pci_address: addr.clone(),
                        hint: format!(
                            "Device {} ({}) not in allowlist. \
                             Allowed: {:?}",
                            addr,
                            device_id,
                            options.allowlist
                        ),
                    });
                }
            }

            debug!(
                address = %addr,
                vendor = %device.vendor_id,
                device = %device.device_id,
                driver = ?device.driver,
                "Device validated"
            );
        }

        // Validate IOMMU groups
        let groups = validate_iommu_groups(pci_addresses)?;

        info!(
            devices = pci_addresses.len(),
            iommu_groups = groups.len(),
            "VFIO device validation passed"
        );

        Ok(groups)
    }

    /// Bind devices to the vfio-pci driver.
    ///
    /// # Process
    ///
    /// 1. Load vfio-pci kernel module (if not loaded)
    /// 2. For each device:
    ///    a. Save current driver for later restore
    ///    b. Unbind from current driver
    ///    c. Register device ID with vfio-pci
    ///    d. Bind to vfio-pci
    pub fn bind_devices(&mut self, pci_addresses: &[String]) -> Result<()> {
        if pci_addresses.is_empty() {
            return Ok(());
        }

        info!(devices = ?pci_addresses, "Binding devices to vfio-pci");

        // Ensure vfio modules are loaded
        Self::ensure_vfio_modules()?;

        for addr in pci_addresses {
            let device = PciDevice::from_address(addr)?;

            // Skip if already bound to vfio-pci
            if device.is_vfio_bound() {
                debug!(address = %addr, "Device already bound to vfio-pci");
                continue;
            }

            // Save original driver for restore
            self.original_drivers.insert(addr.clone(), device.driver.clone());

            // Unbind from current driver
            if let Some(current_driver) = &device.driver {
                self.unbind_from_driver(addr, current_driver)?;
            }

            // Register device ID with vfio-pci
            self.register_device_id(&device.vendor_id, &device.device_id)?;

            // Bind to vfio-pci
            self.bind_to_vfio(addr)?;

            info!(address = %addr, "Device bound to vfio-pci");
        }

        Ok(())
    }

    /// Unbind devices from vfio-pci and restore original drivers.
    pub fn unbind_devices(&mut self, pci_addresses: &[String]) -> Result<()> {
        if pci_addresses.is_empty() {
            return Ok(());
        }

        info!(devices = ?pci_addresses, "Unbinding devices from vfio-pci");

        for addr in pci_addresses {
            let device = PciDevice::from_address(addr)?;

            // Only unbind if currently bound to vfio-pci
            if !device.is_vfio_bound() {
                debug!(address = %addr, driver = ?device.driver, "Device not bound to vfio-pci");
                continue;
            }

            // Unbind from vfio-pci
            self.unbind_from_driver(addr, VFIO_PCI_DRIVER)?;

            // Restore original driver if we saved it
            if let Some(Some(original)) = self.original_drivers.get(addr) {
                debug!(address = %addr, driver = %original, "Restoring original driver");
                // Trigger driver probe
                let driver_probe_path =
                    PathBuf::from("/sys/bus/pci/drivers").join(original).join("bind");
                if driver_probe_path.exists() {
                    let _ = fs::write(&driver_probe_path, addr);
                }
            }

            info!(address = %addr, "Device unbound from vfio-pci");
        }

        self.original_drivers.clear();
        Ok(())
    }

    /// Get /dev/vfio/GROUP_NUMBER paths for devices.
    ///
    /// These paths are passed to cloud-hypervisor for VFIO passthrough.
    pub fn get_vfio_group_paths(&self, pci_addresses: &[String]) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        let mut seen_groups = std::collections::HashSet::new();

        for addr in pci_addresses {
            let device = PciDevice::from_address(addr)?;

            let group_id = device.iommu_group.ok_or_else(|| HyprError::GpuUnavailable {
                reason: format!("Device {} has no IOMMU group", addr),
            })?;

            if seen_groups.contains(&group_id) {
                continue;
            }
            seen_groups.insert(group_id.clone());

            let group_path = PathBuf::from(VFIO_DEV_PATH).join(&group_id);
            if !group_path.exists() {
                return Err(HyprError::GpuNotBound {
                    pci_address: addr.clone(),
                    hint: format!(
                        "VFIO group device {} not found. \
                         Device may not be bound to vfio-pci driver.",
                        group_path.display()
                    ),
                });
            }

            paths.push(group_path);
        }

        Ok(paths)
    }

    /// Get detailed info about a PCI device.
    pub fn get_device_info(&self, pci_address: &str) -> Result<PciDevice> {
        PciDevice::from_address(pci_address)
    }

    // --- Private helpers ---

    /// Ensure VFIO kernel modules are loaded.
    fn ensure_vfio_modules() -> Result<()> {
        // Try to load vfio-pci module
        // This is a no-op if already loaded
        let status = std::process::Command::new("modprobe")
            .args(["vfio-pci"])
            .status()
            .map_err(|e| HyprError::Internal(format!("Failed to run modprobe: {}", e)))?;

        if !status.success() {
            warn!("modprobe vfio-pci returned non-zero (may already be loaded)");
        }

        // Verify vfio-pci driver exists
        let driver_path = PathBuf::from("/sys/bus/pci/drivers/vfio-pci");
        if !driver_path.exists() {
            return Err(HyprError::GpuUnavailable {
                reason: "vfio-pci driver not available. Install linux-headers and run: \
                         modprobe vfio-pci"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Unbind device from its current driver.
    fn unbind_from_driver(&self, pci_address: &str, driver: &str) -> Result<()> {
        let unbind_path = PathBuf::from("/sys/bus/pci/drivers").join(driver).join("unbind");

        debug!(address = %pci_address, driver = %driver, "Unbinding from driver");

        fs::write(&unbind_path, pci_address).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                // Driver may have been unloaded, not an error
                return HyprError::Internal(format!("Driver {} not found", driver));
            }
            HyprError::IoError { path: unbind_path.clone(), source: e }
        })?;

        Ok(())
    }

    /// Register device ID with vfio-pci driver.
    fn register_device_id(&self, vendor_id: &str, device_id: &str) -> Result<()> {
        let new_id_path = PathBuf::from("/sys/bus/pci/drivers/vfio-pci/new_id");
        let id_string = format!("{} {}", vendor_id, device_id);

        debug!(vendor = %vendor_id, device = %device_id, "Registering device ID with vfio-pci");

        // This may fail if device ID is already registered (not an error)
        match fs::write(&new_id_path, &id_string) {
            Ok(_) => Ok(()),
            Err(e) => {
                // "File exists" or "Device or resource busy" means already registered
                let err_str = e.to_string();
                if err_str.contains("exist") || err_str.contains("busy") {
                    debug!("Device ID already registered with vfio-pci");
                    Ok(())
                } else {
                    Err(HyprError::IoError { path: new_id_path, source: e })
                }
            }
        }
    }

    /// Bind device to vfio-pci driver.
    fn bind_to_vfio(&self, pci_address: &str) -> Result<()> {
        let bind_path = PathBuf::from("/sys/bus/pci/drivers/vfio-pci/bind");

        debug!(address = %pci_address, "Binding to vfio-pci");

        match fs::write(&bind_path, pci_address) {
            Ok(_) => Ok(()),
            Err(e) => {
                // Check if device is now bound (may have been auto-bound after new_id)
                let device = PciDevice::from_address(pci_address)?;
                if device.is_vfio_bound() {
                    debug!("Device auto-bound to vfio-pci");
                    Ok(())
                } else {
                    Err(HyprError::GpuNotBound {
                        pci_address: pci_address.to_string(),
                        hint: format!("Failed to bind to vfio-pci: {}", e),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vfio_manager_creation() {
        let manager = VfioManager::new();
        assert!(manager.original_drivers.is_empty());
    }

    #[test]
    fn test_bind_options_default() {
        let options = BindOptions::default();
        assert!(!options.force_boot_vga);
        assert!(options.allowlist.is_empty());
    }
}
