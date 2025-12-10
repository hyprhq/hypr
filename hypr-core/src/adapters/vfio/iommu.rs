//! IOMMU group handling for VFIO passthrough.
//!
//! IOMMU groups are the smallest unit of device isolation. All devices in an
//! IOMMU group share the same memory isolation domain, meaning they can all
//! access each other's memory via DMA.
//!
//! # Key Rules
//!
//! 1. **All-or-Nothing**: You must pass through ALL devices in an IOMMU group,
//!    or none at all. Partial passthrough breaks isolation.
//!
//! 2. **GPU + Audio**: Graphics cards often have an audio controller in the same
//!    IOMMU group. Both must be passed through together.
//!
//! 3. **IOMMU Availability**: If a device has no IOMMU group, IOMMU may not be
//!    enabled in BIOS/kernel. This is required for secure passthrough.

use crate::adapters::vfio::device::PciDevice;
use crate::error::{HyprError, Result};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, warn};

/// Path to IOMMU groups in sysfs.
const IOMMU_GROUPS_PATH: &str = "/sys/kernel/iommu_groups";

/// Represents an IOMMU group containing one or more PCI devices.
#[derive(Debug, Clone)]
pub struct IommuGroup {
    /// IOMMU group ID (e.g., "42")
    pub id: String,
    /// All devices in this group
    pub devices: Vec<String>,
    /// Sysfs path to this group
    pub path: PathBuf,
}

impl IommuGroup {
    /// Read IOMMU group information from sysfs.
    pub fn from_id(group_id: &str) -> Result<Self> {
        let path = PathBuf::from(IOMMU_GROUPS_PATH).join(group_id);
        if !path.exists() {
            return Err(HyprError::GpuUnavailable {
                reason: format!("IOMMU group {} not found", group_id),
            });
        }

        let devices_path = path.join("devices");
        let mut devices = Vec::new();

        if devices_path.exists() {
            for entry in fs::read_dir(&devices_path)
                .map_err(|e| HyprError::IoError { path: devices_path.clone(), source: e })?
            {
                let entry = entry.map_err(|e| HyprError::Internal(e.to_string()))?;
                if let Some(name) = entry.file_name().to_str() {
                    devices.push(name.to_string());
                }
            }
        }

        debug!(group_id = %group_id, devices = ?devices, "Read IOMMU group");

        Ok(Self { id: group_id.to_string(), devices, path })
    }

    /// Check if this group contains only the specified devices.
    ///
    /// Returns `true` if all devices in the group are in the requested set.
    pub fn contains_only(&self, requested: &HashSet<String>) -> bool {
        self.devices.iter().all(|d| requested.contains(d))
    }

    /// Get devices in this group that are NOT in the requested set.
    pub fn extra_devices(&self, requested: &HashSet<String>) -> Vec<String> {
        self.devices.iter().filter(|d| !requested.contains(*d)).cloned().collect()
    }
}

/// Validate IOMMU groups for a set of devices.
///
/// # Rules Enforced
///
/// 1. All devices must have an IOMMU group (IOMMU must be enabled)
/// 2. All devices in each IOMMU group must be included in the request
///
/// # Returns
///
/// A list of IOMMU groups that contain the requested devices.
pub fn validate_iommu_groups(pci_addresses: &[String]) -> Result<Vec<IommuGroup>> {
    let requested: HashSet<String> = pci_addresses.iter().cloned().collect();
    let mut groups: Vec<IommuGroup> = Vec::new();
    let mut seen_groups: HashSet<String> = HashSet::new();

    for addr in pci_addresses {
        let device = PciDevice::from_address(addr)?;

        // Check IOMMU is available
        let group_id = device.iommu_group.ok_or_else(|| HyprError::GpuUnavailable {
            reason: format!(
                "Device {} has no IOMMU group. \
                 IOMMU may not be enabled in BIOS or kernel. \
                 Enable VT-d/AMD-Vi in BIOS and add 'intel_iommu=on' or 'amd_iommu=on' \
                 to kernel cmdline.",
                addr
            ),
        })?;

        // Skip if we've already processed this group
        if seen_groups.contains(&group_id) {
            continue;
        }
        seen_groups.insert(group_id.clone());

        // Load group info
        let group = IommuGroup::from_id(&group_id)?;

        // Check group integrity: all devices in group must be passed through
        let extra = group.extra_devices(&requested);
        if !extra.is_empty() {
            // Load info about extra devices for better error message
            let extra_info: Vec<String> = extra
                .iter()
                .map(|addr| {
                    PciDevice::from_address(addr)
                        .map(|d| format!("{} ({})", addr, d.display_name()))
                        .unwrap_or_else(|_| addr.clone())
                })
                .collect();

            // Check if extra devices are benign (like PCI bridges)
            let non_trivial: Vec<&str> = extra
                .iter()
                .filter_map(|addr| {
                    PciDevice::from_address(addr).ok().and_then(|d| {
                        // PCI bridges (class 0x0604) are usually safe to leave
                        if d.class.starts_with("0x0604") {
                            None
                        } else {
                            Some(addr.as_str())
                        }
                    })
                })
                .collect();

            if !non_trivial.is_empty() {
                return Err(HyprError::GpuNotBound {
                    pci_address: addr.clone(),
                    hint: format!(
                        "IOMMU group {} contains additional devices that must also be \
                         passed through: {}. \n\
                         All devices in an IOMMU group share memory isolation and must \
                         be passed through together.",
                        group_id,
                        extra_info.join(", ")
                    ),
                });
            } else {
                warn!(
                    group_id = %group_id,
                    extra_devices = ?extra,
                    "IOMMU group contains PCI bridges (will be ignored)"
                );
            }
        }

        groups.push(group);
    }

    Ok(groups)
}

/// Check if IOMMU is enabled on the system.
pub fn is_iommu_enabled() -> bool {
    PathBuf::from(IOMMU_GROUPS_PATH).exists()
}

/// Get all IOMMU groups on the system.
pub fn list_iommu_groups() -> Result<Vec<IommuGroup>> {
    let path = PathBuf::from(IOMMU_GROUPS_PATH);
    if !path.exists() {
        return Err(HyprError::GpuUnavailable {
            reason: "IOMMU not enabled. Enable VT-d/AMD-Vi in BIOS.".to_string(),
        });
    }

    let mut groups = Vec::new();

    for entry in
        fs::read_dir(&path).map_err(|e| HyprError::IoError { path: path.clone(), source: e })?
    {
        let entry = entry.map_err(|e| HyprError::Internal(e.to_string()))?;
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(group) = IommuGroup::from_id(name) {
                groups.push(group);
            }
        }
    }

    // Sort by group ID numerically
    groups.sort_by(|a, b| {
        let a_num: u32 = a.id.parse().unwrap_or(0);
        let b_num: u32 = b.id.parse().unwrap_or(0);
        a_num.cmp(&b_num)
    });

    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iommu_path_exists() {
        // This test just verifies the path constant is valid
        // Actual IOMMU presence depends on hardware
        let path = PathBuf::from(IOMMU_GROUPS_PATH);
        // Path may or may not exist depending on system
        let _ = path.exists();
    }
}
