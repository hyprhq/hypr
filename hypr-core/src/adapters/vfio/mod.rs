//! VFIO (Virtual Function I/O) device passthrough for Linux.
//!
//! This module provides GPU and other PCI device passthrough via the VFIO framework.
//! VFIO exposes direct device access to userspace, enabling near-native performance
//! for GPU workloads in VMs.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     VFIO Passthrough                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  VfioManager                                                │
//! │  ├── validate_devices() - Check PCI addresses & allowlist   │
//! │  ├── check_iommu_groups() - Verify IOMMU group integrity    │
//! │  ├── bind_devices() - Bind to vfio-pci driver               │
//! │  └── unbind_devices() - Restore original drivers            │
//! │                                                             │
//! │  IommuGroup                                                 │
//! │  └── All devices in group must be passed through together   │
//! │                                                             │
//! │  PciDevice                                                  │
//! │  └── Device metadata: vendor, driver, NUMA node, etc.       │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Safety
//!
//! - **IOMMU Group Integrity**: All devices in an IOMMU group must be passed through
//!   together. Partial passthrough is not allowed and will be rejected.
//!
//! - **Boot VGA Protection**: Unbinding the boot VGA device (the GPU driving the
//!   display) can hang the host. This is blocked unless `--force` is specified.
//!
//! # Usage
//!
//! ```rust,ignore
//! use hypr_core::adapters::vfio::VfioManager;
//!
//! let manager = VfioManager::new();
//!
//! // Validate and bind GPU for passthrough
//! manager.validate_devices(&["0000:01:00.0"])?;
//! manager.bind_devices(&["0000:01:00.0"])?;
//!
//! // Get VFIO group paths for cloud-hypervisor
//! let paths = manager.get_vfio_group_paths(&["0000:01:00.0"])?;
//! ```

#[cfg(target_os = "linux")]
mod detect;
#[cfg(target_os = "linux")]
mod device;
#[cfg(target_os = "linux")]
mod iommu;
#[cfg(target_os = "linux")]
mod manager;

#[cfg(target_os = "linux")]
pub use detect::{detect_gpus, DetectedGpu};
#[cfg(target_os = "linux")]
pub use device::PciDevice;
#[cfg(target_os = "linux")]
pub use iommu::IommuGroup;
#[cfg(target_os = "linux")]
pub use manager::VfioManager;

// macOS stub - GPU detection only (no VFIO)
#[cfg(target_os = "macos")]
mod detect_macos;
#[cfg(target_os = "macos")]
pub use detect_macos::{detect_gpus, DetectedGpu};
