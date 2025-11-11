//! Core domain types for HYPR.

pub mod vm;
pub mod image;
pub mod volume;
pub mod network;
pub mod stack;

// Re-exports
pub use vm::{Vm, VmConfig, VmHandle, VmStatus, VmResources};
pub use image::{Image, ImageManifest};
pub use volume::{Volume, VolumeMount};
pub use network::{Network, NetworkConfig, PortMapping};
pub use stack::{Stack, Service};
