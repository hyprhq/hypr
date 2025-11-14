//! Type conversions between domain types and protobuf types.

use crate::error::{HyprError, Result};
use crate::types::image::{
    HealthCheckConfig, HealthCheckType, Image, ImageManifest, RestartPolicy, RuntimeConfig,
};
use crate::types::network::{NetworkConfig, PortMapping, Protocol};
use crate::types::stack::{Service, Stack};
use crate::types::vm::{
    DiskConfig, DiskFormat, GpuConfig, GpuVendor, Vm, VmConfig, VmResources, VmStatus,
};
use crate::types::volume::VolumeMount;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

// Re-export proto types for convenience
pub use hypr_api::hypr::v1;

// Type aliases for proto types
type ProtoVm = v1::Vm;
type ProtoVmConfig = v1::VmConfig;
type ProtoVmResources = v1::VmResources;
type ProtoDiskConfig = v1::DiskConfig;
type ProtoNetworkConfig = v1::NetworkConfig;
type ProtoPortMapping = v1::PortMapping;
type ProtoVolumeMount = v1::VolumeMount;
type ProtoGpuConfig = v1::GpuConfig;
type ProtoImage = v1::Image;
type ProtoImageManifest = v1::ImageManifest;
type ProtoRuntimeConfig = v1::RuntimeConfig;
type ProtoHealthCheckConfig = v1::HealthCheckConfig;

// ============================================================================
// VM Conversions
// ============================================================================

impl From<Vm> for ProtoVm {
    fn from(vm: Vm) -> Self {
        Self {
            id: vm.id,
            name: vm.name,
            image_id: vm.image_id,
            status: vm.status.to_string(),
            config: Some(vm.config.into()),
            ip_address: vm.ip_address,
            pid: vm.pid,
            created_at: vm.created_at.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
            started_at: vm
                .started_at
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64),
            stopped_at: vm
                .stopped_at
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64),
        }
    }
}

impl TryFrom<ProtoVm> for Vm {
    type Error = HyprError;

    fn try_from(proto: ProtoVm) -> Result<Self> {
        let status = match proto.status.as_str() {
            "creating" => VmStatus::Creating,
            "running" => VmStatus::Running,
            "stopped" => VmStatus::Stopped,
            "failed" => VmStatus::Failed,
            "deleting" => VmStatus::Deleting,
            _ => {
                return Err(HyprError::InvalidConfig {
                    reason: format!("Invalid VM status: {}", proto.status),
                })
            }
        };

        let config = proto
            .config
            .ok_or_else(|| HyprError::InvalidConfig { reason: "Missing VM config".to_string() })?
            .try_into()?;

        Ok(Self {
            id: proto.id,
            name: proto.name,
            image_id: proto.image_id,
            status,
            config,
            ip_address: proto.ip_address,
            pid: proto.pid,
            created_at: UNIX_EPOCH + std::time::Duration::from_secs(proto.created_at as u64),
            started_at: proto
                .started_at
                .map(|t| UNIX_EPOCH + std::time::Duration::from_secs(t as u64)),
            stopped_at: proto
                .stopped_at
                .map(|t| UNIX_EPOCH + std::time::Duration::from_secs(t as u64)),
        })
    }
}

impl From<VmConfig> for ProtoVmConfig {
    fn from(config: VmConfig) -> Self {
        Self {
            id: config.id,
            name: config.name,
            resources: Some(config.resources.into()),
            disks: config.disks.into_iter().map(|d| d.into()).collect(),
            network: Some(config.network.into()),
            ports: config.ports.into_iter().map(|p| p.into()).collect(),
            env: config.env,
            volumes: config.volumes.into_iter().map(|v| v.into()).collect(),
            kernel_args: config.kernel_args,
            kernel_path: config.kernel_path.and_then(|p| p.to_str().map(String::from)),
            gpu: config.gpu.map(|g| g.into()),
            vsock_path: String::new(), // Removed: vsock communication no longer used
        }
    }
}

impl TryFrom<ProtoVmConfig> for VmConfig {
    type Error = HyprError;

    fn try_from(proto: ProtoVmConfig) -> Result<Self> {
        let resources = proto
            .resources
            .ok_or_else(|| HyprError::InvalidConfig { reason: "Missing resources".to_string() })?
            .try_into()?;

        let network = proto
            .network
            .ok_or_else(|| HyprError::InvalidConfig {
                reason: "Missing network config".to_string(),
            })?
            .try_into()?;

        Ok(Self {
            network_enabled: true, // gRPC VMs are runtime VMs
            id: proto.id,
            name: proto.name,
            resources,
            kernel_path: proto.kernel_path.map(PathBuf::from),
            kernel_args: proto.kernel_args,
            initramfs_path: None, // Proto support for initramfs not yet added to hypr.proto
            disks: proto.disks.into_iter().map(|d| d.try_into()).collect::<Result<Vec<_>>>()?,
            network,
            ports: proto.ports.into_iter().map(|p| p.try_into()).collect::<Result<Vec<_>>>()?,
            env: proto.env,
            volumes: proto.volumes.into_iter().map(|v| v.try_into()).collect::<Result<Vec<_>>>()?,
            gpu: proto.gpu.map(|g| g.try_into()).transpose()?,
            virtio_fs_mounts: vec![], // Proto support for virtio-fs not yet added to hypr.proto
        })
    }
}

impl From<VmResources> for ProtoVmResources {
    fn from(res: VmResources) -> Self {
        Self { cpus: res.cpus, memory_mb: res.memory_mb }
    }
}

impl TryFrom<ProtoVmResources> for VmResources {
    type Error = HyprError;

    fn try_from(proto: ProtoVmResources) -> Result<Self> {
        Ok(Self { cpus: proto.cpus, memory_mb: proto.memory_mb })
    }
}

impl From<DiskConfig> for ProtoDiskConfig {
    fn from(disk: DiskConfig) -> Self {
        let format = match disk.format {
            DiskFormat::Squashfs => "squashfs",
            DiskFormat::Ext4 => "ext4",
            DiskFormat::Raw => "raw",
        };

        Self {
            path: disk.path.to_str().unwrap_or_default().to_string(),
            readonly: disk.readonly,
            format: format.to_string(),
        }
    }
}

impl TryFrom<ProtoDiskConfig> for DiskConfig {
    type Error = HyprError;

    fn try_from(proto: ProtoDiskConfig) -> Result<Self> {
        let format = match proto.format.as_str() {
            "squashfs" => DiskFormat::Squashfs,
            "ext4" => DiskFormat::Ext4,
            "raw" => DiskFormat::Raw,
            _ => {
                return Err(HyprError::InvalidConfig {
                    reason: format!("Invalid disk format: {}", proto.format),
                })
            }
        };

        Ok(Self { path: PathBuf::from(proto.path), readonly: proto.readonly, format })
    }
}

impl From<NetworkConfig> for ProtoNetworkConfig {
    fn from(_net: NetworkConfig) -> Self {
        Self {
            mode: "bridge".to_string(), // Default mode
            cidr: None,                 // Managed by network module
            gateway: None,              // Managed by network module
        }
    }
}

impl TryFrom<ProtoNetworkConfig> for NetworkConfig {
    type Error = HyprError;

    fn try_from(_proto: ProtoNetworkConfig) -> Result<Self> {
        Ok(NetworkConfig::default())
    }
}

impl From<PortMapping> for ProtoPortMapping {
    fn from(port: PortMapping) -> Self {
        let protocol = match port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };

        Self {
            host_port: port.host_port as u32,
            guest_port: port.vm_port as u32,
            protocol: protocol.to_string(),
        }
    }
}

impl TryFrom<ProtoPortMapping> for PortMapping {
    type Error = HyprError;

    fn try_from(proto: ProtoPortMapping) -> Result<Self> {
        let protocol = match proto.protocol.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => {
                return Err(HyprError::InvalidConfig {
                    reason: format!("Invalid protocol: {}", proto.protocol),
                })
            }
        };

        Ok(Self { host_port: proto.host_port as u16, vm_port: proto.guest_port as u16, protocol })
    }
}

impl From<VolumeMount> for ProtoVolumeMount {
    fn from(vol: VolumeMount) -> Self {
        Self { source: vol.source, target: vol.target, readonly: vol.readonly }
    }
}

impl TryFrom<ProtoVolumeMount> for VolumeMount {
    type Error = HyprError;

    fn try_from(proto: ProtoVolumeMount) -> Result<Self> {
        Ok(Self { source: proto.source, target: proto.target, readonly: proto.readonly })
    }
}

impl From<GpuConfig> for ProtoGpuConfig {
    fn from(gpu: GpuConfig) -> Self {
        let vendor = match gpu.vendor {
            GpuVendor::Nvidia => "nvidia",
            GpuVendor::Amd => "amd",
            GpuVendor::Intel => "intel",
            GpuVendor::Metal => "metal",
        };

        Self {
            vendor: vendor.to_string(),
            pci_address: gpu.pci_address,
            model: gpu.model,
            use_sriov: gpu.use_sriov,
            gpu_memory_mb: gpu.gpu_memory_mb,
        }
    }
}

impl TryFrom<ProtoGpuConfig> for GpuConfig {
    type Error = HyprError;

    fn try_from(proto: ProtoGpuConfig) -> Result<Self> {
        let vendor = match proto.vendor.as_str() {
            "nvidia" => GpuVendor::Nvidia,
            "amd" => GpuVendor::Amd,
            "intel" => GpuVendor::Intel,
            "metal" => GpuVendor::Metal,
            _ => {
                return Err(HyprError::InvalidConfig {
                    reason: format!("Invalid GPU vendor: {}", proto.vendor),
                })
            }
        };

        Ok(Self {
            vendor,
            pci_address: proto.pci_address,
            model: proto.model,
            use_sriov: proto.use_sriov,
            gpu_memory_mb: proto.gpu_memory_mb,
        })
    }
}

// ============================================================================
// Image Conversions
// ============================================================================

impl From<Image> for ProtoImage {
    fn from(img: Image) -> Self {
        Self {
            id: img.id,
            name: img.name,
            tag: img.tag,
            manifest: Some(img.manifest.into()),
            rootfs_path: img.rootfs_path.to_str().unwrap_or_default().to_string(),
            size_bytes: img.size_bytes,
            created_at: img.created_at.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        }
    }
}

impl TryFrom<ProtoImage> for Image {
    type Error = HyprError;

    fn try_from(proto: ProtoImage) -> Result<Self> {
        let manifest = proto
            .manifest
            .ok_or_else(|| HyprError::InvalidConfig {
                reason: "Missing image manifest".to_string(),
            })?
            .try_into()?;

        Ok(Self {
            id: proto.id,
            name: proto.name,
            tag: proto.tag,
            manifest,
            rootfs_path: PathBuf::from(proto.rootfs_path),
            size_bytes: proto.size_bytes,
            created_at: UNIX_EPOCH + std::time::Duration::from_secs(proto.created_at as u64),
        })
    }
}

impl From<ImageManifest> for ProtoImageManifest {
    fn from(manifest: ImageManifest) -> Self {
        Self {
            version: manifest.version,
            name: manifest.name,
            tag: manifest.tag,
            architecture: manifest.architecture,
            os: manifest.os,
            entrypoint: manifest.entrypoint,
            cmd: manifest.cmd,
            env: manifest.env,
            workdir: manifest.workdir,
            exposed_ports: manifest.exposed_ports.into_iter().map(|p| p as u32).collect(),
            runtime: Some(manifest.runtime.into()),
            health: manifest.health.map(|h| h.into()),
        }
    }
}

impl TryFrom<ProtoImageManifest> for ImageManifest {
    type Error = HyprError;

    fn try_from(proto: ProtoImageManifest) -> Result<Self> {
        let runtime = proto
            .runtime
            .ok_or_else(|| HyprError::InvalidConfig {
                reason: "Missing runtime config".to_string(),
            })?
            .try_into()?;

        Ok(Self {
            version: proto.version,
            name: proto.name,
            tag: proto.tag,
            architecture: proto.architecture,
            os: proto.os,
            entrypoint: proto.entrypoint,
            cmd: proto.cmd,
            env: proto.env,
            workdir: proto.workdir,
            exposed_ports: proto.exposed_ports.into_iter().map(|p| p as u16).collect(),
            runtime,
            health: proto.health.map(|h| h.try_into()).transpose()?,
        })
    }
}

impl From<RuntimeConfig> for ProtoRuntimeConfig {
    fn from(config: RuntimeConfig) -> Self {
        let restart_policy = match config.restart_policy {
            RestartPolicy::No => "no",
            RestartPolicy::Always => "always",
            RestartPolicy::OnFailure => "on_failure",
            RestartPolicy::UnlessStopped => "unless_stopped",
        };

        Self {
            default_memory_mb: config.default_memory_mb,
            default_cpus: config.default_cpus,
            kernel_channel: config.kernel_channel,
            rootfs_type: config.rootfs_type,
            restart_policy: restart_policy.to_string(),
        }
    }
}

impl TryFrom<ProtoRuntimeConfig> for RuntimeConfig {
    type Error = HyprError;

    fn try_from(proto: ProtoRuntimeConfig) -> Result<Self> {
        let restart_policy = match proto.restart_policy.as_str() {
            "no" => RestartPolicy::No,
            "always" => RestartPolicy::Always,
            "on_failure" => RestartPolicy::OnFailure,
            "unless_stopped" => RestartPolicy::UnlessStopped,
            _ => {
                return Err(HyprError::InvalidConfig {
                    reason: format!("Invalid restart policy: {}", proto.restart_policy),
                })
            }
        };

        Ok(Self {
            default_memory_mb: proto.default_memory_mb,
            default_cpus: proto.default_cpus,
            kernel_channel: proto.kernel_channel,
            rootfs_type: proto.rootfs_type,
            restart_policy,
        })
    }
}

impl From<HealthCheckConfig> for ProtoHealthCheckConfig {
    fn from(health: HealthCheckConfig) -> Self {
        let check_type = match health.check_type {
            HealthCheckType::Http => "http",
            HealthCheckType::Tcp => "tcp",
            HealthCheckType::Exec => "exec",
        };

        Self {
            check_type: check_type.to_string(),
            endpoint: health.endpoint,
            port: health.port as u32,
            interval_sec: health.interval_sec,
            timeout_sec: health.timeout_sec,
            retries: health.retries,
        }
    }
}

impl TryFrom<ProtoHealthCheckConfig> for HealthCheckConfig {
    type Error = HyprError;

    fn try_from(proto: ProtoHealthCheckConfig) -> Result<Self> {
        let check_type = match proto.check_type.as_str() {
            "http" => HealthCheckType::Http,
            "tcp" => HealthCheckType::Tcp,
            "exec" => HealthCheckType::Exec,
            _ => {
                return Err(HyprError::InvalidConfig {
                    reason: format!("Invalid health check type: {}", proto.check_type),
                })
            }
        };

        Ok(Self {
            check_type,
            endpoint: proto.endpoint,
            port: proto.port as u16,
            interval_sec: proto.interval_sec,
            timeout_sec: proto.timeout_sec,
            retries: proto.retries,
        })
    }
}

// ============================================================================
// Stack Conversions
// ============================================================================

type ProtoStack = v1::Stack;
type ProtoStackService = v1::StackService;

impl From<Stack> for ProtoStack {
    fn from(stack: Stack) -> Self {
        Self {
            id: stack.id,
            name: stack.name,
            services: stack.services.into_iter().map(|s| s.into()).collect(),
            compose_path: stack.compose_path,
            created_at: stack.created_at.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        }
    }
}

impl TryFrom<ProtoStack> for Stack {
    type Error = HyprError;

    fn try_from(proto: ProtoStack) -> Result<Self> {
        Ok(Self {
            id: proto.id,
            name: proto.name,
            services: proto
                .services
                .into_iter()
                .map(|s| s.try_into())
                .collect::<Result<Vec<_>>>()?,
            compose_path: proto.compose_path,
            created_at: UNIX_EPOCH + std::time::Duration::from_secs(proto.created_at as u64),
        })
    }
}

impl From<Service> for ProtoStackService {
    fn from(service: Service) -> Self {
        Self { name: service.name, vm_id: service.vm_id, status: service.status }
    }
}

impl TryFrom<ProtoStackService> for Service {
    type Error = HyprError;

    fn try_from(proto: ProtoStackService) -> Result<Self> {
        Ok(Self { name: proto.name, vm_id: proto.vm_id, status: proto.status })
    }
}
