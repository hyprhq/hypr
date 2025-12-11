# HYPR Documentation

HYPR is a microVM orchestration platform that runs OCI container images as lightweight virtual machines.

## What is HYPR?

HYPR bridges the gap between containers and virtual machines. It takes standard container images from any OCI registry and boots them as isolated microVMs with their own Linux kernel. This provides hardware-level isolation while maintaining the developer experience of containers.

Each VM runs:
- A minimal Linux kernel (6.12) with essential drivers
- A guest agent (Kestrel) as PID 1
- The container rootfs as a read-only squashfs with overlayfs for writes

## Why HYPR?

**VM-Level Isolation**: Each workload runs in its own virtual machine with separate kernel, memory, and CPU allocation. Kernel vulnerabilities in one VM cannot affect others.

**Container Ergonomics**: Use the same images, Dockerfiles, and compose files you already have. No new formats to learn.

**GPU Support**: Pass GPUs through to VMs for ML/AI workloads. Supports NVIDIA/AMD via VFIO on Linux and Metal on Apple Silicon.

**Fast Boot Times**: Optimized kernel and guest agent enable sub-second VM boot times.

## Documentation Sections

- [Getting Started](getting-started.md) - Installation and first VM
- [CLI Reference](cli-reference.md) - Complete command documentation
- [Building Images](building-images.md) - Dockerfile support
- [Compose Stacks](compose.md) - Multi-service deployments
- [GPU Passthrough](gpu.md) - GPU acceleration
- [Architecture](architecture.md) - System internals
- [Configuration](configuration.md) - Environment and paths
- [Troubleshooting](troubleshooting.md) - Common issues

## Platform Support

| Platform | Architecture | Hypervisor | GPU Support |
|----------|--------------|------------|-------------|
| Linux | x86_64 | cloud-hypervisor | VFIO |
| Linux | ARM64 | cloud-hypervisor | VFIO |
| macOS | Apple Silicon | krunkit | Metal |
| macOS | Intel | vfkit | None |

## Quick Example

```sh
# Install HYPR
curl -fsSL https://get.hypr.tech | sh

# Run nginx with port mapping
hypr run nginx -p 8080:80

# Check running VMs
hypr ps

# View logs
hypr logs <vm-id> -f

# Execute command in VM
hypr exec <vm-id> -- cat /etc/nginx/nginx.conf

# Stop and remove
hypr stop <vm-id>
hypr rm <vm-id>
```

## License

HYPR is licensed under the Business Source License 1.1 (BSL-1.1).
