# HYPR

HYPR is a microVM orchestration platform that runs OCI container images as lightweight virtual machines. It provides container-like ergonomics with VM-level isolation, supporting GPU passthrough and sub-second boot times.

## Overview

HYPR converts standard container images into bootable microVMs. Each VM runs a minimal Linux kernel with the container's rootfs mounted as a squashfs filesystem. This architecture provides hardware-level isolation while maintaining the developer experience of containers.

```
hypr run nginx
```

## Features

- **OCI-Compatible**: Pull images from Docker Hub, GHCR, and any OCI registry
- **Dockerfile Builds**: Build images using standard Dockerfile syntax
- **Compose Support**: Deploy multi-service stacks with docker-compose.yml files
- **Volume Management**: Persistent named volumes and bind mounts
- **Custom Networks**: Create isolated networks with custom CIDR ranges
- **GPU Passthrough**: NVIDIA/AMD via VFIO (Linux), Metal via Venus (macOS ARM64)
- **Sub-Second Boot**: VMs boot in under 500ms on warm cache
- **Exec Support**: Execute commands in running VMs like `docker exec`
- **Cross-Platform**: Linux (x86_64, ARM64) and macOS (Apple Silicon, Intel)

## Installation

```sh
curl -fsSL https://get.hypr.tech | sh
```

This installs:
- `hypr` - CLI tool
- `hyprd` - Background daemon (installed as systemd service or LaunchDaemon)

### Requirements

**Linux:**
- x86_64 or ARM64
- Kernel 5.10+ with KVM support
- `squashfs-tools` for image builds
- `virtiofsd` for shared filesystem support

**macOS:**
- macOS 14+ (Sonoma) for Apple Silicon GPU support
- `libkrun-efi` library (installed via `brew tap slp/krunkit && brew install libkrun-efi`)
- `squashfs` from Homebrew

## Quick Start

Run a VM from a registry image:
```sh
hypr run nginx -p 8080:80
```

List running VMs:
```sh
hypr ps
```

Execute a command in a VM:
```sh
hypr exec <vm> -- ls -la
```

Stream logs:
```sh
hypr logs <vm> -f
```

Stop and remove:
```sh
hypr stop <vm>
hypr rm <vm>
```

## Building Images

Build from a Dockerfile:
```sh
hypr build -t myapp:latest .
```

Supported Dockerfile instructions:
- FROM, RUN, COPY, ADD, ENV, ARG
- WORKDIR, USER, EXPOSE, CMD, ENTRYPOINT
- HEALTHCHECK, LABEL, VOLUME, SHELL
- Multi-stage builds with `--target`

## Compose Stacks

Deploy a multi-service stack:
```sh
hypr compose up -f docker-compose.yml
```

Supported compose file names (searched in order):
- `hypr-compose.yml`, `hypr-compose.yaml`
- `Hyprfile`, `Hyprfile.yml`, `Hyprfile.yaml`
- `docker-compose.yml`, `docker-compose.yaml`
- `compose.yml`, `compose.yaml`

Manage stacks:
```sh
hypr compose ps              # List stacks
hypr compose down <stack>    # Destroy stack
```

## Volumes

Create and manage persistent volumes:
```sh
hypr volume create mydata         # Create volume
hypr volume ls                    # List volumes
hypr volume inspect mydata        # Show details
hypr volume rm mydata             # Remove volume
hypr volume prune                 # Remove unused volumes
```

Use volumes in compose:
```yaml
services:
  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

## Networks

Create isolated networks for service communication:
```sh
hypr network create mynet                      # Create network
hypr network create mynet --subnet 10.89.0.0/16  # Custom CIDR
hypr network ls                                # List networks
hypr network inspect mynet                     # Show details
hypr network rm mynet                          # Remove network
hypr network prune                             # Remove unused networks
```

Use networks in compose:
```yaml
services:
  web:
    networks:
      - frontend
  api:
    networks:
      - frontend
      - backend

networks:
  frontend:
  backend:
```

## GPU Passthrough

**Linux (VFIO):**
```sh
hypr gpu list                           # List available GPUs
hypr run --gpu 0000:01:00.0 <image>     # Attach specific GPU
```

**macOS Apple Silicon (Metal):**
```sh
hypr run --gpu <image>                  # Enable Metal GPU
```

GPU passthrough is not available on Intel Macs.

## Architecture

```
+-----------------------------------------------------------------+
|                         hypr CLI                                |
|                   (gRPC client, user interface)                 |
+---------------------------------+-------------------------------+
                                  | gRPC (Unix socket)
+---------------------------------v-------------------------------+
|                         hyprd                                   |
|         (daemon: VM lifecycle, networking, state)               |
+-----------------------------------------------------------------+
|  +-------------+  +-------------+  +-----------------------+    |
|  | StateManager|  | NetworkMgr  |  |   VmmAdapter          |    |
|  |  (SQLite)   |  | (bridge,DNS)|  | (CHV/libkrun)         |    |
|  +-------------+  +-------------+  +-----------------------+    |
+---------------------------------+-------------------------------+
                                  |
+---------------------------------v-------------------------------+
|                       microVM                                   |
|  +-----------------------------------------------------------+  |
|  |  Linux Kernel + Kestrel (PID 1 guest agent)               |  |
|  |  SquashFS rootfs + overlayfs (copy-on-write)              |  |
|  +-----------------------------------------------------------+  |
+-----------------------------------------------------------------+
```

### Hypervisor Adapters

| Platform       | Hypervisor        | GPU Support |
|----------------|-------------------|-------------|
| Linux          | cloud-hypervisor  | VFIO        |
| macOS ARM64    | libkrun           | Metal       |
| macOS Intel    | libkrun           | None        |

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `HYPR_DATA_DIR` | Data directory (default: `/var/lib/hypr`) |
| `HYPR_RUNTIME_DIR` | Runtime directory (default: `/run/hypr` or `/tmp/hypr`) |
| `RUST_LOG` | Log level (e.g., `info`, `debug`, `hypr_core=debug`) |
| `HYPR_OTLP_ENABLED` | Enable OpenTelemetry tracing |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint for traces |

### Data Paths

| Path | Description |
|------|-------------|
| `/var/lib/hypr/hypr.db` | SQLite database |
| `/var/lib/hypr/images/` | Built and pulled images |
| `/var/lib/hypr/volumes/` | Named volumes |
| `/var/lib/hypr/logs/` | VM logs |
| `/var/lib/hypr/cache/` | Build cache |

### Ports

HYPR uses ports in the 41000-41999 range to avoid conflicts:

| Port  | Service |
|-------|---------|
| 41000 | gRPC API |
| 41001 | REST gateway |
| 41002 | Prometheus metrics |
| 41003 | DNS server |

## System Maintenance

View disk usage:
```sh
hypr system df
```

Clean up unused resources:
```sh
hypr system prune          # Remove dangling images and cache
hypr system prune --all    # Also remove stopped VMs
hypr system prune --volumes  # Also remove unused volumes
```

## Documentation

Full documentation is available in the [docs/](docs/) directory:

- [Getting Started](docs/getting-started.md) - Installation and first VM
- [CLI Reference](docs/cli-reference.md) - Complete command documentation
- [Building Images](docs/building-images.md) - Dockerfile support
- [Compose Stacks](docs/compose.md) - Multi-service deployments
- [Networking](docs/networking.md) - Network configuration
- [Volumes](docs/volumes.md) - Persistent storage
- [GPU Passthrough](docs/gpu.md) - GPU acceleration
- [Architecture](docs/architecture.md) - System internals
- [Configuration](docs/configuration.md) - Environment and paths
- [Troubleshooting](docs/troubleshooting.md) - Common issues

## License

Business Source License 1.1 (BSL-1.1)

## Repository

https://github.com/hyprhq/hypr
