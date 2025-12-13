# HYPR

HYPR is a microVM orchestration platform that runs OCI container images as lightweight virtual machines. It provides container-like ergonomics with VM-level isolation, supporting GPU passthrough and sub-second boot times.

## Overview

HYPR converts standard container images into bootable microVMs. Each VM runs a minimal Linux kernel with the container's rootfs mounted as a squashfs filesystem. This architecture provides hardware-level isolation while maintaining the developer experience of containers.

```sh
hypr run nginx
```

## Features

### Core
- **OCI-Compatible**: Pull images from Docker Hub, GHCR, and any OCI registry
- **Dockerfile Builds**: Build images using standard Dockerfile syntax
- **Compose Support**: Deploy multi-service stacks with docker-compose.yml files
- **Volume Management**: Persistent named volumes and bind mounts
- **Custom Networks**: Create isolated networks with custom CIDR ranges
- **GPU Passthrough**: NVIDIA/AMD via VFIO (Linux), Metal via Virtualization.framework (macOS ARM64)
- **Sub-Second Boot**: VMs boot in under 500ms on warm cache
- **Exec Support**: Execute commands in running VMs like `docker exec`
- **Cross-Platform**: Linux (x86_64, ARM64) and macOS (Apple Silicon, Intel)

### Advanced (API)
- **VM Templates**: Pre-configured VM templates for common workloads
- **Snapshots**: Create and restore VM state snapshots
- **Metrics History**: Historical resource usage with configurable resolution
- **Process Explorer**: List processes running inside VMs
- **Security Scanning**: Vulnerability scanning with Trivy integration
- **Cron Jobs**: Schedule recurring VM tasks
- **Dev Environments**: devcontainer.json support for development
- **Rolling Updates**: Zero-downtime stack updates
- **Docker Import**: Import existing Docker containers and images

## Installation

```sh
curl -fsSL https://get.hypr.tech | sh
```

This installs:
- `hypr` - CLI tool
- `hyprd` - Background daemon (installed as systemd service or LaunchDaemon)

The installer automatically handles dependencies:
- **gvproxy** (via podman) - Userspace networking
- **squashfs-tools** - Image building
- **virtiofsd** (Linux only) - Filesystem sharing

### What's Embedded (No Install Needed)
- **libkrun** (macOS) - Hypervisor runtime
- **cloud-hypervisor** (Linux) - VMM binary
- **initramfs** - Boot environment with kestrel guest agent
- **Linux kernel** - Pre-built HYPR kernel

### Requirements

**Linux:**
- x86_64 or ARM64
- Kernel 5.10+ with KVM support (`/dev/kvm` accessible)

**macOS:**
- macOS 13+ (Ventura) - Intel and Apple Silicon
- macOS 14+ (Sonoma) recommended for GPU support

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
- `FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `ARG`
- `WORKDIR`, `USER`, `EXPOSE`, `CMD`, `ENTRYPOINT`
- `HEALTHCHECK`, `LABEL`, `VOLUME`, `SHELL`
- Multi-stage builds with `--target`

Build options:
```sh
hypr build <path>
  --tag <name:tag>        # Image name and tag
  --file <Dockerfile>     # Dockerfile path (default: Dockerfile)
  --build-arg KEY=VALUE   # Build arguments
  --target <stage>        # Multi-stage target
  --no-cache              # Disable build cache
```

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
hypr compose logs <service>  # Stream service logs
```

Example compose file:
```yaml
version: "3"
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - webdata:/usr/share/nginx/html
    depends_on:
      - api

  api:
    build: ./api
    environment:
      DATABASE_URL: postgres://db:5432/app
    networks:
      - backend

  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - backend

volumes:
  webdata:
  pgdata:

networks:
  backend:
```

## Volumes

Create and manage persistent volumes:
```sh
hypr volume create mydata      # Create volume
hypr volume ls                 # List volumes
hypr volume inspect mydata     # Show details
hypr volume rm mydata          # Remove volume
hypr volume prune              # Remove unused volumes
```

Use volumes when running VMs:
```sh
hypr run -v mydata:/data nginx
```

## Networks

Create isolated networks for service communication:
```sh
hypr network create mynet                         # Create network
hypr network create mynet --subnet 10.89.0.0/16   # Custom CIDR
hypr network ls                                   # List networks
hypr network inspect mynet                        # Show details
hypr network rm mynet                             # Remove network
hypr network prune                                # Remove unused networks
```

## GPU Passthrough

**Linux (VFIO):**
```sh
hypr gpu list                           # List available GPUs
hypr run --gpu 0000:01:00.0 <image>     # Attach specific GPU by PCI address
```

**macOS Apple Silicon (Metal):**
```sh
hypr run --gpu <image>                  # Enable Metal GPU
```

GPU passthrough is not available on Intel Macs.

### GPU Time-Slicing (API)

For multi-tenant GPU sharing, configure time-slicing via the API:
- `time_slice_ms` - Time slice duration in milliseconds
- `memory_fraction` - Fraction of GPU memory (0.0-1.0)

## Run Options

```sh
hypr run <image>
  --name <name>           # VM name
  --cpus <n>              # Number of vCPUs (default: 2)
  --memory <mb>           # Memory in MB (default: 512)
  --port <host:guest>     # Port mapping (repeatable)
  --env KEY=VALUE         # Environment variable (repeatable)
  --volume <vol:/path>    # Volume mount (repeatable)
  --gpu [address]         # GPU passthrough
  --detach                # Run in background
```

## System Maintenance

View disk usage:
```sh
hypr system df
```

Clean up unused resources:
```sh
hypr system prune            # Remove dangling images and cache
hypr system prune --all      # Also remove stopped VMs
hypr system prune --volumes  # Also remove unused volumes
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        hypr CLI                             │
│                  (gRPC client, user interface)              │
└─────────────────────────────────┬───────────────────────────┘
                                  │ gRPC (Unix socket :41000)
┌─────────────────────────────────▼───────────────────────────┐
│                          hyprd                              │
│           (daemon: VM lifecycle, networking, state)         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ StateManager│  │ NetworkMgr  │  │    VmmAdapter       │  │
│  │  (SQLite)   │  │ (gvproxy)   │  │ (CHV/libkrun)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────┬───────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                        microVM                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Linux Kernel + Kestrel (PID 1 guest agent)           │  │
│  │  SquashFS rootfs + overlayfs (copy-on-write)          │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Hypervisor Adapters

| Platform       | Hypervisor        | GPU Support |
|----------------|-------------------|-------------|
| Linux x86_64   | cloud-hypervisor  | VFIO        |
| Linux ARM64    | cloud-hypervisor  | VFIO        |
| macOS ARM64    | libkrun           | Metal       |
| macOS Intel    | libkrun           | None        |

### Networking

HYPR uses **gvproxy** (gvisor-tap-vsock) for unified networking on both platforms:
- Userspace networking - no root required
- Built-in DHCP, DNS, and NAT
- Port forwarding without kernel modules
- Default subnet: 192.168.127.0/24

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
| `/var/lib/hypr/bin/` | Extracted binaries (cloud-hypervisor) |
| `/var/lib/hypr/lib/` | Extracted libraries (libkrun.dylib) |

### Ports

HYPR uses ports in the 41000-41999 range to avoid conflicts:

| Port  | Service |
|-------|---------|
| 41000 | gRPC API |
| 41001 | REST gateway |
| 41002 | Prometheus metrics |
| 41003 | DNS server |

## API Features

The following features are available via the gRPC API (CLI commands coming soon):

### Templates
Pre-configured VM templates for common workloads:
- List available templates by category
- Run VMs from templates with customization

### Snapshots
Save and restore VM state:
- Create memory + disk snapshots
- List snapshots for a VM
- Restore to a previous state
- Delete old snapshots

### Metrics History
Historical resource usage:
- CPU, memory, disk, network metrics
- Configurable resolution (1s, 5s, 1m, 5m, 1h)
- Time-range queries

### Process Explorer
View processes inside VMs:
- List all processes with resource usage
- Sort by CPU, memory, PID, name
- Tree view of process hierarchy

### Security Scanning
Vulnerability scanning with Trivy:
- Scan images before running
- Get vulnerability reports by severity
- Risk assessment and recommendations

### Cron Jobs
Schedule recurring VM tasks:
- Cron expression scheduling
- Configurable resources and timeouts
- Run history and status tracking

### Dev Environments
devcontainer.json support:
- Clone repos and set up dev environments
- Port forwarding for development
- VS Code integration ready

### Rolling Updates
Zero-downtime stack updates:
- Service-by-service updates
- Automatic rollback on failure
- Health check verification

### Docker Import
Migrate from Docker:
- Import running containers as VMs
- Import Docker images to HYPR format
- Preserve volumes and networks

## Troubleshooting

### Check daemon status

**Linux:**
```sh
sudo systemctl status hyprd
journalctl -u hyprd -f
```

**macOS:**
```sh
sudo launchctl list | grep hypr
tail -f /var/log/hypr/hyprd.log
```

### Restart daemon

**Linux:**
```sh
sudo systemctl restart hyprd
```

**macOS:**
```sh
sudo launchctl kickstart -k system/ai.hypr.hyprd
```

### Check health
```sh
hypr health
```

### Common Issues

**"gvproxy not found"**
```sh
# macOS
brew install podman

# Linux (Debian/Ubuntu)
sudo apt install podman

# Linux (Fedora)
sudo dnf install podman
```

**"KVM not accessible"**
```sh
# Add user to kvm group
sudo usermod -aG kvm $USER
# Log out and back in
```

**"mksquashfs not found"**
```sh
# macOS
brew install squashfs

# Linux
sudo apt install squashfs-tools
```

## License

Business Source License 1.1 (BSL-1.1)

## Repository

https://github.com/hyprhq/hypr
