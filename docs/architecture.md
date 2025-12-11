# Architecture

Technical overview of HYPR's internal architecture.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              User                                       │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────┐
│                            hypr CLI                                     │
│                      (gRPC client, TUI)                                 │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │ gRPC (Unix socket)
┌─────────────────────────────────▼───────────────────────────────────────┐
│                             hyprd                                       │
│                    (Daemon - runs as root)                              │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │  API Server  │  │   State      │  │  Network     │  │  Orchestr.  │  │
│  │   (gRPC)     │  │  (SQLite)    │  │  Manager     │  │  (Stacks)   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘  │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐   │
│  │  Builder     │  │  Registry    │  │       VMM Adapter            │   │
│  │ (Dockerfile) │  │ (OCI pull)   │  │  ┌────────┐ ┌────────┐       │   │
│  └──────────────┘  └──────────────┘  │  │  CHV   │ │krunkit │ ...   │   │
│                                       │  └────────┘ └────────┘       │   │
│                                       └──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────────────┐
│                           microVMs                                      │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  Linux Kernel (6.12)                                           │     │
│  │  Kestrel (PID 1) - guest agent                                 │     │
│  │  SquashFS rootfs + overlayfs                                   │     │
│  │  virtio-net, virtio-blk, virtio-vsock                          │     │
│  └────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### hypr CLI

The command-line interface that users interact with. Written in Rust using clap for argument parsing.

**Key files:**
- `hypr-cli/src/main.rs` - Command definitions and routing
- `hypr-cli/src/client/mod.rs` - gRPC client wrapper
- `hypr-cli/src/commands/` - Individual command implementations

**Communication:**
The CLI connects to hyprd via a Unix socket at `/run/hypr/hypr.sock` (Linux) or `/tmp/hypr/hypr.sock` (macOS).

### hyprd Daemon

The background service that manages all VM operations. Runs as root for hardware access (KVM, networking, VFIO).

**Key files:**
- `hypr-daemon/src/main.rs` - Daemon entry point, initialization
- `hypr-daemon/src/api/server.rs` - gRPC service implementation
- `hypr-daemon/src/network_manager.rs` - Network setup and management
- `hypr-daemon/src/orchestrator/` - Stack orchestration

**Responsibilities:**
- VM lifecycle management (create, start, stop, delete)
- Network setup (bridge, TAP devices, port forwarding)
- Image management (storage, lookup)
- State persistence (SQLite)
- Graceful shutdown and cleanup

### State Manager

Persistent storage using SQLite. Stores VM state, images, stacks, and configuration.

**Location:** `/var/lib/hypr/hypr.db`

**Tables:**
- `vms` - VM records with config, status, timestamps
- `images` - Image metadata and paths
- `stacks` - Compose stack definitions
- Migrations handled automatically on startup

### Network Manager

Handles all networking for VMs.

**Linux:**
- Creates bridge device `vbr0`
- Allocates TAP devices per VM
- IP allocation via built-in IPAM (10.88.0.0/16)
- Port forwarding via eBPF or userspace proxy
- DNS server for `.hypr` domain resolution

**macOS:**
- Uses vmnet framework (via krunkit/vfkit)
- IP allocation via DHCP (192.168.64.0/24)
- Port forwarding via userspace proxy

### VMM Adapter

Abstract interface for hypervisor operations. Platform-specific implementations:

| Adapter | Platform | Hypervisor |
|---------|----------|------------|
| `CloudHypervisorAdapter` | Linux | cloud-hypervisor |
| `HvfAdapter` | macOS ARM64 | krunkit |
| `HvfAdapter` | macOS Intel | vfkit |

**Key files:**
- `hypr-core/src/adapters/mod.rs` - Trait definition
- `hypr-core/src/adapters/cloudhypervisor.rs` - Linux adapter
- `hypr-core/src/adapters/hvf.rs` - macOS adapter

**Trait interface:**
```rust
#[async_trait]
pub trait VmmAdapter: Send + Sync {
    async fn build_command(&self, config: &VmConfig) -> Result<CommandSpec>;
    async fn create(&self, config: &VmConfig) -> Result<VmHandle>;
    async fn start(&self, handle: &VmHandle) -> Result<()>;
    async fn stop(&self, handle: &VmHandle, timeout: Duration) -> Result<()>;
    async fn kill(&self, handle: &VmHandle) -> Result<()>;
    async fn delete(&self, handle: &VmHandle) -> Result<()>;
    // ...
}
```

### Builder

Builds images from Dockerfiles.

**Process:**
1. Parse Dockerfile into AST (`parser.rs`)
2. Build dependency graph (`graph.rs`)
3. Check layer cache (`cache.rs`)
4. Execute instructions in build VM (`executor.rs`)
5. Generate squashfs and manifest (`manifest.rs`)

**Key files:**
- `hypr-core/src/builder/parser.rs` - Dockerfile parser
- `hypr-core/src/builder/executor.rs` - Build execution
- `hypr-core/src/builder/oci.rs` - OCI layer handling

### Registry Client

Pulls images from OCI registries.

**Key files:**
- `hypr-core/src/registry/mod.rs` - Image puller

**Process:**
1. Parse image reference (handle Docker Hub shorthand)
2. Authenticate (anonymous or with credentials)
3. Fetch manifest, select platform
4. Download and extract layers
5. Create squashfs from extracted rootfs
6. Save manifest with entrypoint, env, ports

### Kestrel Guest Agent

Minimal C program that runs as PID 1 inside VMs. Compiled statically (~500KB).

**Key files:**
- `guest/kestrel.c` - Guest agent source

**Responsibilities:**
- Mount essential filesystems (/proc, /sys, /dev)
- Mount rootfs (squashfs + overlayfs)
- Parse runtime manifest from kernel cmdline
- Configure networking (IP, gateway, DNS)
- Execute user workload
- Handle exec sessions via vsock
- Reap zombie processes
- Implement restart policies

**Modes:**
- **Runtime mode**: Normal VM operation
- **Build mode**: Isolated build environment (no network)

## Data Flow

### Running a VM

1. User: `hypr run nginx -p 8080:80`
2. CLI parses args, calls `CreateVM` RPC
3. Daemon checks for image, pulls if needed
4. Network manager allocates IP and TAP device
5. Adapter builds hypervisor command
6. Hypervisor spawns VM with kernel + initramfs
7. Kestrel mounts rootfs, configures network
8. Kestrel executes entrypoint
9. Port forwarding activated

### Executing Commands

1. User: `hypr exec vm123 -- ls -la`
2. CLI calls exec RPC
3. Daemon looks up VM's vsock path
4. CLI connects to vsock, sends exec request
5. Kestrel spawns command, relays I/O
6. Exit code returned to CLI

## Ports and Sockets

HYPR uses ports in the 41000-41999 range:

| Port | Service |
|------|---------|
| 41000 | gRPC API |
| 41001 | REST gateway |
| 41002 | Prometheus metrics |
| 41003 | DNS server |
| 41010 | Build proxy |
| 41011 | Build agent vsock |

## File Layout

```
/var/lib/hypr/
├── hypr.db              # SQLite database
├── images/              # Built/pulled images
│   └── nginx_latest/
│       ├── rootfs.squashfs
│       └── manifest.json
├── logs/                # VM logs
│   └── <vm-id>.log
└── cache/               # Build cache

/run/hypr/               # Runtime (Linux)
/tmp/hypr/               # Runtime (macOS)
├── hypr.sock            # gRPC Unix socket
├── hyprd.pid            # Daemon PID file
├── <vm-id>.vsock        # VM vsock sockets
└── kestrel-initramfs.cpio
```

## Observability

### Logging

Structured logging via `tracing` crate. Control with `RUST_LOG`:
```sh
RUST_LOG=info hyprd                    # Info and above
RUST_LOG=hypr_core=debug hyprd         # Debug for core
RUST_LOG=hypr_daemon::api=trace hyprd  # Trace for API
```

### Metrics

Prometheus metrics exposed at `:41002/metrics`:
- VM counts by status
- Operation durations
- Network bytes
- Build statistics

### Tracing

OpenTelemetry support for distributed tracing:
```sh
HYPR_OTLP_ENABLED=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 hyprd
```

## Security Model

- Daemon runs as root for KVM/hardware access
- VMs are isolated via hardware virtualization
- Each VM has its own kernel, memory, network
- Build VMs have no network access (filesystem IPC only)
- Boot VGA protection prevents display GPU unbind
