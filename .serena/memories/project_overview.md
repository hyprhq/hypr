# Project Overview: HYPR

HYPR is a Rust-based, drop-in Docker replacement that uses microVMs. It provides the developer experience of Docker (`hypr run`, `hypr build`) with the security and isolation of dedicated kernels.

## Core Value Proposition
1. **Zero-Dependency Distribution:** Single binary containing Hypervisor, Kernel, and Initramfs.
2. **"No-Tax" Guest Agent:** Uses `Kestrel` (static C, ~500KB) instead of heavy agents, enabling <50ms boot times.
3. **True Docker Parity:** Natively parses `Dockerfile` and `docker-compose.yml`.

## Architecture

### Host (Monolithic Rust)
* **`hyprd` (Daemon):** The brain.
  * **Orchestrator:** Manages VM lifecycle and multi-VM stacks (`hypr-daemon/src/api/server.rs`).
  * **Network Manager:** Coordinates IP allocation (IPAM), port forwarding (Proxy/eBPF), and DNS (`hypr-daemon/src/network_manager.rs`).
  * **State Manager:** Persistent state via SQLite (`hypr-core/src/state`).
  * **API Server:** gRPC over Unix socket (`hypr-daemon/src/api/server.rs`).
* **`hypr` (CLI):** User interface, talks to daemon via gRPC.

### Guest (The MicroVM)
* **Hypervisor:**
  * **macOS:** `vfkit` (Apple Virtualization Framework) via `HvfAdapter`
  * **Linux:** `cloud-hypervisor` (KVM) via `CloudHypervisorAdapter`
* **Kernel:** Custom Linux kernel (auto-downloaded from cloud-hypervisor releases).
* **Agent (`kestrel`):**
  * Static C binary, runs as PID 1.
  * **Build Mode:** Handles filesystem operations via virtio-fs for image building.
  * **Runtime Mode:** Handles networking setup, process supervision, and health checks.

## Build System Architecture

### Build Flow
1. **Parser** (`hypr-core/src/builder/parser.rs`): Parses Dockerfile into `Dockerfile` struct with stages
2. **Graph** (`hypr-core/src/builder/graph.rs`): Converts to DAG with cache keys and dependency tracking
3. **Executor** (`hypr-core/src/builder/executor.rs`): Executes build in VM
   - `MacOsVmBuilder`: Uses vfkit/HVF
   - `LinuxVmBuilder`: Uses cloud-hypervisor
   - `NativeBuilder`: Linux-only chroot-based (alternative)
4. **VM Builder** (`hypr-core/src/builder/vm_builder.rs`): Spawns VMs, writes command files
5. **Kestrel** (`guest/kestrel.c`): Executes commands in VM, creates layer tarballs

### Build Mode Protocol (Filesystem-based IPC)
1. Host writes command files to `/context/.hypr/commands/NNN.cmd`
2. VM boots, kestrel scans commands directory
3. Kestrel executes commands in lexical order
4. Kestrel prints `[HYPR-RESULT]` markers to stdout
5. On `FINALIZE`, creates layer tarball in `/shared/`
6. VM exits, host collects results

## Compose System

### Files
* **Types**: `hypr-core/src/compose/types.rs` - ComposeFile, Service, Environment, Resources
* **Parser**: `hypr-core/src/compose/parser.rs` - YAML parsing and validation
* **Converter**: `hypr-core/src/compose/converter.rs` - Converts to StackConfig
* **Stack Types**: `hypr-core/src/types/stack.rs` - Runtime stack representation

### Current Limitations
* Only `image:` directive supported (no `build:`)
* No multi-stage build integration

## Directory Structure
* `hypr-core`: Shared logic, adapters, builder, networking types, compose, state
* `hypr-daemon`: Main runtime, API server, orchestration logic
* `hypr-cli`: Command-line interface (build, run, compose up/down, ps, images, logs)
* `hypr-api`: gRPC proto definitions
* `guest`: Kestrel agent source code (C)
* `scripts`: Utility scripts