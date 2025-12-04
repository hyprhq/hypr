### The Pivot: Why Volant became HYPR

**Volant** was built like a cloud platform—a distributed set of microservices (Daemon, CLI, Builder, Load Balancer) written in Go. It was powerful but heavy. It required external dependencies (`skopeo`, `umoci`, `cloud-hypervisor`) and the Guest Agent was a 10MB+ Go binary.

**HYPR** is a systems tool. It is rewritten in **Rust** to achieve three critical goals that Volant missed:

1.  **Zero-Dependency Distribution:** HYPR embeds the Hypervisor, Kernel, and Initramfs directly into a single binary. No `apt-get install`. You download one file, and it runs anywhere.
2.  **The "No-Tax" Guest Agent:** We replaced the Go agent with **Kestrel (C)**—a 20KB static binary. This reduces boot overhead from ~400ms to <50ms.
3.  **True Docker Parity:** Volant required conversion tools (`volant-compose`). HYPR parses `Dockerfile` and `docker-compose.yml` natively. It is a drop-in replacement, not a migration project.

---

### New README.md

You can drop this file directly into your repo.

***

# HYPR

**The hardware-isolated runtime for the container era.**

[![Build Status](https://img.shields.io/github/actions/workflow/status/hyprhq/hypr/ci.yml?branch=main&style=flat-square)](https://github.com/hypr-net/hypr/actions)
[![Rust](https://img.shields.io/badge/Built%20with-Rust-orange?style=flat-square)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-BSL_1.1-black.svg?style=flat-square)](LICENSE)

> **"Your `docker-compose.yml` already works. Just faster, safer, and with true hardware isolation."**

HYPR (formerly Volant) is a drop-in replacement for Docker that runs your workloads in **microVMs** instead of containers. It provides the developer experience you know (`hypr build`, `hypr run`) with the security and isolation of a dedicated kernel.

It solves the "Security vs. Speed" trade-off by embedding a custom hypervisor stack directly into a single binary. No heavy background daemons, no Kubernetes sprawl, just instant, secure VMs.

---

## ⚡️ The 30-Second Pitch

1.  **It's just Docker (on the surface):** Supports `Dockerfile`, `docker-compose.yml`, and OCI images out of the box.
2.  **It's a VM (under the hood):** Every container gets its own Linux Kernel. A kernel panic in one app cannot crash the host or leak data to neighbors.
3.  **It's Fast:** Boots in **<50ms** thanks to **Kestrel**, our 20KB static C guest agent.
4.  **It's Everywhere:** Develop on macOS (Apple Silicon/Intel) with native virtualization, deploy to Linux with eBPF networking.

---

## 🚀 Quick Start

### 1. Install
HYPR is a single binary with zero external dependencies.

```bash
curl -fsSL https://get.hypr.tech | sh
hypr daemon start
```

### 2. Run a Container (as a VM)
Use the commands you already know.

```bash
# Pulls nginx from Docker Hub, converts to rootfs, boots in a microVM
hypr run -p 8080:80 --name web nginx:latest
```

### 3. Run a Stack
Navigate to any folder with a `docker-compose.yml`:

```bash
# Boots the whole stack in parallel microVMs
hypr compose up
```

That's it. You are now running hardware-isolated infrastructure.

---

## 🏗 Architecture

HYPR is a monolithic Rust application designed for extreme density and speed.

```mermaid
graph TD
    CLI[hypr CLI] -->|gRPC| D[hyprd Daemon]
    D -->|Manage| DB[(SQLite State)]
    D -->|Control| VMM[VMM Adapter]
    
    subgraph Host
        VMM -->|Linux| CH[Cloud Hypervisor]
        VMM -->|macOS| VF[Apple Virtualization]
        
        D -->|Load Balance| EBPF[Drift eBPF]
    end
    
    subgraph MicroVM
        CH --> Kernel[Linux Kernel]
        Kernel --> Kestrel[Kestrel Agent (PID 1)]
        Kestrel --> App[User Workload]
    end
```

### Key Components

*   **`hyprd` (Rust):** The brain. Handles image building (DAG solver), state management (SQLite), and orchestration.
*   **Kestrel (C):** The heart. A 20KB static guest agent that replaces systemd. It handles mounting, networking, and process supervision inside the VM instantly.
*   **Drift (eBPF):** The muscle. On Linux, HYPR loads custom eBPF programs into the kernel to handle L4 load balancing and NAT at line rate (10Gbps+).
*   **Hermetic Builder:** HYPR doesn't use BuildKit. It spins up ephemeral microVMs to run `RUN` commands, ensuring your build process is completely isolated from the host.

---

## 🛠 Features

### 1. Universal Compatibility
Don't rewrite your manifests. HYPR parses standard `Dockerfile` and `docker-compose.yml` files. It automatically handles volume mounts, port forwarding, and environment variables.

### 2. True Dev/Prod Parity
*   **macOS:** Uses `HVF` (Hypervisor.framework) and `virtio-fs` for native speed.
*   **Linux:** Uses `KVM` and `io_uring` for production performance.
*   **The Result:** The exact same kernel and userspace run on your laptop and your server.

### 3. GPU Passthrough (VFIO)
AI/ML workloads are first-class citizens. HYPR handles the complexity of IOMMU groups and VFIO binding.

```bash
# Pass a specific NVIDIA GPU to the VM
hypr run --gpu pci:0000:01:00.0 pytorch/pytorch:latest
```

### 4. Hermetic Builds
Builds happen inside a disposable VM. A malicious `npm install` script cannot access your host filesystem, SSH keys, or environment variables.

```bash
# Builds in a secure VM, outputs a signed SquashFS image
hypr build -t my-app .
```

---

## 📊 Performance: HYPR vs The World

| Feature | Docker | Firecracker | HYPR |
| :--- | :--- | :--- | :--- |
| **Isolation** | Process (Weak) | Hardware (Strong) | **Hardware (Strong)** |
| **Boot Time** | ~1s | ~150ms | **<50ms** |
| **Agent Overhead** | High (Host) | N/A | **Zero (20KB C binary)** |
| **Networking** | Bridge/IPTables | Tap/Tun | **eBPF / XDP** |
| **UX** | Excellent | Low-level | **Excellent (Docker-like)** |
| **State** | Mutable | Ephemeral | **Persistent (SQLite)** |

---

## 🗺 Roadmap

*   **Phase 1: Foundation** ✅
    *   Core Rust Architecture
    *   Cloud Hypervisor / HVF Adapters
    *   SQLite State Management
*   **Phase 2: Networking & Compose** (In Progress 🟡)
    *   `docker-compose` parsing
    *   Native Connectivity (Ping)
    *   Port Forwarding
*   **Phase 3: The Builder** ✅
    *   DAG Solver
    *   Hermetic VM Builds
    *   Content-Addressable Caching
*   **Phase 4: Hardware Acceleration** (Next Up)
    *   VFIO / GPU Passthrough
    *   Apple Metal Passthrough (via `libkrun`)

---

## 🤝 Contributing

HYPR is built in **Rust** and **C**. We value clean architecture, zero compiler warnings, and observability.

1.  Clone the repo: `git clone https://github.com/hyprhq/hypr`
2.  Run tests: `cargo test`
3.  Check the [Contributing Guide](docs/CONTRIBUTING.md).

---

## 📄 License

**Business Source License 1.1**
*   Free for personal, educational, and internal business use.
*   Commercial resale/hosting requires a license.
*   Converts to **Apache 2.0** automatically on **October 4, 2029**.

*Designed for stealth, speed, and scale.*

**© 2025 HYPR PTE. LTD.**
