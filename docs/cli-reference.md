# CLI Reference

Complete reference for all `hypr` commands.

## Global Options

The CLI respects the `RUST_LOG` environment variable for log levels:
```sh
RUST_LOG=debug hypr run nginx
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `hypr run` | Run a VM from an image |
| `hypr ps` | List all VMs |
| `hypr start` | Start a stopped VM |
| `hypr stop` | Stop a running VM |
| `hypr rm` | Delete a VM |
| `hypr logs` | Stream logs from a VM |
| `hypr exec` | Execute a command in a VM |
| `hypr build` | Build an image from Dockerfile |
| `hypr images` | List images |
| `hypr pull` | Pull an image from registry |
| `hypr rmi` | Remove an image |
| `hypr image` | Image management subcommands |
| `hypr volume` | Volume management subcommands |
| `hypr network` | Network management subcommands |
| `hypr compose` | Stack management subcommands |
| `hypr gpu` | GPU management subcommands |
| `hypr system` | System maintenance subcommands |
| `hypr health` | Check daemon health |

---

## VM Commands

### hypr run

Run a VM from an image.

```sh
hypr run <image> [options]
```

**Arguments:**
- `<image>` - Image name (e.g., `nginx`, `redis:7`, `ghcr.io/org/repo:tag`)

**Options:**

| Option | Description |
|--------|-------------|
| `-n, --name <name>` | VM name (auto-generated if omitted) |
| `-c, --cpus <n>` | Number of vCPUs (default: 2) |
| `-m, --memory <mb>` | Memory in MB (default: 512) |
| `-p, --port <host:guest>` | Port mapping (can be repeated) |
| `-e, --env <KEY=VALUE>` | Environment variable (can be repeated) |
| `--gpu [address]` | Enable GPU passthrough. Linux: specify PCI address. macOS: no value needed |

**Examples:**
```sh
# Basic run
hypr run nginx

# With port mapping
hypr run nginx -p 8080:80 -p 443:443

# With resources
hypr run redis -c 2 -m 1024

# With environment variables
hypr run postgres -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=myapp

# With GPU (Linux)
hypr run pytorch --gpu 0000:01:00.0

# With GPU (macOS Apple Silicon)
hypr run pytorch --gpu
```

---

### hypr ps

List all VMs.

```sh
hypr ps
```

**Output columns:**
- `ID` - VM identifier (first 12 characters)
- `NAME` - VM name
- `IMAGE` - Source image
- `STATUS` - Current state (creating, running, stopped, failed)
- `IP` - Assigned IP address
- `PORTS` - Port mappings

---

### hypr start

Start a stopped VM.

```sh
hypr start <vm>
```

**Arguments:**
- `<vm>` - VM ID or name

---

### hypr stop

Stop a running VM.

```sh
hypr stop <vm> [options]
```

**Arguments:**
- `<vm>` - VM ID or name

**Options:**

| Option | Description |
|--------|-------------|
| `-t, --timeout <seconds>` | Shutdown timeout (default: 30) |

---

### hypr rm

Delete a VM.

```sh
hypr rm <vm> [options]
```

**Arguments:**
- `<vm>` - VM ID or name

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --force` | Force delete even if running |

---

### hypr logs

Stream logs from a VM.

```sh
hypr logs <vm> [options]
```

**Arguments:**
- `<vm>` - VM ID or name

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --follow` | Follow log output (like `tail -f`) |
| `-n, --tail <lines>` | Number of lines from end (default: all) |

**Examples:**
```sh
# Show all logs
hypr logs myvm

# Follow logs
hypr logs myvm -f

# Last 100 lines
hypr logs myvm --tail 100
```

---

### hypr exec

Execute a command in a running VM.

```sh
hypr exec <vm> [options] [-- command]
```

**Arguments:**
- `<vm>` - VM ID or name
- `<command>` - Command to execute (defaults to `/bin/sh`)

**Options:**

| Option | Description |
|--------|-------------|
| `-i, --interactive` | Interactive mode with TTY |
| `-t, --tty` | Allocate TTY (same as `-i`) |
| `-e, --env <KEY=VALUE>` | Environment variable (can be repeated) |

**Examples:**
```sh
# Interactive shell
hypr exec myvm -it

# Run specific command
hypr exec myvm -- ls -la /app

# With environment
hypr exec myvm -e DEBUG=1 -- ./script.sh
```

---

## Image Commands

### hypr build

Build an image from a Dockerfile.

```sh
hypr build [path] [options]
```

**Arguments:**
- `[path]` - Build context directory (default: `.`)

**Options:**

| Option | Description |
|--------|-------------|
| `-t, --tag <name:tag>` | Image name and tag |
| `-f, --file <path>` | Dockerfile path (default: `Dockerfile`) |
| `--build-arg <KEY=VALUE>` | Build argument (can be repeated) |
| `--target <stage>` | Target stage for multi-stage builds |
| `--no-cache` | Disable build cache |

**Examples:**
```sh
# Build with tag
hypr build -t myapp:latest .

# Specify Dockerfile
hypr build -f Dockerfile.prod -t myapp:prod .

# Multi-stage build
hypr build --target builder -t myapp:builder .

# With build args
hypr build --build-arg VERSION=1.0 -t myapp .
```

---

### hypr images

List local images.

```sh
hypr images
```

**Output columns:**
- `NAME` - Image name
- `TAG` - Image tag
- `ID` - Image identifier
- `SIZE` - Image size
- `CREATED` - Creation time

---

### hypr pull

Pull an image from a registry.

```sh
hypr pull <image>
```

**Arguments:**
- `<image>` - Image reference (e.g., `nginx`, `nginx:1.25`, `ghcr.io/org/repo:tag`)

**Registry support:**
- Docker Hub: `nginx`, `library/nginx`, `user/repo`
- GitHub Container Registry: `ghcr.io/org/repo:tag`
- Google Container Registry: `gcr.io/project/image:tag`
- Quay.io: `quay.io/org/repo:tag`
- Any OCI-compliant registry

---

### hypr rmi

Remove an image.

```sh
hypr rmi <image> [options]
```

**Arguments:**
- `<image>` - Image name or ID

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --force` | Force removal |

---

### hypr image

Image management subcommands.

#### hypr image ls

List images (same as `hypr images`).

```sh
hypr image ls
```

#### hypr image pull

Pull an image (same as `hypr pull`).

```sh
hypr image pull <image>
```

#### hypr image rm

Remove an image (same as `hypr rmi`).

```sh
hypr image rm <image> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --force` | Force removal |

#### hypr image inspect

Display detailed information on an image.

```sh
hypr image inspect <image>
```

**Arguments:**
- `<image>` - Image name or ID

#### hypr image prune

Remove unused images.

```sh
hypr image prune [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-a, --all` | Remove all unused images, not just dangling ones |
| `-f, --force` | Do not prompt for confirmation |

---

## Volume Commands

### hypr volume ls

List all volumes.

```sh
hypr volume ls
```

**Output columns:**
- `DRIVER` - Volume driver (currently `local`)
- `VOLUME NAME` - Volume name

---

### hypr volume create

Create a new volume.

```sh
hypr volume create <name>
```

**Arguments:**
- `<name>` - Volume name

**Example:**
```sh
hypr volume create mydata
```

---

### hypr volume rm

Remove a volume.

```sh
hypr volume rm <name> [options]
```

**Arguments:**
- `<name>` - Volume name

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --force` | Force removal (don't check if in use) |

---

### hypr volume inspect

Display detailed information on a volume.

```sh
hypr volume inspect <name>
```

**Arguments:**
- `<name>` - Volume name

**Output:**
```json
[
    {
        "Name": "mydata",
        "Driver": "local",
        "Mountpoint": "/var/lib/hypr/volumes/local/mydata",
        "Scope": "local",
        "Size": 1048576
    }
]
```

---

### hypr volume prune

Remove all unused volumes.

```sh
hypr volume prune [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --force` | Do not prompt for confirmation |

---

## Network Commands

### hypr network ls

List all networks.

```sh
hypr network ls
```

**Output columns:**
- `NETWORK ID` - Network identifier (first 12 characters)
- `NAME` - Network name
- `DRIVER` - Network driver
- `SCOPE` - Network scope (always `local`)

---

### hypr network create

Create a new network.

```sh
hypr network create <name> [options]
```

**Arguments:**
- `<name>` - Network name

**Options:**

| Option | Description |
|--------|-------------|
| `--subnet <cidr>` | Subnet in CIDR notation (e.g., `10.89.0.0/16`) |
| `--gateway <ip>` | Gateway IP address |
| `-d, --driver <driver>` | Network driver (default: `bridge`) |

**Examples:**
```sh
# Create with auto-allocated subnet
hypr network create mynet

# Create with custom subnet
hypr network create mynet --subnet 10.89.0.0/16

# Create with custom subnet and gateway
hypr network create mynet --subnet 10.89.0.0/16 --gateway 10.89.0.1
```

---

### hypr network rm

Remove a network.

```sh
hypr network rm <name> [options]
```

**Arguments:**
- `<name>` - Network name

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --force` | Force removal (don't check if in use) |

---

### hypr network inspect

Display detailed information on a network.

```sh
hypr network inspect <name>
```

**Arguments:**
- `<name>` - Network name

**Output:**
```json
[
    {
        "Name": "mynet",
        "Id": "abc123def456",
        "Created": "2024-01-15T10:30:00Z",
        "Scope": "local",
        "Driver": "bridge",
        "IPAM": {
            "Driver": "default",
            "Config": [
                {
                    "Subnet": "10.89.0.0/16",
                    "Gateway": "10.89.0.1"
                }
            ]
        },
        "Options": {
            "com.docker.network.bridge.name": "vbr1"
        }
    }
]
```

---

### hypr network prune

Remove all unused networks.

```sh
hypr network prune [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --force` | Do not prompt for confirmation |

---

## Compose Commands

Manage multi-service stacks. See [Compose Stacks](compose.md) for details.

### hypr compose up

Deploy a stack from a compose file.

```sh
hypr compose up [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --file <path>` | Compose file path |
| `-n, --name <name>` | Stack name (defaults to directory name) |
| `-d, --detach` | Run in background |
| `--force-recreate` | Recreate even if exists |
| `--build` | Build images before deploying |

**Compose file search order:**
1. `hypr-compose.yml`, `hypr-compose.yaml`
2. `Hyprfile`, `Hyprfile.yml`, `Hyprfile.yaml`
3. `docker-compose.yml`, `docker-compose.yaml`
4. `compose.yml`, `compose.yaml`

---

### hypr compose down

Destroy a stack.

```sh
hypr compose down <stack-name> [options]
```

**Arguments:**
- `<stack-name>` - Name of the stack to destroy

**Options:**

| Option | Description |
|--------|-------------|
| `-f, --force` | Force destroy without confirmation |

---

### hypr compose ps

List stacks or show stack details.

```sh
hypr compose ps [stack-name]
```

**Arguments:**
- `[stack-name]` - Optional: show details for specific stack

---

### hypr compose logs

Show logs for a service.

```sh
hypr compose logs <service-name>
```

**Arguments:**
- `<service-name>` - Name of the service

---

## GPU Commands

### hypr gpu list

List available GPUs on the system.

```sh
hypr gpu list
```

**Linux output:**
```
PCI ADDRESS     VENDOR     MODEL                          DRIVER       IOMMU      STATUS
0000:01:00.0    Nvidia     NVIDIA GeForce RTX 4090        nvidia       1          available
0000:02:00.0    Amd        AMD Radeon RX 7900 XTX         amdgpu       2          vfio-ready
```

**macOS output:**
```
VENDOR     MODEL                                    MEMORY          STATUS
Apple      Apple M3 Max                             48.0 GB         available
```

See [GPU Passthrough](gpu.md) for details.

---

## System Commands

### hypr system df

Show disk usage information.

```sh
hypr system df
```

**Output:**
```
HYPR Disk Usage

COMPONENT                  SIZE     COUNT
------------------------------------------
Images                   512 MB        5
Build Cache               64 MB       12
Logs                       8 MB        3
Volumes                   256 MB       2
Database                   1 MB        1
------------------------------------------
TOTAL                    841 MB
```

---

### hypr system prune

Remove unused resources.

```sh
hypr system prune [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-a, --all` | Remove all stopped VMs and unused images |
| `-f, --force` | Skip confirmation prompt |
| `--volumes` | Also remove unused volumes |

**Resources cleaned:**
- Dangling images (not referenced by any VM)
- Build cache
- Orphaned log files
- Linux: orphaned TAP devices, orphaned VFIO bindings

---

## Health Check

### hypr health

Check daemon health.

```sh
hypr health
```

**Output:**
```
Status: healthy
Version: 0.1.0
```
