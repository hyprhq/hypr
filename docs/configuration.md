# Configuration

HYPR is configured through environment variables and file paths.

## Environment Variables

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `HYPR_DATA_DIR` | `/var/lib/hypr` | Base directory for persistent data |
| `HYPR_RUNTIME_DIR` | `/run/hypr` (Linux) or `/tmp/hypr` (macOS) | Runtime files (sockets, PIDs) |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level filter |

**Examples:**
```sh
# Info level (default)
RUST_LOG=info hyprd

# Debug for all components
RUST_LOG=debug hyprd

# Debug for specific crate
RUST_LOG=hypr_core=debug hyprd

# Multiple filters
RUST_LOG=hypr_daemon=debug,hypr_core::builder=trace hyprd

# Quiet (errors only)
RUST_LOG=error hyprd
```

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `HYPR_OTLP_ENABLED` | unset | Enable OpenTelemetry tracing |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP collector endpoint |

**Enable tracing:**
```sh
HYPR_OTLP_ENABLED=1 hyprd
```

**With custom endpoint:**
```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317 hyprd
```

## File Paths

### Data Directory

Default: `/var/lib/hypr`

Override with `HYPR_DATA_DIR`:
```sh
export HYPR_DATA_DIR=/opt/hypr/data
```

**Contents:**

| Path | Description |
|------|-------------|
| `hypr.db` | SQLite database (VMs, images, stacks, networks, volumes) |
| `images/` | Built and pulled images |
| `volumes/` | Named volumes |
| `logs/` | VM log files |
| `cache/` | Build cache layers |
| `vmlinux` | Linux kernel binary |

### Runtime Directory

Default: `/run/hypr` (Linux) or `/tmp/hypr` (macOS)

Override with `HYPR_RUNTIME_DIR`:
```sh
export HYPR_RUNTIME_DIR=/var/run/hypr
```

**Contents:**

| Path | Description |
|------|-------------|
| `hypr.sock` | gRPC Unix socket |
| `hyprd.pid` | Daemon PID file |
| `<vm-id>.vsock` | Per-VM vsock sockets |
| `kestrel-initramfs.cpio` | Extracted guest initramfs |

## Service Ports

All HYPR services use ports in the 41000-41999 range.

| Port | Service | Protocol |
|------|---------|----------|
| 41000 | gRPC API | gRPC over Unix socket |
| 41001 | REST gateway | HTTP |
| 41002 | Prometheus metrics | HTTP |
| 41003 | DNS server | DNS/UDP |
| 41010 | Build HTTP proxy | HTTP |
| 41011 | Build agent | vsock |

## VM Resources

### Default Resources

When not specified, VMs use these defaults:

| Resource | Default |
|----------|---------|
| CPUs | 2 |
| Memory | 512 MB |
| Balloon | Enabled |

### Override at Runtime

```sh
hypr run nginx -c 4 -m 2048
```

### Override in Compose

```yaml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 2G
```

## Network Configuration

### Linux

| Setting | Value |
|---------|-------|
| Bridge | `vbr0` |
| CIDR | `10.88.0.0/16` |
| Gateway | `10.88.0.1` |
| DNS | `10.88.0.1` |

### macOS

| Setting | Value |
|---------|-------|
| Network | vmnet (shared mode) |
| CIDR | `192.168.64.0/24` |
| Gateway | `192.168.64.1` |
| DNS | `192.168.64.1` |

### Custom Networks

Create networks with custom subnets:
```sh
hypr network create mynet --subnet 10.89.0.0/16 --gateway 10.89.0.1
```

## Volume Configuration

### Default Storage

Volumes are stored in `/var/lib/hypr/volumes/`:
- Standalone volumes: `/var/lib/hypr/volumes/local/<name>`
- Stack volumes: `/var/lib/hypr/volumes/<stack>/<name>`

### Volume Driver

Currently only the `local` driver is supported, which stores data on the host filesystem.

## Kernel Configuration

HYPR downloads a custom-built Linux kernel on first use.

**Kernel version:** 6.12

**Features enabled:**
- SquashFS with compression
- OverlayFS
- virtio drivers (blk, net, vsock, fs)
- Container namespaces
- Memory ballooning

**Download source:**
```
https://github.com/hyprhq/hypr/releases/download/kernel-6.12-hypr/
```

**Architecture-specific files:**
- x86_64: `vmlinux-x86_64`
- ARM64: `Image-aarch64`

## Systemd Configuration (Linux)

Service file location: `/etc/systemd/system/hyprd.service`

```ini
[Unit]
Description=HYPR Daemon
Documentation=https://github.com/hyprhq/hypr
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hyprd
Restart=always
RestartSec=5
Environment=RUST_LOG=info
Environment=HOME=/var/lib/hypr
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

**Commands:**
```sh
sudo systemctl start hyprd
sudo systemctl stop hyprd
sudo systemctl restart hyprd
sudo systemctl status hyprd
journalctl -u hyprd -f
```

## LaunchDaemon Configuration (macOS)

Plist location: `/Library/LaunchDaemons/ai.hypr.hyprd.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.hypr.hyprd</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/hyprd</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/hypr/hyprd.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/hypr/hyprd.log</string>
    <key>WorkingDirectory</key>
    <string>/var/lib/hypr</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
```

**Commands:**
```sh
sudo launchctl load /Library/LaunchDaemons/ai.hypr.hyprd.plist
sudo launchctl unload /Library/LaunchDaemons/ai.hypr.hyprd.plist
sudo launchctl kickstart -k system/ai.hypr.hyprd
tail -f /var/log/hypr/hyprd.log
```

## DNS Resolution

HYPR runs a DNS server for `.hypr` domain resolution on port 41003.

**Linux setup (systemd-resolved):**
```sh
# Automatic if systemd-resolved is available
# Manual: resolvectl domain vbr0 ~hypr
```

**macOS setup:**
```sh
# Automatic via /etc/resolver/hypr
cat /etc/resolver/hypr
# nameserver 192.168.64.1
```

**Usage:**
```sh
# Access VM by name
curl http://myvm.hypr/
ping myvm.hypr
```

## Database Configuration

HYPR uses SQLite for state persistence.

**Location:** `/var/lib/hypr/hypr.db`

**Tables:**
- `vms` - VM records
- `images` - Image metadata
- `stacks` - Compose stacks
- `networks` - Network definitions
- `volumes` - Volume metadata

**Migrations:** Applied automatically on daemon startup

**Backup:**
```sh
# Stop daemon first
sudo systemctl stop hyprd
cp /var/lib/hypr/hypr.db /backup/hypr.db.bak
sudo systemctl start hyprd
```
