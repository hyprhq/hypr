# Getting Started

This guide covers installation and running your first HYPR VM.

## Installation

### One-Line Install

```sh
curl -fsSL https://get.hypr.tech | sh
```

This installer:
1. Detects your platform (Linux or macOS) and architecture
2. Downloads `hypr` (CLI) and `hyprd` (daemon) binaries
3. Installs platform-specific dependencies
4. Configures the daemon as a system service

### Manual Installation

Download binaries from the [releases page](https://github.com/hyprhq/hypr/releases):

```sh
# Linux x86_64
curl -fsSL https://github.com/hyprhq/hypr/releases/latest/download/hypr-linux-amd64 -o hypr
curl -fsSL https://github.com/hyprhq/hypr/releases/latest/download/hyprd-linux-amd64 -o hyprd

# Linux ARM64
curl -fsSL https://github.com/hyprhq/hypr/releases/latest/download/hypr-linux-arm64 -o hypr
curl -fsSL https://github.com/hyprhq/hypr/releases/latest/download/hyprd-linux-arm64 -o hyprd

# macOS ARM64 (Apple Silicon)
curl -fsSL https://github.com/hyprhq/hypr/releases/latest/download/hypr-darwin-arm64 -o hypr
curl -fsSL https://github.com/hyprhq/hypr/releases/latest/download/hyprd-darwin-arm64 -o hyprd

# macOS Intel
curl -fsSL https://github.com/hyprhq/hypr/releases/latest/download/hypr-darwin-amd64 -o hypr
curl -fsSL https://github.com/hyprhq/hypr/releases/latest/download/hyprd-darwin-amd64 -o hyprd
```

Make executable and move to PATH:
```sh
chmod +x hypr hyprd
sudo mv hypr hyprd /usr/local/bin/
```

## Requirements

### Linux

- Kernel 5.10+ with KVM enabled
- `squashfs-tools` for image building:
  ```sh
  # Debian/Ubuntu
  sudo apt install squashfs-tools

  # Fedora
  sudo dnf install squashfs-tools

  # Arch
  sudo pacman -S squashfs-tools
  ```
- `virtiofsd` for shared filesystem support (installed automatically)

### macOS

- macOS 14 (Sonoma) or later for full GPU support
- Homebrew for dependency installation
- Apple Silicon: `krunkit` (installed automatically via `brew tap slp/krunkit && brew install krunkit`)
- Intel: `vfkit` (installed automatically via `brew install vfkit`)
- `squashfs` for image building: `brew install squashfs`

## Starting the Daemon

The installer configures the daemon to start automatically. To manage it manually:

**Linux (systemd):**
```sh
sudo systemctl start hyprd    # Start
sudo systemctl stop hyprd     # Stop
sudo systemctl status hyprd   # Status
journalctl -u hyprd -f        # Logs
```

**macOS (launchd):**
```sh
sudo launchctl load /Library/LaunchDaemons/ai.hypr.hyprd.plist      # Start
sudo launchctl unload /Library/LaunchDaemons/ai.hypr.hyprd.plist    # Stop
sudo launchctl kickstart -k system/ai.hypr.hyprd                    # Restart
tail -f /var/log/hypr/hyprd.log                                     # Logs
```

## Verify Installation

Check daemon health:
```sh
hypr health
```

Expected output:
```
Status: healthy
Version: 0.1.0
```

## Running Your First VM

Pull and run an nginx container as a VM:

```sh
hypr run nginx -p 8080:80
```

This:
1. Pulls the `nginx:latest` image from Docker Hub
2. Converts it to a squashfs rootfs
3. Boots a microVM with the image
4. Maps host port 8080 to guest port 80

Access nginx at `http://localhost:8080`.

## Listing VMs

```sh
hypr ps
```

Output:
```
ID            NAME           IMAGE          STATUS    IP            PORTS
a1b2c3d4e5f6  eager-fox      nginx:latest   running   10.88.0.2     8080->80/tcp
```

## Stopping and Removing VMs

Stop a running VM:
```sh
hypr stop <vm-id>
```

Remove a stopped VM:
```sh
hypr rm <vm-id>
```

Force remove a running VM:
```sh
hypr rm -f <vm-id>
```

## Next Steps

- [CLI Reference](cli-reference.md) - All available commands
- [Building Images](building-images.md) - Build images from Dockerfiles
- [Compose Stacks](compose.md) - Deploy multi-service applications
