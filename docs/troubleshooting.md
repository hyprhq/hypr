# Troubleshooting

Solutions for common issues with HYPR.

## Daemon Issues

### Daemon Not Running

**Symptom:**
```
Error: Failed to connect to daemon
```

**Linux:**
```sh
# Check status
sudo systemctl status hyprd

# Start daemon
sudo systemctl start hyprd

# View logs
journalctl -u hyprd -f
```

**macOS:**
```sh
# Check status
sudo launchctl list | grep hypr

# Load daemon
sudo launchctl load /Library/LaunchDaemons/ai.hypr.hyprd.plist

# View logs
tail -f /var/log/hypr/hyprd.log
```

### Another Instance Running

**Symptom:**
```
Another hyprd instance is already running (PID 12345)
```

**Solution:**
```sh
# Kill existing process
sudo kill 12345

# Remove stale PID file
sudo rm /run/hypr/hyprd.pid  # Linux
sudo rm /tmp/hypr/hyprd.pid  # macOS

# Start daemon
sudo systemctl start hyprd   # Linux
sudo launchctl load /Library/LaunchDaemons/ai.hypr.hyprd.plist  # macOS
```

### Permission Denied

**Symptom:**
```
Error: Permission denied: /var/lib/hypr
```

**Solution:**

The daemon must run as root. Ensure proper service configuration:

```sh
# Linux
sudo systemctl restart hyprd

# macOS - ensure running as root
sudo launchctl kickstart -k system/ai.hypr.hyprd
```

## VM Issues

### VM Fails to Start

**Symptom:**
```
Error: Failed to start VM: hypervisor error
```

**Possible causes:**

1. **Missing kernel:**
   ```sh
   ls /var/lib/hypr/vmlinux
   ```
   If missing, delete and let HYPR re-download:
   ```sh
   sudo rm /var/lib/hypr/vmlinux
   hypr run nginx  # triggers download
   ```

2. **KVM not available (Linux):**
   ```sh
   ls /dev/kvm
   ```
   If missing, enable virtualization in BIOS or install KVM:
   ```sh
   sudo apt install qemu-kvm  # Debian/Ubuntu
   ```

3. **Hypervisor not found (macOS):**
   ```sh
   which krunkit   # ARM64
   which vfkit     # Intel
   ```
   Install if missing:
   ```sh
   brew tap slp/krunkit && brew install krunkit  # ARM64
   brew install vfkit                            # Intel
   ```

### VM Boot Timeout

**Symptom:**
```
Error: VM health check timeout
```

**Possible causes:**

1. **Image entrypoint fails immediately:**
   ```sh
   hypr logs <vm-id>
   ```
   Check for application errors.

2. **Resource constraints:**
   Increase memory:
   ```sh
   hypr run <image> -m 1024
   ```

3. **Slow disk I/O:**
   Wait longer or check disk health.

### Cannot Connect to VM Port

**Symptom:** Port mapping configured but connection refused.

**Checks:**

1. **VM running:**
   ```sh
   hypr ps
   ```

2. **Port mapping correct:**
   ```sh
   hypr ps | grep <vm-id>
   # Check PORTS column
   ```

3. **Service running in VM:**
   ```sh
   hypr exec <vm-id> -- ss -tlnp
   ```

4. **Firewall blocking:**
   ```sh
   # Linux
   sudo iptables -L -n | grep <port>

   # macOS
   sudo pfctl -sr | grep <port>
   ```

## Image Issues

### Image Pull Failed

**Symptom:**
```
Error: Failed to pull image: connection refused
```

**Checks:**

1. **Network connectivity:**
   ```sh
   curl -I https://registry-1.docker.io/v2/
   ```

2. **DNS resolution:**
   ```sh
   nslookup registry-1.docker.io
   ```

3. **Proxy settings:**
   If behind corporate proxy, set `HTTP_PROXY` and `HTTPS_PROXY`.

### Image Not Found

**Symptom:**
```
Error: Image not found: myimage:latest
```

**Checks:**

1. **Correct image name:**
   ```sh
   # Docker Hub library images
   hypr pull nginx           # correct
   hypr pull library/nginx   # also correct

   # User images
   hypr pull user/repo:tag

   # Other registries
   hypr pull ghcr.io/org/repo:tag
   ```

2. **Tag exists:**
   Check registry for available tags.

3. **Architecture match:**
   Some images only have x86_64 or ARM64 variants.

### Build Failed

**Symptom:**
```
Error: Build failed: instruction failed
```

**Checks:**

1. **View build output:**
   Build errors are printed to stdout.

2. **Missing dependencies:**
   Add required packages in Dockerfile:
   ```dockerfile
   RUN apt-get update && apt-get install -y <package>
   ```

3. **Network in build:**
   Build VMs have no network access. All downloads must happen in the base image or use multi-stage builds.

4. **Check Dockerfile syntax:**
   ```sh
   # Validate with Docker (if available)
   docker build --check .
   ```

## Network Issues

### No Network in VM

**Symptom:** VM cannot reach external networks.

**Linux checks:**

1. **Bridge exists:**
   ```sh
   ip link show vbr0
   ```

2. **TAP attached:**
   ```sh
   ip link show master vbr0
   ```

3. **IP forwarding enabled:**
   ```sh
   cat /proc/sys/net/ipv4/ip_forward
   # Should be 1
   ```
   Enable:
   ```sh
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

4. **NAT configured:**
   ```sh
   sudo iptables -t nat -L POSTROUTING
   ```

**macOS checks:**

1. **vmnet service running:**
   Check System Preferences > Sharing > Internet Sharing.

2. **krunkit/vfkit permissions:**
   May need to allow in Security & Privacy settings.

### DNS Not Resolving

**Symptom:** VM cannot resolve hostnames.

**Inside VM:**
```sh
hypr exec <vm-id> -- cat /etc/resolv.conf
hypr exec <vm-id> -- ping 8.8.8.8     # Check IP connectivity
hypr exec <vm-id> -- nslookup google.com
```

**Fix:**
```sh
hypr exec <vm-id> -- sh -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
```

## GPU Issues

### GPU Not Detected (Linux)

**Symptom:**
```sh
hypr gpu list
# No GPUs detected
```

**Checks:**

1. **GPU present:**
   ```sh
   lspci | grep -i vga
   lspci | grep -i nvidia
   ```

2. **IOMMU enabled:**
   ```sh
   dmesg | grep -i iommu
   ```
   Add to kernel cmdline:
   - Intel: `intel_iommu=on`
   - AMD: `amd_iommu=on`

3. **VFIO modules:**
   ```sh
   lsmod | grep vfio
   ```
   Load:
   ```sh
   sudo modprobe vfio-pci
   ```

### GPU Passthrough Failed

**Symptom:**
```
Error: GPU not bound to vfio-pci driver
```

**Solution:**

1. **Unbind from current driver:**
   ```sh
   echo "0000:01:00.0" | sudo tee /sys/bus/pci/drivers/nvidia/unbind
   ```

2. **Bind to vfio-pci:**
   ```sh
   echo "10de 2684" | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id
   echo "0000:01:00.0" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
   ```

### Metal Not Available (macOS)

**Symptom:** GPU option does nothing on Apple Silicon.

**Checks:**

1. **macOS version:**
   Requires macOS 14 (Sonoma) or later.

2. **krunkit version:**
   ```sh
   krunkit --version
   ```
   Update: `brew upgrade krunkit`

## Disk Space Issues

### No Space Left

**Symptom:**
```
Error: No space left on device
```

**Solution:**

1. **Check usage:**
   ```sh
   hypr system df
   ```

2. **Prune unused resources:**
   ```sh
   hypr system prune --all
   ```

3. **Remove specific images:**
   ```sh
   hypr images
   # Note image ID
   # Delete via API or manually remove from /var/lib/hypr/images/
   ```

## Debug Mode

Enable debug logging for detailed information:

```sh
# Full debug
RUST_LOG=debug hyprd

# Component-specific
RUST_LOG=hypr_core::adapters=trace hyprd
RUST_LOG=hypr_daemon::network_manager=debug hyprd
```

## Getting Help

1. Check logs: `journalctl -u hyprd -f` (Linux) or `tail -f /var/log/hypr/hyprd.log` (macOS)
2. Enable debug logging: `RUST_LOG=debug`
3. Report issues: https://github.com/hyprhq/hypr/issues
