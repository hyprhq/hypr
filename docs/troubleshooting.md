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

3. **Hypervisor library not found (macOS):**
   Check if libkrun-efi is installed:
   ```sh
   ls /opt/homebrew/opt/libkrun-efi/lib/libkrun-efi.dylib  # ARM64
   ls /usr/local/opt/libkrun-efi/lib/libkrun-efi.dylib     # Intel
   ```
   Install if missing:
   ```sh
   brew tap slp/krunkit && brew install libkrun-efi
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

2. **libkrun permissions:**
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

### VMs Cannot Communicate

**Symptom:** VMs on same network cannot ping each other.

**Checks:**

1. **Same network:**
   Ensure both VMs are on the same network (default or custom).

2. **IP addresses:**
   ```sh
   hypr ps  # Shows IP column
   ```

3. **Test connectivity:**
   ```sh
   hypr exec vm1 -- ping <vm2-ip>
   ```

### Custom Network Not Working

**Symptom:** VMs on custom network cannot communicate.

**Checks:**

1. **Network exists:**
   ```sh
   hypr network ls
   ```

2. **Network configuration:**
   ```sh
   hypr network inspect mynet
   ```

3. **VMs attached:**
   Check compose file has correct `networks:` section.

## Volume Issues

### Volume Not Found

**Symptom:**
```
Error: Volume 'mydata' not found
```

**Checks:**

1. **List volumes:**
   ```sh
   hypr volume ls
   ```

2. **Check name:**
   Stack volumes are prefixed: `<stack>_<volume>`

3. **Check path:**
   ```sh
   ls /var/lib/hypr/volumes/
   ```

### Volume In Use

**Symptom:**
```
Error: Volume 'mydata' is in use by: myvm
```

**Solution:**

1. **Stop the VM:**
   ```sh
   hypr stop myvm
   hypr volume rm mydata
   ```

2. **Or force remove:**
   ```sh
   hypr volume rm mydata --force
   ```

### Permission Denied on Volume

**Symptom:** VM cannot read/write to volume.

**Checks:**

1. **Host permissions:**
   ```sh
   ls -la /var/lib/hypr/volumes/local/mydata
   ```

2. **Change permissions:**
   ```sh
   sudo chmod -R 777 /var/lib/hypr/volumes/local/mydata
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

2. **libkrun-efi version:**
   ```sh
   brew info libkrun-efi
   ```
   Update: `brew upgrade libkrun-efi`

## Compose Issues

### Stack Deploy Failed

**Symptom:**
```
Error: Failed to deploy stack
```

**Checks:**

1. **Compose file syntax:**
   ```sh
   # Validate with Docker (if available)
   docker compose config
   ```

2. **Image availability:**
   ```sh
   hypr pull <image>
   ```

3. **Port conflicts:**
   Check if ports are already in use.

### Service Dependency Timeout

**Symptom:** Service waits forever for dependency.

**Solution:**

Check if dependent service actually starts:
```sh
hypr compose ps mystack
hypr logs <service-vm-id>
```

### Volumes Not Created

**Symptom:** Volume mount fails in compose.

**Checks:**

1. **Volume defined:**
   Ensure volume is in top-level `volumes:` section.

2. **Check volume:**
   ```sh
   hypr volume ls
   ```

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

3. **Prune volumes:**
   ```sh
   hypr volume prune
   ```

4. **Remove specific images:**
   ```sh
   hypr images
   hypr rmi <image>
   ```

## Debug Mode

Enable debug logging for detailed information:

```sh
# Full debug
RUST_LOG=debug hyprd

# Component-specific
RUST_LOG=hypr_core::adapters=trace hyprd
RUST_LOG=hypr_daemon::network_manager=debug hyprd
RUST_LOG=hypr_core::network=debug hyprd
```

## Getting Help

1. Check logs: `journalctl -u hyprd -f` (Linux) or `tail -f /var/log/hypr/hyprd.log` (macOS)
2. Enable debug logging: `RUST_LOG=debug`
3. Check system resources: `hypr system df`
4. Report issues: https://github.com/hyprhq/hypr/issues

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Failed to connect to daemon` | Daemon not running | Start daemon with systemctl/launchctl |
| `Image not found` | Image doesn't exist | Check image name and registry |
| `VM health check timeout` | VM failed to boot | Check logs, increase resources |
| `Port already in use` | Port conflict | Use different port or stop conflicting service |
| `Volume in use` | Volume attached to running VM | Stop VM or use --force |
| `Network in use` | VMs attached to network | Remove VMs first or use --force |
| `No space left` | Disk full | Run `hypr system prune --all --volumes` |
