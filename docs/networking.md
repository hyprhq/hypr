# Networking

HYPR provides Docker-compatible networking for VMs with support for custom networks, DNS resolution, and port forwarding.

## Overview

Each VM is assigned an IP address on a virtual network. VMs can communicate with each other by IP or by name (via built-in DNS). Port forwarding exposes VM services to the host.

## Default Network

HYPR creates a default network automatically using `gvproxy` (gVisor TAP-vsock). This provides a unified networking experience across Linux and macOS without requiring root privileges or complex host network configuration.

| Property | Value |
|----------|-------|
| Subnet | `192.168.127.0/24` |
| Gateway | `192.168.127.1` |
| DNS | `192.168.127.1` (gvproxy built-in) |
| DHCP Range | `192.168.127.2` - `192.168.127.254` |

Both Linux and macOS use this identical configuration.

## Creating Networks

Create a custom network:

```sh
hypr network create mynet
```

*Note: Currently, HYPR uses a single unified network backend. Custom subnets are supported but map to isolated gvproxy instances.*

## Listing Networks

```sh
hypr network ls
```

## Inspecting Networks

```sh
hypr network inspect bridge
```

Output:
```json
[
    {
        "Name": "bridge",
        "Id": "000000000000",
        "Driver": "gvproxy",
        "IPAM": {
            "Config": [
                {
                    "Subnet": "192.168.127.0/24",
                    "Gateway": "192.168.127.1"
                }
            ]
        }
    }
]
```

## Removing Networks

```sh
hypr network rm mynet
```

## DNS Resolution

HYPR VMs automatically use the host's DNS configuration via the `gvproxy` gateway.

### VM Name Resolution

VMs are accessible by their assigned IP addresses. Internal name resolution (e.g., `ping myvm`) is handled by the `gvproxy` DNS server.

### DNS Setup

Each VM is configured with `/etc/resolv.conf` pointing to the gateway:

```
nameserver 192.168.127.1
```

If the gateway cannot resolve a query, it falls back to the host's system resolvers or `8.8.8.8`.

## Port Forwarding

Expose VM ports to the host:

```sh
hypr run nginx -p 8080:80
```

This binds port 8080 on `localhost` (127.0.0.1) and forwards traffic to port 80 inside the VM.

## Network Architecture

HYPR uses a **User-Mode Networking** architecture powered by `gvproxy`.

```
Host (localhost) <---> gvproxy (192.168.127.1) <---> VM (192.168.127.2+)
```

### Components

1.  **gvproxy**: A Go binary (based on gVisor) that acts as the network gateway, DHCP server, and DNS forwarder. It runs as a user process on the host.
2.  **Virtio-vsock / Unix Sockets**: Communication channel between the host `gvproxy` process and the Guest VM.
3.  **Kestrel Agent**: Runs inside the VM to configure the network interface with the IP assigned by `gvproxy`.

### Advantages

*   **No Root Required**: Unlike TAP/Bridge networking, this doesn't require `sudo` to set up host interfaces.
*   **Isolation**: Network traffic is isolated from the host's real network stack.
*   **Consistency**: Identical behavior on macOS and Linux.
*   **VPN Compatibility**: Works well with corporate VPNs (Tailscale, Cisco AnyConnect) because it doesn't conflict with host routing tables.

## Troubleshooting
 
### VM Cannot Reach Internet
 
**All Platforms:**
 
1. Check if `gvproxy` is running:
   ```sh
   ps aux | grep gvproxy
   ```
 
2. Check `hypr` daemon logs for network errors:
   ```sh
   tail -f ~/.hypr/logs/hyprd.log
   ```
 
3. Verify VM is connected to gateway:
   ```sh
   hypr exec myvm -- ping -c 1 192.168.127.1
   ```
 
4. Check VM DNS resolution:
   ```sh
   hypr exec myvm -- nslookup google.com
   ```
 
### Port Forwarding Not Working
 
1. Verify port mapping:
   ```sh
   hypr ps | grep <vm-name>
   ```
 
2. Check service is listening in VM:
   ```sh
   hypr exec myvm -- ss -tlnp
   ```
 
3. Check `gvproxy` port bindings on host:
   ```sh
   netstat -an | grep <host-port>
   ```
 
### VMs Cannot Communicate
 
1. Verify both VMs are running.
2. Check IP addresses:
   ```sh
   hypr ps
   ```
3. Test connectivity:
   ```sh
   hypr exec vm1 -- ping <vm2-ip>
   ```

## Advanced Configuration

### Custom Bridge Name

Networks create bridge devices with names like `vbr0`, `vbr1`, etc. The bridge name is shown in network inspect output.

### IP Range Exhaustion

The default Linux subnet (`10.88.0.0/16`) provides ~65,000 addresses. macOS (`192.168.64.0/24`) provides ~250 addresses.

Check current allocations:
```sh
hypr network inspect bridge
```

### Multiple Networks

A VM can connect to multiple networks in compose:

```yaml
services:
  proxy:
    image: nginx:latest
    networks:
      - public
      - internal

networks:
  public:
  internal:
    internal: true  # No external access
```
