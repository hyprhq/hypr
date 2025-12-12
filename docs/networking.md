# Networking

HYPR provides Docker-compatible networking for VMs with support for custom networks, DNS resolution, and port forwarding.

## Overview

Each VM is assigned an IP address on a virtual network. VMs can communicate with each other by IP or by name (via built-in DNS). Port forwarding exposes VM services to the host.

## Default Network

HYPR creates a default network automatically. Platform-specific configuration:

| Platform | Subnet | Gateway | DNS |
|----------|--------|---------|-----|
| Linux | `10.88.0.0/16` | `10.88.0.1` | `10.88.0.1` |
| macOS | `192.168.64.0/24` | `192.168.64.1` | `192.168.64.1` |

Linux uses a custom subnet to avoid conflicts with Docker (`172.17.0.0/16`) and Tailscale (`100.64.0.0/10`).

macOS uses the vmnet framework's default range.

## Creating Networks

Create a custom network:

```sh
hypr network create mynet
```

With custom subnet:

```sh
hypr network create mynet --subnet 10.89.0.0/16
```

With custom subnet and gateway:

```sh
hypr network create mynet --subnet 10.89.0.0/16 --gateway 10.89.0.1
```

## Listing Networks

```sh
hypr network ls
```

Output:
```
NETWORK ID      NAME       DRIVER     SCOPE
abc123def456    bridge     bridge     local
def456ghi789    mynet      bridge     local
```

## Inspecting Networks

```sh
hypr network inspect mynet
```

Output:
```json
[
    {
        "Name": "mynet",
        "Id": "def456ghi789",
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

## Removing Networks

```sh
hypr network rm mynet
```

Force remove (even if VMs are attached):

```sh
hypr network rm mynet --force
```

Remove all unused networks:

```sh
hypr network prune
```

## Networks in Compose

Define networks in your compose file:

```yaml
version: "3.8"

services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    networks:
      - frontend

  api:
    image: myapi:latest
    networks:
      - frontend
      - backend

  db:
    image: postgres:16
    networks:
      - backend

networks:
  frontend:
  backend:
```

Services on the same network can communicate by service name:

```sh
# From the api service:
curl http://db:5432  # Connects to postgres
curl http://web:80   # Connects to nginx
```

### Custom Subnets in Compose

```yaml
networks:
  internal:
    driver: bridge
    ipam:
      config:
        - subnet: 10.90.0.0/16
          gateway: 10.90.0.1
```

## DNS Resolution

HYPR runs a DNS server for `.hypr` domain resolution on port 41003.

### VM Name Resolution

VMs are accessible by name with the `.hypr` suffix:

```sh
# If you have a VM named "myvm"
ping myvm.hypr
curl http://myvm.hypr:8080
```

### Service Name Resolution

Within compose stacks, services resolve by name:

```sh
# From within a VM in the stack
ping db        # Resolves to the db service IP
curl api:3000  # Connects to the api service
```

### Linux DNS Setup

On Linux with systemd-resolved, HYPR configures DNS automatically:

```sh
# Verify configuration
resolvectl status vbr0
```

Manual configuration:
```sh
resolvectl domain vbr0 ~hypr
resolvectl dns vbr0 10.88.0.1
```

### macOS DNS Setup

On macOS, HYPR creates a resolver file:

```sh
cat /etc/resolver/hypr
# nameserver 192.168.64.1
```

## Port Forwarding

Expose VM ports to the host:

```sh
hypr run nginx -p 8080:80
```

Multiple ports:

```sh
hypr run nginx -p 8080:80 -p 8443:443
```

In compose:

```yaml
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"    # HOST:CONTAINER
      - "443:443"
```

## Network Architecture

### Linux

```
Host Network
    |
    +-- vbr0 (bridge, 10.88.0.1/16)
        |
        +-- tap0 (VM 1: 10.88.0.2)
        |
        +-- tap1 (VM 2: 10.88.0.3)
        |
        +-- tap2 (VM 3: 10.88.0.4)
```

Components:
- **vbr0**: Linux bridge device
- **tapN**: TAP device per VM
- **IPAM**: IP address allocation (SQLite-backed)
- **DNS**: Built-in DNS server on the bridge IP

### macOS

```
Host Network
    |
    +-- vmnet (192.168.64.1/24)
        |
        +-- VM 1 (192.168.64.2)
        |
        +-- VM 2 (192.168.64.3)
```

Components:
- **vmnet**: Apple's Virtualization framework network
- **DHCP**: IP allocation via vmnet
- **DNS**: Built-in DNS server

## Troubleshooting

### VM Cannot Reach Internet

**Linux:**

1. Check IP forwarding:
   ```sh
   cat /proc/sys/net/ipv4/ip_forward
   # Should be 1
   ```

   Enable:
   ```sh
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

2. Check NAT:
   ```sh
   sudo iptables -t nat -L POSTROUTING -n
   ```

3. Check bridge exists:
   ```sh
   ip link show vbr0
   ```

**macOS:**

1. Check vmnet service is running
2. Verify libkrun permissions in Security & Privacy

### DNS Not Resolving

1. Check DNS server is running:
   ```sh
   nc -vz 10.88.0.1 41003  # Linux
   nc -vz 192.168.64.1 41003  # macOS
   ```

2. Check /etc/resolv.conf in VM:
   ```sh
   hypr exec myvm -- cat /etc/resolv.conf
   ```

3. Test with explicit nameserver:
   ```sh
   hypr exec myvm -- nslookup google.com 8.8.8.8
   ```

### VMs Cannot Communicate

1. Verify both VMs are on the same network
2. Check IP addresses:
   ```sh
   hypr ps  # Shows IP column
   ```

3. Test connectivity:
   ```sh
   hypr exec vm1 -- ping <vm2-ip>
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

3. Check host firewall:
   ```sh
   # Linux
   sudo iptables -L INPUT -n | grep <port>

   # macOS
   sudo pfctl -sr | grep <port>
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
