# Volumes

HYPR supports persistent volumes and bind mounts for data that survives VM restarts and removals.

## Volume Types

### Named Volumes

Named volumes are managed by HYPR and stored in `/var/lib/hypr/volumes/`. They persist until explicitly removed.

```sh
# Create a volume
hypr volume create mydata

# Use in a VM (via compose)
# See "Volumes in Compose" section below
```

### Bind Mounts

Bind mounts map a host directory directly into a VM. Changes are immediately visible on both sides.

```yaml
services:
  web:
    image: nginx:latest
    volumes:
      - ./html:/usr/share/nginx/html  # Bind mount
```

## Managing Volumes

### Creating Volumes

```sh
hypr volume create mydata
```

Output:
```
mydata
```

### Listing Volumes

```sh
hypr volume ls
```

Output:
```
DRIVER     VOLUME NAME
local      mydata
local      pgdata
local      mystack_cache
```

### Inspecting Volumes

```sh
hypr volume inspect mydata
```

Output:
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

### Removing Volumes

```sh
hypr volume rm mydata
```

If the volume is in use:
```
Error: Volume 'mydata' is in use by: myvm. Use --force to remove anyway.
```

Force remove:
```sh
hypr volume rm mydata --force
```

### Pruning Unused Volumes

Remove all volumes not attached to any running VM:

```sh
hypr volume prune
```

Output:
```
WARNING! This will remove all local volumes not used by at least one container.
Are you sure you want to continue? [y/N] y

Deleted Volumes:
old-data
temp-cache

Total reclaimed space: 256.5MB
```

Skip confirmation:
```sh
hypr volume prune --force
```

## Volumes in Compose

### Named Volumes

Define volumes in the top-level `volumes` section:

```yaml
version: "3.8"

services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: secret
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

When deployed:
- HYPR creates a volume named `<stack>_pgdata`
- Data persists across `hypr compose down` and `hypr compose up`
- Volume is removed only with `hypr volume rm`

### Bind Mounts

Map host directories into VMs:

```yaml
services:
  web:
    image: nginx:latest
    volumes:
      - ./html:/usr/share/nginx/html        # Relative path
      - /var/log/nginx:/var/log/nginx       # Absolute path
```

### Multiple Volumes

```yaml
services:
  app:
    image: myapp:latest
    volumes:
      - uploads:/app/uploads      # Named volume for user uploads
      - cache:/app/cache          # Named volume for cache
      - ./config:/app/config      # Bind mount for config files

volumes:
  uploads:
  cache:
```

### Read-Only Volumes

Mount a volume as read-only:

```yaml
services:
  app:
    volumes:
      - config:/app/config:ro     # Read-only named volume
      - ./secrets:/run/secrets:ro # Read-only bind mount
```

## Volume Storage

### Storage Location

| Volume Type | Location |
|------------|----------|
| Standalone volumes | `/var/lib/hypr/volumes/local/<name>` |
| Stack volumes | `/var/lib/hypr/volumes/<stack>/<name>` |

### Naming Convention

Stack volumes are prefixed with the stack name:

```
<stack-name>_<volume-name>
```

Example: If stack is `myproject` and volume is `pgdata`, the full name is `myproject_pgdata`.

### Direct Access

You can access volume data directly on the host:

```sh
# View volume contents
ls /var/lib/hypr/volumes/local/mydata

# Backup a volume
tar -czf backup.tar.gz /var/lib/hypr/volumes/local/mydata
```

## Use Cases

### Database Persistence

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: secret
    volumes:
      - pgdata:/var/lib/postgresql/data

  mysql:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: secret
    volumes:
      - mysqldata:/var/lib/mysql

volumes:
  pgdata:
  mysqldata:
```

### Development with Hot Reload

```yaml
services:
  app:
    image: node:20
    command: npm run dev
    volumes:
      - ./src:/app/src           # Hot reload source files
      - node_modules:/app/node_modules  # Persist node_modules

volumes:
  node_modules:
```

### Shared Data Between Services

```yaml
services:
  writer:
    image: mywriter:latest
    volumes:
      - shared:/data

  reader:
    image: myreader:latest
    volumes:
      - shared:/data:ro  # Read-only access

volumes:
  shared:
```

### Log Persistence

```yaml
services:
  app:
    image: myapp:latest
    volumes:
      - logs:/var/log/app
      - /var/log/host-logs:/var/log/app:ro  # Also write to host

volumes:
  logs:
```

## Backup and Restore

### Backup a Volume

```sh
# Stop services using the volume
hypr compose down mystack

# Create backup
tar -czf pgdata-backup.tar.gz -C /var/lib/hypr/volumes/mystack pgdata

# Restart services
hypr compose up -d
```

### Restore a Volume

```sh
# Stop services
hypr compose down mystack

# Remove existing volume
hypr volume rm mystack_pgdata

# Restore from backup
mkdir -p /var/lib/hypr/volumes/mystack
tar -xzf pgdata-backup.tar.gz -C /var/lib/hypr/volumes/mystack

# Restart services
hypr compose up -d
```

### Copy Data Between Volumes

```sh
# Create a temporary VM to copy data
hypr run alpine -n copier

# Mount both volumes and copy
# (Currently requires manual volume mounting in compose)
```

## Troubleshooting

### Volume Not Found

```
Error: Volume 'mydata' not found
```

**Solution:** Check volume name and scope:
```sh
hypr volume ls
```

Stack volumes include the stack name prefix.

### Permission Denied

If a VM cannot write to a volume:

1. Check host directory permissions:
   ```sh
   ls -la /var/lib/hypr/volumes/local/mydata
   ```

2. Ensure the VM user has write access

### Volume In Use

```
Error: Volume 'mydata' is in use by: myvm
```

**Solution:**
1. Stop the VM using the volume:
   ```sh
   hypr stop myvm
   ```

2. Or force remove:
   ```sh
   hypr volume rm mydata --force
   ```

### Disk Space

Check volume sizes:
```sh
hypr system df
```

View specific volume size:
```sh
hypr volume inspect mydata | grep Size
```

Reclaim space:
```sh
hypr volume prune
hypr system prune --volumes
```

## Best Practices

1. **Use named volumes for databases** - Ensures data survives container recreation

2. **Use bind mounts for development** - Enables hot reload and easy editing

3. **Don't store secrets in volumes** - Use environment variables or secret management

4. **Regular backups** - Volumes are not replicated automatically

5. **Prune regularly** - Remove unused volumes to reclaim disk space:
   ```sh
   hypr volume prune
   ```

6. **Name volumes descriptively** - Use names like `postgres-data` not `vol1`
