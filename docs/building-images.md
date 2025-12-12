# Building Images

HYPR builds images from Dockerfiles using an isolated build process.

## Basic Build

```sh
hypr build -t myapp:latest .
```

This parses the Dockerfile, executes each instruction, and produces a squashfs image.

## Build Process

1. **Parse Dockerfile** - Validate syntax, extract stages and instructions
2. **Resolve Base Image** - Pull base image from registry if not cached
3. **Execute Instructions** - Run each instruction in an isolated build VM
4. **Create Layers** - Cache each layer for incremental builds
5. **Generate Squashfs** - Compress final rootfs to squashfs format
6. **Store Manifest** - Save image metadata (entrypoint, env, ports, etc.)

## Supported Instructions

### FROM

Set base image for the build stage.

```dockerfile
FROM alpine:3.19
FROM golang:1.21 AS builder
FROM scratch
FROM --platform=linux/amd64 ubuntu:22.04
```

### RUN

Execute commands during build.

```dockerfile
# Shell form
RUN apt-get update && apt-get install -y nginx

# Exec form
RUN ["apt-get", "update"]
```

### COPY

Copy files from build context or previous stage.

```dockerfile
# From build context
COPY src/ /app/src/
COPY package.json package-lock.json ./

# From previous stage
COPY --from=builder /app/binary /usr/local/bin/

# With ownership
COPY --chown=nginx:nginx config/ /etc/nginx/
```

### ADD

Copy files with automatic extraction.

```dockerfile
ADD archive.tar.gz /app/
ADD https://example.com/file.txt /app/
```

### ENV

Set environment variables.

```dockerfile
# Single variable
ENV NODE_ENV production

# Multiple variables
ENV NODE_ENV=production DEBUG=false PORT=3000
```

### ARG

Define build-time variables.

```dockerfile
ARG VERSION=1.0
ARG BUILD_DATE

FROM alpine:3.19
RUN echo "Building version $VERSION"
```

Pass values at build time:
```sh
hypr build --build-arg VERSION=2.0 -t myapp .
```

### WORKDIR

Set working directory.

```dockerfile
WORKDIR /app
RUN pwd  # outputs /app
```

### USER

Set the user for subsequent instructions and runtime.

```dockerfile
USER nginx
USER 1000:1000
```

### EXPOSE

Document exposed ports.

```dockerfile
EXPOSE 80
EXPOSE 443/tcp
EXPOSE 53/udp
```

### ENTRYPOINT

Set the executable.

```dockerfile
# Exec form (recommended)
ENTRYPOINT ["nginx", "-g", "daemon off;"]

# Shell form
ENTRYPOINT nginx -g "daemon off;"
```

### CMD

Set default arguments.

```dockerfile
# Exec form
CMD ["--config", "/etc/nginx/nginx.conf"]

# Combined with ENTRYPOINT
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
```

### VOLUME

Declare mount points.

```dockerfile
VOLUME /data
VOLUME ["/data", "/logs"]
```

### LABEL

Add metadata.

```dockerfile
LABEL version="1.0"
LABEL maintainer="team@example.com"
```

### HEALTHCHECK

Define health check command.

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -f http://localhost/ || exit 1
```

### SHELL

Set default shell.

```dockerfile
SHELL ["/bin/bash", "-c"]
RUN echo $SHELL
```

### STOPSIGNAL

Set stop signal.

```dockerfile
STOPSIGNAL SIGTERM
```

## Multi-Stage Builds

Use multiple FROM instructions to create smaller final images.

```dockerfile
# Build stage
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Runtime stage
FROM alpine:3.19
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

Build specific stage:
```sh
hypr build --target builder -t myapp:builder .
```

## Build Arguments

Define with `ARG` in Dockerfile:

```dockerfile
ARG GO_VERSION=1.21
FROM golang:${GO_VERSION}
```

Pass at build time:
```sh
hypr build --build-arg GO_VERSION=1.22 -t myapp .
```

## Build Cache

HYPR caches layers based on instruction content. Cache is invalidated when:
- Dockerfile instruction changes
- Files copied by COPY/ADD change
- Base image changes
- Build argument values change

Disable cache:
```sh
hypr build --no-cache -t myapp .
```

Clear all cached layers:
```sh
hypr system prune
```

## Image Storage

Built images are stored in `/var/lib/hypr/images/` as squashfs files with accompanying manifest JSON.

List images:
```sh
hypr images
```

## Example Dockerfiles

### Node.js Application

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

### Go Application

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/server /usr/local/bin/
EXPOSE 8080
CMD ["server"]
```

### Python Application

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0"]
```

## Managing Images

List local images:
```sh
hypr images
```

Remove an image:
```sh
hypr rmi myapp:latest
```

Force remove:
```sh
hypr rmi -f myapp:latest
```

Inspect image:
```sh
hypr image inspect myapp:latest
```

Remove unused images:
```sh
hypr image prune        # Dangling only
hypr image prune --all  # All unused
```

## Compose Builds

Build images as part of stack deployment:

```yaml
services:
  api:
    build:
      context: ./api
      dockerfile: Dockerfile.prod
      args:
        VERSION: "1.0"
      target: production
```

Deploy with build:
```sh
hypr compose up --build
```

## Limitations

### No Network During Build

Build VMs have no network access for security. All dependencies must be:
- Included in the base image
- Added to the build context
- Downloaded in a previous multi-stage build

### Platform-Specific

Images are built for the current platform (x86_64 or ARM64). Cross-platform builds are not supported.

### Not BuildKit

HYPR uses its own build implementation. Some advanced BuildKit features are not supported:
- Secret mounts (`--mount=type=secret`)
- SSH mounts (`--mount=type=ssh`)
- Cache mounts (`--mount=type=cache`)
- Git context URLs

## Best Practices

1. **Use multi-stage builds** to minimize image size
2. **Order instructions** by change frequency (stable first)
3. **Combine RUN commands** to reduce layers
4. **Use `.dockerignore`** to exclude unnecessary files
5. **Set USER** to avoid running as root
6. **Define HEALTHCHECK** for container health monitoring
7. **Use specific tags** instead of `latest` for reproducibility

## Troubleshooting

### Build Fails

1. Check Dockerfile syntax
2. View build output for error messages
3. Verify base image is available
4. Ensure context files exist

### Out of Space

```sh
hypr system df
hypr system prune
```

### Cache Not Working

Cache is invalidated when instruction or context files change. Use `--no-cache` to force rebuild.
