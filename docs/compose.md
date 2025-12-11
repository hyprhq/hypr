# Compose Stacks

HYPR supports Docker Compose files for deploying multi-service applications.

## Deploying a Stack

```sh
hypr compose up
```

This searches for compose files in the current directory:

1. `hypr-compose.yml`, `hypr-compose.yaml`
2. `Hyprfile`, `Hyprfile.yml`, `Hyprfile.yaml`
3. `docker-compose.yml`, `docker-compose.yaml`
4. `compose.yml`, `compose.yaml`

Specify a file explicitly:
```sh
hypr compose up -f my-compose.yml
```

## Stack Management

### List Stacks

```sh
hypr compose ps
```

### Stack Details

```sh
hypr compose ps mystack
```

### Destroy Stack

```sh
hypr compose down mystack
```

Force without confirmation:
```sh
hypr compose down mystack -f
```

## Compose File Format

HYPR supports Docker Compose v2 and v3 syntax.

### Basic Example

```yaml
version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"

  api:
    image: myapi:latest
    ports:
      - "3000:3000"
    depends_on:
      - db

  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: secret
```

## Service Configuration

### image

Container image to run.

```yaml
services:
  web:
    image: nginx:latest
```

### build

Build image from Dockerfile.

```yaml
services:
  app:
    build: .

  # Full form
  api:
    build:
      context: ./api
      dockerfile: Dockerfile.prod
      args:
        VERSION: "1.0"
      target: production
```

### ports

Map host ports to container ports.

```yaml
services:
  web:
    ports:
      - "8080:80"        # HOST:CONTAINER
      - "443:443"
```

### environment

Set environment variables.

```yaml
services:
  db:
    # Map syntax
    environment:
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: myapp

    # List syntax
    environment:
      - POSTGRES_PASSWORD=secret
      - POSTGRES_DB=myapp
```

### Automatic .env Loading

HYPR automatically loads `.env` from the compose file directory, just like Docker Compose. No configuration needed.

```
project/
├── docker-compose.yml
├── .env              # Automatically loaded
└── .env.local        # Use env_file to load additional files
```

### env_file

Load additional environment files beyond the automatic `.env`.

```yaml
services:
  api:
    # Single file
    env_file: .env.local

    # Multiple files (loaded in order, later files override)
    env_file:
      - .env.production
      - ./secrets.env
```

**Priority order** (later overrides earlier):
1. `.env` (auto-loaded from compose directory)
2. `env_file` entries (in order listed)
3. `environment` section (highest priority)

Env files use `KEY=VALUE` format, one per line. Comments (`#`) and empty lines are ignored. Values can be quoted.

### volumes

Mount volumes.

```yaml
services:
  web:
    volumes:
      - ./html:/usr/share/nginx/html    # Bind mount
      - data:/var/lib/data              # Named volume

volumes:
  data:
```

### depends_on

Set service dependencies.

```yaml
services:
  web:
    depends_on:
      - db
      - cache

  db:
    image: postgres:16

  cache:
    image: redis:7
```

Services start in dependency order. The web service waits for db and cache to be running before starting.

### networks

Connect to networks.

```yaml
services:
  web:
    networks:
      - frontend

  api:
    networks:
      - frontend
      - backend

  db:
    networks:
      - backend

networks:
  frontend:
  backend:
```

### command

Override the default command.

```yaml
services:
  app:
    image: python:3.12
    # Exec form (array)
    command: ["python", "-m", "http.server", "8000"]

  worker:
    image: myapp
    # Shell form (string)
    command: python worker.py --queue high
```

### entrypoint

Override the entrypoint.

```yaml
services:
  app:
    # Exec form
    entrypoint: ["/entrypoint.sh"]
    command: ["--config", "/app/config.yml"]

  server:
    # Shell form
    entrypoint: /usr/bin/myserver
```

### working_dir

Set working directory.

```yaml
services:
  app:
    working_dir: /app
```

### user

Set user.

```yaml
services:
  app:
    user: "1000:1000"
```

### labels

Add metadata labels.

```yaml
services:
  web:
    labels:
      app: myapp
      environment: production
```

## Resource Limits

Use the `deploy` section to set resource constraints.

```yaml
services:
  api:
    image: myapi:latest
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 1G
        reservations:
          cpus: "0.5"
          memory: 512M
```

## Complete Example

```yaml
version: "3.8"

services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    volumes:
      - ./html:/usr/share/nginx/html
    networks:
      - frontend
    depends_on:
      - api

  api:
    build:
      context: ./api
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgres://user:pass@db:5432/myapp
      REDIS_URL: redis://cache:6379
    networks:
      - frontend
      - backend
    depends_on:
      - db
      - cache
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 1G

  db:
    image: postgres:16
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: myapp
    volumes:
      - db-data:/var/lib/postgresql/data
    networks:
      - backend

  cache:
    image: redis:7
    networks:
      - backend

volumes:
  db-data:

networks:
  frontend:
  backend:
```

Deploy:
```sh
hypr compose up -d
```

## Build Before Deploy

Build images before deploying:
```sh
hypr compose up --build
```

Force recreate all services:
```sh
hypr compose up --force-recreate
```

## Stack Naming

By default, stacks are named after the directory containing the compose file. Override with `--name`:

```sh
hypr compose up --name myproject
```
