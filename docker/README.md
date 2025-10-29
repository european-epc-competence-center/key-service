# Docker Setup for Key Service

This directory contains all Docker-related files for the key-service application.

## Files

- `Dockerfile` - Production-ready multi-stage build
- `Dockerfile.dev` - Development build with hot reloading
- `docker-compose.yml` - Production compose configuration
- `docker-compose.dev.yml` - Development compose configuration
- `.dockerignore` - Files to exclude from Docker build context

## Quick Start

### Manual Docker commands

```bash
# Production
docker build -t key-service:latest -f docker/Dockerfile .
docker-compose -f docker/docker-compose.yml up -d

# Development
docker build -t key-service:dev -f docker/Dockerfile.dev .
docker-compose -f docker/docker-compose.dev.yml up --build
```

## Docker Images

### Production Image (`key-service:latest`)

- Multi-stage build for optimized size
- Non-root user for security
- Health checks included
- Production dependencies only
- Alpine Linux base for minimal attack surface

### Development Image (`key-service:dev`)

- Includes all development dependencies
- Hot reloading support
- Volume mounting for live code changes
- Suitable for local development

## Environment Variables

### Production

- `NODE_ENV=production`
- `PORT=3000`

### Development

- `NODE_ENV=development`
- `PORT=3000`

## Ports

- **3000** - Application port (both production and development)

## Health Checks

The production container includes health checks that verify the application is responding on the `/health` endpoint.

## Security Features

- Non-root user execution
- Minimal base image (Alpine Linux)
- Production-only dependencies in final image
- Proper file permissions

## Development Features

- Hot reloading with volume mounts
- Development dependencies included
- Easy debugging capabilities
- Live code changes without rebuilds
