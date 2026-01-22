# Deployment Configuration

## Helm Deployment (Kubernetes)

### Overview

The Key Service includes a production-ready Helm chart for Kubernetes deployment.

**Location**: `helm/`

### Key Features
- **PostgreSQL Integration**: Automatic PostgreSQL deployment via Bitnami chart dependency
- **Auto-generated Secrets**: Signing keys and configuration secrets created on first install
- **Health Probes**: Liveness and readiness probes configured
- **ClusterIP Service**: Internal cluster access only
- **Request Encryption**: Configurable request encryption with shared secrets
- **Simple & Focused**: No ingress, autoscaling, or monitoring - use as a building block

### Quick Start

```bash
# Add Bitnami repository
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Update dependencies (pulls PostgreSQL chart)
cd helm
helm dependency update

# Install with defaults
helm install key-service ./ \
  --create-namespace \
  --namespace key-service \
  --set keyService.tag=v1.7.0
```

### Configuration Options

Key values in `helm/values.yaml`:
- `keyService.image` - Docker image (default: `ghcr.io/european-epc-competence-center/key-service`)
- `keyService.tag` - Image tag (default: `latest`)
- `keyService.replicas` - Number of replicas (default: `1`)
- `keyService.requestEncryption.enabled` - Enable request encryption (default: `false`)
- `keyService.resources` - CPU/memory limits
- `postgresql.enabled` - Deploy PostgreSQL (default: `true`)

### Production Deployment

```bash
# Create signing key secret BEFORE deployment
openssl rand -base64 64 > production-signing-key
kubectl create secret generic key-service-signing-key \
  --from-file=key=production-signing-key \
  --namespace production
kubectl annotate secret key-service-signing-key \
  helm.sh/resource-policy=keep --namespace production

# Deploy with production settings
helm install key-service ./ \
  --namespace production \
  --create-namespace \
  --set keyService.tag=v1.7.0 \
  --set keyService.replicas=2 \
  --set keyService.signingKey.existingSecret=true \
  --set keyService.requestEncryption.enabled=true \
  --set keyService.requestEncryption.sharedSecret="secure-secret"
```

### Secrets Management

Auto-generated secrets (retained across upgrades):
1. **key-service-signing-key**: Cryptographic signing key (64-char random)
2. **key-service-secret**: Contains PBKDF2 iterations and request encryption secret
3. **postgresql**: Database password (Bitnami chart)

**⚠️ IMPORTANT - Production Secret Management**:

The auto-generated signing key and mounting it via Kubernetes secrets is **ONLY A WORKAROUND** for development/testing environments where HashiCorp Vault is not available.

**In production, the signing key MUST be mounted from Vault**, not stored as a Kubernetes secret. This provides:
- Centralized secret management with access control
- Audit logging of secret access
- Secret rotation capabilities
- HSM-backed encryption at rest
- Compliance with security standards

Use Vault Agent Injector or Vault CSI driver to mount the signing key from Vault at `/run/secrets/signing-key`.

### Accessing the Service

Within cluster:
```
http://key-service-key-service.{namespace}.svc.cluster.local:3000
```

Port forwarding:
```bash
kubectl port-forward svc/key-service-key-service 3000:3000 -n key-service
```

### External PostgreSQL

To use external PostgreSQL instead of bundled chart:

```bash
helm install key-service ./ \
  --namespace key-service \
  --create-namespace \
  --set postgresql.enabled=false \
  --set postgresql.host=external-postgres.example.com \
  --set postgresql.auth.existingSecret=external-postgresql
```

### Documentation

Full Helm deployment documentation: `helm/README.md`

## Docker Support

### Production Dockerfile
- Location: `docker/Dockerfile`
- Multi-stage build for optimized image size
- Node.js 22+ runtime requirement
- Production-ready configuration

### Development Docker
- Development containers with hot reload
- Volume mounting for live code changes
- Separate development compose files

### Docker Commands
```bash
# Build production image
docker build -t key-service:latest -f docker/Dockerfile .

# Run production container
docker run -p 3000:3000 key-service:latest

# Use Docker Compose
docker-compose -f docker/docker-compose.yml up -d
```

## Environment Configuration

### Required Environment Variables
```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_NAME=key_service
DB_SSL=false

# Application Configuration
NODE_ENV=production
SIGNING_KEY_PATH=/run/secrets/signing-key

# CORS Configuration (optional)
CORS_ENABLED=true
CORS_ORIGINS=https://example.com,https://app.example.com
CORS_METHODS=GET,POST,PUT,DELETE
CORS_CREDENTIALS=false
CORS_MAX_AGE=86400
```

### Security Considerations
- **Production**: Always set specific `CORS_ORIGINS`
- **Secrets**: Use proper secret management for `SIGNING_KEY_PATH`
- **SSL**: Enable `DB_SSL=true` for production databases

## Database Setup

### PostgreSQL Deployment
- Requires PostgreSQL database
- Automatic table creation in non-production environments
- Migration system for schema versioning

### Docker Compose Database
```bash
# Start PostgreSQL with Docker Compose
docker-compose up -d postgres

# Check database logs
docker-compose logs -f postgres
```

## Health Checks

### Kubernetes Ready Endpoints
- `/health` - General health check with database connectivity
- `/health/liveness` - Liveness probe (application running)
- `/health/readiness` - Readiness probe (ready to serve traffic)

### Health Check Integration
- Built-in database connectivity verification
- Kubernetes deployment ready
- Proper HTTP status codes for orchestration

## Production Deployment

### Build Process
1. `npm run build` - Compile TypeScript and migrations
2. Docker image build with multi-stage optimization
3. Environment variable configuration
4. Database migration execution

### Scaling Considerations
- Stateless application design
- Database connection pooling
- Horizontal scaling supported

### Monitoring & Logging
- Structured logging output
- Health endpoint monitoring
- Application version logging on startup

## CI/CD Pipeline

### GitHub Actions Workflow
- Location: `.github/workflows/ci-cd.yml`
- Jobs: unit-tests, build-and-push, create-release
- Automated testing and Docker image builds

#### Container Registries
- **GitHub Container Registry**: `ghcr.io/european-epc-competence-center/key-service`
  - Pushed on all main branch commits and version tags
- **Azure Container Registry**: `gs1euwstvcacr.azurecr.io/key-service`
  - Pushed only for version tags (e.g., `v1.7.0`)
  - Requires `GO_CONTAINER_PUSH_PASSWD` secret in GitHub Actions

### GitHub Synchronization

The repository can be automatically synced to GitHub on releases or manually triggered.

#### Required CI/CD Variables
Set these in GitLab: Settings → CI/CD → Variables

```bash
GITHUB_ACCESS_TOKEN  # GitHub Personal Access Token with repo write access
GITHUB_REPO          # Format: username/repository (e.g., "yourorg/key-service")
```

#### Trigger Conditions
1. **Automatic on Release**: Pushes to GitHub when a version tag is created (e.g., `v1.4.1`)
2. **Manual Trigger**: Can be triggered manually from GitLab Pipelines UI

#### Partial Sync (Filtering Sensitive Files)
- The `.github-filter` file documents which files/folders should be excluded
- By default, the full repository is pushed
- To enable filtering, uncomment the rm -rf lines in the `push_to_github` job
- Recommended exclusions:
  - `security_audit/` - Internal security audit files
  - `security_crew/` - Internal security tooling
  - `docker/signing-key` - Sensitive signing keys

#### Creating GitHub Access Token
1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. Select scopes: `repo` (full control of private repositories)
4. Copy token and add to GitLab CI/CD variables as `GITHUB_ACCESS_TOKEN`