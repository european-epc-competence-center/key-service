# Deployment Configuration

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

### GitLab CI Configuration
- Location: `.gitlab-ci.yml`
- Stages: test, build, push, sync
- Automated testing and Docker image builds
- Docker registry: `registry.eecc.info/ssi/key-service`

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