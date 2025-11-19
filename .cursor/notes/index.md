# Key Service Project Overview

## Project Summary

The Key Service is a NestJS-based API for signing verifiable credentials using multiple signature formats (JWT, Data Integrity, SD-JWT). It provides secure key management, credential signing, and public key retrieval capabilities.

**Current Version**: v1.7.0  
**License**: AGPL-3.0 (GNU Affero General Public License v3.0)  
**Author**: Christian Fries  
**Technology Stack**: NestJS, TypeScript, PostgreSQL, Docker  
**Node.js**: ≥22.0.0

## Project Structure

```
key-service/
├── apps/app/                    # Main NestJS application
│   ├── src/
│   │   ├── config/             # Configuration files (CORS, DB, failed attempts)
│   │   ├── filters/            # Global exception handling
│   │   ├── health/             # Health check endpoints
│   │   ├── key-services/       # Core key management services
│   │   ├── signing-services/   # Credential signing services
│   │   ├── types/              # TypeScript type definitions
│   │   └── utils/              # Utility functions and logging
│   └── test/                   # Test configuration and E2E tests
├── docker/                     # Docker configuration
├── docs/                       # Security and architecture documentation
├── migrations/                 # Database migrations
├── scripts/                    # Build and release scripts
├── security_audit/             # Multi-agent security audit framework and outputs
└── security_crew/              # Security audit tooling (Python-based)
```

## Core Features

- **Multiple Signature Types**: JWT, Data Integrity, SD-JWT
- **Key Management**: Ed25519, ES256, PS256 algorithm support
- **Encrypted Storage**: Keys encrypted using secret service
- **Request Encryption**: AES-256-GCM decryption of encrypted incoming requests in service layer (responses are plain JSON)
- **Verifiable Credentials**: W3C VC Data Model 2.0 compliant
- **Health Checks**: Kubernetes-ready health endpoints
- **Docker Support**: Production-ready containers

## Key Services Architecture

### Main Components

1. **KeyService** - Core key generation and management
2. **KeyStorageService** - Database operations for encrypted keys
3. **SecretService** - Encryption/decryption of key materials
4. **PayloadEncryptionService** - AES-256-GCM request decryption (clients send encrypted, service responds plain)
5. **JwtSigningService** - JWT-VC signing implementation
6. **DataIntegritySigningService** - Data Integrity proof signing
7. **FailedAttemptsCacheService** - Security rate limiting

### Database

- **PostgreSQL** - Primary database for encrypted key storage
- **TypeORM** - Database ORM with entity management
- **Migration System** - Version-controlled schema management

## Security Architecture

Based on `docs/security_and_key_management_concept.md`, the system implements:

- **Multi-layer encryption** with service + user secrets
- **Zero-knowledge architecture** - private keys never exposed
- **Failed attempt protection** with cooldown mechanisms
- **Physical secret separation** across security domains
- **Multi-signature authorization** for shared keys

## Development & Testing

### Scripts

- `npm run dev` - Development with hot reload
- `npm test` - Run all tests (unit + e2e)
- `npm run test:unit` - Unit tests only
- `npm run test:e2e` - Integration tests with real database
- `npm run build` - Production build

### Environment

- Node.js >=22.0.0
- PostgreSQL database required
- Docker support for containerized deployment

## API Endpoints

- `POST /sign/vc/:type` - Sign verifiable credentials (type: jwt, data-integrity, sd-jwt)
- `POST /sign/vp/:type` - Sign verifiable presentations (type: jwt, data-integrity, sd-jwt)
- `POST /generate` - Generate new key pairs (algorithms: Ed25519, ES256, PS256)
- **Note**: All POST endpoints automatically support encrypted requests (decryption handled in AppService layer for enhanced security)
- `GET /health` - General health check
- `GET /health/liveness` - Kubernetes liveness probe
- `GET /health/readiness` - Kubernetes readiness probe

### Request Structure (v1.5.0)

All signing and generation requests use:
- `verifiable`: The VC or VP object (not "credential")
- `secrets`: Array of 1-10 secrets (not single "secret")
- `identifier`: Key identifier (alphanumeric + `-_:.`)
- Additional fields for VP: `challenge`, `domain`

## Notes Files Reference

- [architecture.md](./architecture.md) - Detailed technical architecture
- [security.md](./security.md) - Security implementation details and audit framework
- [data-integrity-signatures.md](./data-integrity-signatures.md) - Data Integrity proof implementation (Ed25519, ES256)
- [input-validation-implementation.md](./input-validation-implementation.md) - Input validation security implementation (2025-10-07)
- [development.md](./development.md) - Development workflows and patterns
- [deployment.md](./deployment.md) - Helm, Docker and deployment configuration
- [testing.md](./testing.md) - Testing strategies and patterns

## Quick Start Commands

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Start test database
npm run test:db:start

# Run all tests
npm test

# Build for production
npm run build
```

## Important Files to Reference

- `README.md` - **Updated 2025-10-29** - Comprehensive project documentation with accurate API endpoints, testing instructions, and deployment guides
- `apps/app/src/app.module.ts` - Main application module
- `apps/app/src/main.ts` - Application bootstrap with input validation
- `apps/app/src/app.controller.ts` - API endpoints (VC/VP signing, key generation)
- `apps/app/src/types/request.dto.ts` - Request DTOs with validation decorators
- `apps/app/src/types/` - Core type definitions
- `package.json` - Dependencies and scripts
- `docs/security_and_key_management_concept.md` - Security architecture concept
- `security_audit/security_review_prompt.md` - Comprehensive multi-agent security audit framework
- `SECURITY_REPORT.md` - External security analysis report (read-only reference)
- `CHANGELOG.md` - Version history and changes (current: v1.7.0)
- `docs/REQUEST_ENCRYPTION_QUICK_START.md` - **NEW** Quick configuration reference for request encryption
- `docs/payload-encryption-spring-boot.md` - **NEW** Spring Boot/Java client implementation guide
- `docs/REQUEST_ENCRYPTION_USAGE.md` - **NEW** Multi-language client examples (Java, Node.js, Python)
