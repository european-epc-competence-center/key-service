# Technical Architecture

## Service Layer Structure

### Core Services Hierarchy

```
AppModule
├── KeyService (core key operations)
├── KeyStorageService (database layer)
├── SecretService (encryption/decryption)
├── FailedAttemptsCacheService (security)
├── JwtSigningService (JWT-VC signing)
├── DataIntegritySigningService (DI proofs)
└── DocumentLoaderService (JSON-LD)
```

### Key Dependencies

- **@nestjs/typeorm** - Database ORM integration
- **@digitalbazaar/vc** - W3C Verifiable Credentials
- **@digitalbazaar/ed25519-signature-2020** - Ed25519 signatures
- **jose** - JWT operations
- **@noble/curves** - Cryptographic curve operations

## Database Architecture

### Entities
- **EncryptedKey** entity (`apps/app/src/key-services/entities/encrypted-key.entity.ts`)
- TypeORM configuration in `apps/app/src/config/database.config.ts`
- Migrations in `migrations/` directory

### Key Storage Strategy
- Keys stored encrypted in PostgreSQL
- Multi-layer encryption with service + user secrets
- Database operations abstracted through KeyStorageService

## Configuration Management

### Config Files Location: `apps/app/src/config/`
- `cors.config.ts` - CORS policy configuration
- `database.config.ts` - PostgreSQL connection
- `failed-attempts.config.ts` - Security rate limiting

### Environment Variables
- Database connection (DB_HOST, DB_PORT, etc.)
- CORS settings (CORS_ENABLED, CORS_ORIGINS)
- Node environment (NODE_ENV)
- Signing key path (SIGNING_KEY_PATH)

## Signing Service Architecture

### JWT Signing (`jwt-signing.service.ts`)
- Uses `jose` library for JWT operations
- Supports Ed25519 and ES256 signatures
- Auto-sets issuer and issuance date
- Implements private `sign()` method for code reuse between VC and VP signing

### Data Integrity Signing (`data-integrity-signing.service.ts`)
- Uses Digital Bazaar libraries
- Implements Ed25519Signature2020 proofs
- JSON-LD context processing
- Implements private `sign()` method for code reuse between VC and VP signing

### Common Patterns
Both signing services follow the same architectural pattern:
- Public methods: `signVC()` and `signVP()`
- Private method: `sign()` containing shared signing logic
- Optional `preSignHook` parameter for credential-specific setup (e.g., setting issuer)

## Type System

### Key Type Definitions (`apps/app/src/types/`)
- `verifiable-credential.types.ts` - VC Data Model 2.0 types
- `keypair.types.ts` - Key pair and JWK types
- `verification-method.types.ts` - DID verification methods
- `request.types.ts` - API request/response types
- `key-types.enum.ts` - Supported key formats
- `sign-types.enum.ts` - Signature type enumeration

## Health Check System

### Health Module (`apps/app/src/health/`)
- Standard health en/health`)
- Kubernetes liveness probe (`/health/liveness`)  
- Kubernetes readiness probe (`/health/readiness`)
- Database connectivity checks

## Error Handling

### Global Exception Filter (`apps/aprs/global-exception.filter.ts`)
- Structured error responses
- HTTP status code mapping
- Security-focused error sanitization