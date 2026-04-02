# Technical Architecture

## Service Layer Structure

### Core Services Hierarchy

```
AppModule
├── KeyService (core key operations)
├── KeyStorageService (database layer)
├── SecretService (encryption/decryption)
├── PayloadEncryptionService (AES-256-GCM payload encryption)
├── FailedAttemptsCacheService (security)
├── JwtSigningService (JWT-VC signing)
├── DataIntegritySigningService (DI proofs - Ed25519 & ES256)
│   └── Uses ES256Signature2020 custom suite
└── DocumentLoaderService (JSON-LD)
```

### Key Dependencies

- **@nestjs/typeorm** - Database ORM integration
- **@digitalbazaar/vc** - W3C Verifiable Credentials
- **@digitalbazaar/ed25519-signature-2020** - Ed25519 signatures for Data Integrity proofs
- **jsonld-signatures** - Base library for Data Integrity signatures
- **base58-universal** - Multibase encoding for signature proofs
- **jose** - JWT operations and ES256 signing
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
- `payload-encryption.config.ts` - Request decryption settings (AES-256-GCM)

### Request Decryption Architecture
- **Service-layer decryption** (in `AppService`) for enhanced security
  - Detects requests with `encryptedData` field
  - Decrypts payload after controller, in the service layer
  - Keeps decrypted secrets isolated from request pipeline (reduces logging exposure risk)
  - Controllers pass raw request body to service methods

### Environment Variables
- Database connection (DB_HOST, DB_PORT, etc.)
- CORS settings (CORS_ENABLED, CORS_ORIGINS)
- Node environment (NODE_ENV)
- Signing key path (SIGNING_KEY_PATH)
- Inter-service request decryption (INTER_SERVICE_ENCRYPTION_ENABLED, INTER_SERVICE_SHARED_SECRET)

## Signing Service Architecture

### JWT Signing (`jwt-signing.service.ts`)
- Uses `jose` library for JWT operations
- Supports Ed25519 and ES256 signatures
- Auto-sets issuer and issuance date
- **W3C JWT-VC** (`signCredential` / `signPresentation`, `POST /sign/vc|vp/jwt`): JWS protected header is `alg` + `kid` + `iss` (signing key controller: `kid` without fragment), per [VC-JOSE-COSE key discovery](https://w3c.github.io/vc-jose-cose/#using-header-params-claims-key-discovery); JWT Claims Set has `iat` and optional VP `nonce`/`aud` only (no `iss`); `preSignHook` runs before the payload snapshot; private `signJwtVerifiable`
- **OpenID4VCI proof JWT** (`signProofOfPossession`, `POST /sign/pop/jwt`): Credential Request `proofs.jwt` (spec §8.2), Appendix F.1 `jwt` proof — JWT body is only `aud` (required), `iat` (required), optional `iss` / `nonce`; not a VC; JOSE header `typ` `openid4vci-proof+jwt`, `alg`, `kid`; API requires `domain` → `aud`, optional `challenge` → `nonce`; `verifiable` optional and ignored for `jwt`
- **Data Integrity PoP** (`POST /sign/pop/data-integrity`): OpenID4VCI Appendix F.2 [`di_vp`](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-di_vp-proof-type) — `AppService` builds minimal VP shell, then `signPresentation` / `DataIntegritySigningService.signPresentation`; non-empty `domain`; optional `challenge`; request `verifiable` ignored
- **Proof-of-possession HTTP**: `POST /sign/pop/:type` — body `SignRequestDto` (same as `/sign/vp`); same `SignType` as `POST /sign/vp/:type` (`jwt` → OID4VCI proof JWT; `data-integrity` → same as `POST /sign/vp/data-integrity`; `sd-jwt` → 400)
- Implements private `sign()` method for code reuse between VC and VP signing

### Data Integrity Signing (`data-integrity-signing.service.ts`)
- Uses Digital Bazaar libraries
- Implements Ed25519Signature2020 proofs
- JSON-LD context processing
- Implements private `sign()` method for code reuse between VC and VP signing

### Common Patterns
Both signing services follow the same architectural pattern:
- Public methods: `signCredential()` and `signPresentation()`
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