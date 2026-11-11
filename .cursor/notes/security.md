# Security Implementation

## Multi-Layer Encryption Strategy

### Three-Tier Secret Architecture

1. **Service Secret** - Application-level encryption key
2. **Key Access Secret** - Per-key encryption secret
3. **User Secret** - Optional user-provided secret for additional security

### Encryption Flow

- Private keys encrypted with Service Secret + Key Access Secret
- Key Access Secrets encrypted with Service Secret + User Secret
- Physical separation of secrets across security domains

## Key Security Features

### Failed Attempt Protection

- **FailedAttemptsCacheService** implements cooldown mechanisms
- Rate limiting on key access attempts
- Configuration in `apps/app/src/config/failed-attempts.config.ts`

### Secure Key Generation

- High-entropy 256-bit key generation using SecureRandom
- Support for Ed25519, ES256, PS256 algorithms
- Keys never exist in decrypted form outside security module

### Memory Security

- Secure clearing of sensitive data after use
- Zero-knowledge architecture principle
- Private keys only decrypted during signing operations

## Authentication & Authorization

### CORS Security (`apps/app/src/config/cors.config.ts`)

- Configurable origin restrictions
- Environment-based CORS policies
- Production security defaults

### Input Validation

**IMPLEMENTED**: Comprehensive input validation with class-validator

- **Global ValidationPipe** in `apps/app/src/main.ts` with security settings:
  - `whitelist: true` - Strips properties without decorators
  - `forbidNonWhitelisted: true` - Rejects requests with extra properties
  - `transform: true` - Auto-transforms payloads to DTO instances
  - Error messages sanitized (target/value not exposed)
  
- **Validated DTOs** in `apps/app/src/types/request.dto.ts`:
  - `SignRequestDto` - Request body for signing operations
  - `GenerateRequestDto` - Request body for key generation
  
- **Security Constraints**:
  - Array size limits (1-10 secrets maximum)
  - String length limits (identifiers: max 500 chars, secrets: max 1000 chars)
  - Pattern matching for identifiers (alphanumeric + `-_:.#`)
  - Enum validation for signatureType and keyType
  - Required field validation with descriptive error messages
  
- **Additional Validation**:
  - Global exception filter for error sanitization
  - Type-safe request validation using TypeScript enums
  - ParseEnumPipe for URL parameter validation
  
- **Validation Tests**: `apps/app/test/validation.e2e-spec.ts`

## Database Security

### Encrypted Storage

- All private key material encrypted before database storage
- No plaintext secrets in database
- TypeORM entity abstraction for secure operations

### Connection Security

**At rest:** All key material is AES-256-GCM ciphertext in PostgreSQL regardless of transport settings.

**In transit (today):**

- Database wire: plain TCP by default in Helm/Docker (`DB_SSL=false`); TLS and mTLS are opt-in feature flags — enable via env vars or Helm `database.ssl.enabled` / `database.ssl.mtls.enabled`
- Internal HTTPS (company-wallet → key-service): opt-in via `TLS_ENABLED`, `TLS_CERT`, `TLS_KEY`, `TLS_CA`, `TLS_MTLS`; mTLS enforced on API routes in application middleware (health probes exempt)
- `DB_SSL=true` uses validated TLS modes (`verify-full` default) with optional client certificates; production rejects `DB_SSL_REJECT_UNAUTHORIZED=false` and `DB_SSL_MODE=require` (R7-001 remediated in application code)
- Wallet ↔ key-service: optional AES-256-GCM request encryption (`REQUEST_ENCRYPTION_ENABLED`)

**Planned (infra):** PostgreSQL server-side TLS and Helm/Docker wiring — see `.cursor/plans/postgresql-mtls.md` (cert generation, Helm, Docker Compose).

## API Security

### Endpoint Protection

- Structured error responses (no information leakage)
- Type-safe parameter validation
- Global exception handling

### Key export

`POST /export` decrypts a stored key with the caller's secrets, then `KeyExportService` returns a compact JWE (`PBES2-HS512+A256KW`, `A256GCM`, `p2c` 210000, `cty` `application/eecc-key-export+json`). The protected header also carries `signatureType` and `keyType`, copied from the stored key so the file can be identified before the passphrase. The passphrase is the only secret on that blob; the vault secret is not mixed in, so another deployment can `POST /import` it. Decrypt rejects any other `alg`, `enc`, `cty`, or `p2c`. `POST /generate` and `POST /import` both return `{ verificationMethod, signatureType, keyType }` from the stored row. Code: `apps/app/src/key-services/key-export.service.ts`, `key.service.ts`.

### Security Headers

- Configurable CORS policies
- Support for security-focused response headers
- Environment-based security configuration

## Threat Mitigation

### Addressed Threats (from security concept document)

- Database compromise protection (encrypted storage)
- User account compromise protection (multi-secret requirement)
- Network traffic interception (challenge-response protocols)
- Single point of failure elimination (distributed secrets)

### Security Module Isolation

- Internal API for key operations
- No direct external access to private keys
- Potential for hardware security module integration

## Security Audit and Analysis

### Audit Framework

- **Primary Framework**: Comprehensive multi-agent security audit defined in `security_audit/security_review_prompt.md`
  - Structured 5-phase analysis process covering cryptography, API, infrastructure, dependencies, and compliance
  - Specialized agents for different security domains (Cryptography Agent, API Security Agent, SBOM Agent, etc.)
- **Alternative Tooling**: Python-based security crew in `security_crew/` directory
  - CrewAI-based multi-agent system with agents and tasks defined in YAML
  - External security report available at `SECURITY_REPORT.md` (read-only reference)

### Audit Scope

- Cryptographic implementation analysis (NIST SP 800-57, NIST SP 800-175B compliance)
- API security (OWASP Top 10 API Security Risks)
- Multi-layer encryption architecture verification
- Dependency and supply chain security (SBOM generation)
- Docker and deployment security
- W3C Verifiable Credentials security considerations

### Key Audit Areas

1. **Cryptographic Security**: Key generation entropy, key storage encryption, secure memory handling
2. **API Security**: Authentication, authorization, input validation, rate limiting, error handling
3. **Database Security**: Connection security, encryption at rest, ORM security
4. **Infrastructure Security**: Docker container security, secrets management, deployment configuration
5. **Compliance**: NIST, OWASP, W3C, FIPS standards verification

### Audit Outputs

- Individual analysis reports per security domain in `security_audit/` directory
- Consolidated final report in `security_audit/audit.md`
- SBOM in CycloneDX format for dependency tracking
- Risk-prioritized findings with remediation recommendations

## Dependency / supply-chain notes

### Unused direct deps (removed 2026-08-05)

Removed from `package.json`: `@digitalbazaar/ed25519-signature-2020`, `@digitalbazaar/ed25519-verification-key-2020`, `@noble/curves`, `uint8arrays`. DI signing uses `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` / `@eecc/rsa-rdfc-2025-cryptosuite`.

Keep despite no app imports: `reflect-metadata`, `rxjs` (Nest peers), `pg` (TypeORM driver), `ts-loader` (Nest webpack via `nest-cli.json` `webpack: true`).

### Overrides (`package.json`)

Only parents whose own range cannot reach a patched release are overridden. Everything else (`multer` 2.5.0 from `@nestjs/platform-express` 11.2.9, `body-parser` 2.4.0, `proxy-addr` 2.0.8, `qs` 6.17.1, `form-data` 4.0.6, `handlebars` 4.7.10, `fast-uri` 3.1.9, `js-yaml` 4.3.2 / 3.15.2, `brace-expansion` 1.1.21 / 5.0.12) resolves from the parent range. Do not put a `>=` floor on a package whose latest major is outside that range: the old `fast-uri` and `js-yaml` floors floated Ajv and cosmiconfig onto vulnerable newer majors.

- `undici@5` → `>=6.29.1 <7`. `@digitalbazaar/http-client` 3.x (`jsonld` 8, via `@eecc/rsa-rdfc-2025-cryptosuite`) requests undici 5, which is inside GHSA-2m5v-pch6-74hx / GHSA-qrxm-fqhp-jwvm / GHSA-9fm3-97px-rjf6. http-client 4.x already requests `^6.23.0` and resolves to 6.29.1 on its own. Stay below 7; undici 7+ breaks Jest.
- `glob@10` and `glob@13` → `>=14.0.4 <15` (GHSA-3g3m-2fjr-6pw4). Jest, TypeORM 0.3, and `@nestjs/cli` 11 request glob 10 or 13. Call sites use `glob.sync` / `require("glob").sync`, which 14 still exports. glob 7 is not in the advisory range.
- `minimatch@10` → `>=11.0.8 <12` (GHSA-g3hv-75wg-m249). `test-exclude` 7 calls `minimatch(path, pattern, options)`. minimatch 3.1.5 (fork-ts-checker) is below the affected range.

`deepmerge` 4.3.1 (GHSA-gcqx-w48m-w2h4, prototype poisoning of the returned object) is the latest release and is only used by Jest and `fork-ts-checker-webpack-plugin` in the Nest CLI. No override can move it to a fix.

`@nestjs/platform-express` depends on `multer` 2.5.0 directly (CVE-2026-77078, CVE-2026-113872). This app does not configure `fileFilter` or mount upload middleware. Express `^2.0.7` resolves `proxy-addr` 2.0.8 (CVE-2026-90711). This app does not set `trust proxy`.

### `@eecc/rsa-multikey` install

1.0.3 declares `"engines": { "node": ">=22.0.0" }`. Versions ≤1.0.2 put that constraint in `peerDependencies`, which made npm install the unrelated `node` binary package.

### Malware / key-theft scan (direct crypto stack)

No install scripts on Digital Bazaar / jose / noble direct packages; pattern scan of those trees showed no SSH/credential exfil (false positives only: W3C “credentials” URLs, FFT method named `eval`).

### Runtime network in signing path

`DocumentLoaderService` resolves `@context` URLs via `JsonLdContextCache` (bundled + injected filesystem dirs) before any fetch. Unknown URLs still `fetch` over HTTP/IPFS — residual SSRF / context-injection surface; prefer shipping or mounting contexts under `contexts/` / `/contexts` rather than open fetch.

### Request body validation

`@Body() x: PlainDto | EncryptedPayloadDto` makes Nest’s global `ValidationPipe` skip validation (union → runtime `Object`). Use `RequestBodyValidationPipe` on those endpoints (`apps/app/src/pipes/request-body-validation.pipe.ts`). See `input-validation-implementation.md`.

