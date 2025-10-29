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
  - Pattern matching for identifiers (alphanumeric + `-_:.` only)
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

- SSL/TLS database connections supported
- Environment-based configuration
- Connection pooling with security timeouts

## API Security

### Endpoint Protection

- Structured error responses (no information leakage)
- Type-safe parameter validation
- Global exception handling

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
