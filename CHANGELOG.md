# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- `SignRequestDto.verifiable` is optional at the DTO layer; `POST /sign/vc` and `POST /sign/vp` still require a non-array object (enforced in `AppService`). `POST /sign/pop/jwt` can omit it; `POST /sign/pop/data-integrity` ignores it and always builds a minimal VP shell, then calls `signPresentation` (OpenID4VCI Appendix F.2 `di_vp`)
- **Breaking**: `POST /sign/pop/data-integrity` requires non-empty `domain` (Credential Issuer Identifier for proof `domain`, [OpenID4VCI F.2 `di_vp`](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-di_vp-proof-type)); `POST /sign/vp/data-integrity` unchanged (`domain` still optional there)
- **Breaking**: `POST /sign/pop/data-integrity` no longer uses request `verifiable` — use `POST /sign/vp/data-integrity` for a custom VP

## [2.3.0] - 2026-04-02

### Added
- `POST /sign/pop/:type` — proof-of-possession signing with `type` `jwt` (OpenID4VCI Appendix F.1 key proof JWT) or `data-integrity` (linked-data VP, same as `POST /sign/vp/data-integrity`); body uses `SignRequestDto` (same as `/sign/vp`)
- Signing entry points: `signCredential`, `signPresentation`, `signProofOfPossession` on `JwtSigningService` / `DataIntegritySigningService` / `AppService` (controller handlers match); JWT uses private `signJwt` for W3C VC/VP; OpenID4VCI proof JWT uses `signProofOfPossession` with a minimal F.1 JWT body (not a VC)
- Unit tests for OID4VCI (`jwt-signing.service.spec.ts`)

### Changed
- **Breaking**: W3C JWT VC/VP (`signCredential` / `signPresentation`, `POST /sign/vc|vp/jwt`): `iss` is in the JWS **protected header** (signing key controller: `kid` without fragment), per [VC-JOSE-COSE key discovery](https://w3c.github.io/vc-jose-cose/#using-header-params-claims-key-discovery); JWT Claims Set carries `iat` and optional VP `nonce`/`aud` only (no `iss`, avoiding overlap with VC `issuer`)
- **Breaking**: `PresentRequestDto` and `ProofOfPossessionRequestDto` removed — `SignRequestDto` carries optional `challenge` / `domain` for VP and PoP; `POST /sign/vc|vp|pop/*` share it; OpenID4VCI JWT PoP JOSE header remains only `typ` `openid4vci-proof+jwt`, `alg`, and `kid`
- **Breaking**: OpenID4VCI JWT proof (`signProofOfPossession`, `POST /sign/pop/jwt`) matches [Appendix F.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type): JWT payload is only `aud` / `iat` / optional `iss` / `nonce` — no VC merge; non-empty `domain` is required (`aud`); `verifiable` is ignored for `jwt`
- Documentation: `JwtSigningService.signProofOfPossession` documents Appendix F.1 layout; OID4VCI PoP signing stays inlined in `signProofOfPossession`
- `POST /sign/pop/:type` uses `SignType` (same URL param as `POST /sign/vp/:type`) instead of a separate `SignPopType` enum; `sd-jwt` is rejected with 400
- **Breaking**: OpenID4VCI proof JWTs use `POST /sign/pop/jwt` or `JwtSigningService.signProofOfPossession` (not W3C JWT VC/VP signing on `POST /sign/vc|vp/jwt`)
- JWT `signPresentation` / `signCredential`: `iss` in JWS protected header; OID4VCI proof JWT keeps optional `iss` in the JWT body via `signProofOfPossession` only (Appendix F.1)
- Unit tests (`jwt-signing.service.spec.ts`): VC/VP assert `iss` on decoded header, not payload; OID4VCI tests unchanged; ES256/PS256 VP header asserts no `iat` in the JWS protected header

### Fixed
- JWT signing: VC `preSignHook` (issuer derived from `kid`) runs before the payload snapshot so the JWT body includes the correct issuer DID

### Removed
- **Breaking**: `additionalHeaders` on `SignRequestDto` and on `JwtSigningService` / `DataIntegritySigningService` VC/VP signing — extra JWS protected-header fields are no longer accepted; use `POST /sign/pop/jwt` for OpenID4VCI proof JWT header `typ`


## [2.2.0] - 2026-03-27

### Added
- JWT signing: `signVC` / `signVP` accept optional `additionalHeaders`; `SignRequestDto` / `POST /sign/vc|vp/jwt` accept optional `additionalHeaders` for extra JWS header properties
- Unit test: `typ: openid4vci-proof+jwt` via `additionalHeaders` is present in the signed JWS protected header (`jwt-signing.service.spec.ts`)

### Changed
- JWT signing: issuance time `iat` is set only in the JWS protected header (no longer duplicated in the payload JSON)
- JWT signing: signing key controller identifier is included as `iss` in the JWS protected header (DID string before `#` in `kid`, same as VC `issuer`)
- `docs/SECURITY_REPORT.md`: removed emojis for professional PDF rendering, fixed pandoc formatting (blank lines before lists, heading hierarchy, YAML header with `lang: en` and fancyhdr)
- `docs/SECURITY_REPORT.md`: fixed table column width proportions for all dependency/license tables; removed inline-code backtick formatting from package name cells so LaTeX can wrap long names at hyphens; added `\small` for longtable environments via etoolbox
- `docs/SECURITY_REPORT.md`: fixed mermaid xychart bar chart colors — used correct nested `xyChart.plotColorPalette` variable instead of `primaryColor` (which only affects flowchart nodes); bars now render as professional blue on white background
- `docs/SECURITY_REPORT.md`: fixed code block overflow with `fvextra` package (`breaklines` on `Highlighting` verbatim environment); reduced `\tabcolsep` to 3pt for tighter tables
- `docs/SECURITY_REPORT.md`: removed redundant "Risk Level" column from License Distribution Analysis (derivable from Category) and redundant "Compliance" column from crypto package license table (all rows identical); reduces both from 5 to 4 data columns, preventing horizontal page overflow
- `docs/md_to_pdf.sh`: added `--columns=1000` flag so pandoc uses separator-dash proportions for column widths instead of clamping to terminal width


## [2.1.0] - 2026-01-29

- allow key deletion


## [2.0.1] - 2026-01-22

### Added
- Azure Container Registry support for tagged releases
  - Docker images for version tags are now pushed to both GitHub Container Registry and Azure Container Registry (`gs1euwstvcacr.azurecr.io`)
  - Automated push for version tags (e.g., `v1.7.0`) with semantic versioning tags
  - GitHub Actions workflow configured with Azure CR authentication

### Fixed
- SecretService test suite now correctly validates secure-by-default behavior
  - Service throws error when NODE_ENV is undefined or any non-development value and signing key file cannot be read
  - Added test coverage for test, staging, and undefined NODE_ENV scenarios
  - Fallback secret only used when explicitly in development mode
  - Ensures production deployments fail fast when misconfigured rather than using insecure defaults


## [2.0.0] - 2025-12-15

- move to multikey for all keytypes
- move to latest version of DataIntegrityProof


## [1.9.0] - 2025-12-08

- integrate PS256 data integrity signature


## [1.8.1] - 2025-11-13

- fix es256 data integrity signature in signature package


## [1.8.0] - 2025-11-13

- add ES256 signature package for data integrity proof with es256 JWK


## [1.7.0] - 2025-10-31

### Added
- **Automatic request payload decryption for request encryption**
  - Implemented PayloadEncryptionService using AES-256-GCM encryption
  - Service-layer decryption for enhanced security (decrypted data never exposed in request pipeline)
  - Automatically detects and decrypts requests with `encryptedData` field in AppService
  - Request encryption shared secret configuration via `REQUEST_ENCRYPTION_SHARED_SECRET` environment variable
  - Service decrypts incoming encrypted requests, returns plain JSON responses
  - Simple format: base64(iv:authTag:ciphertext) - compatible with all major platforms
  - Comprehensive unit tests for encryption service
  - Spring Boot, Node.js, and Python client examples
  - All existing endpoints (`/generate`, `/sign/vc/:type`, `/sign/vp/:type`) support both encrypted and plain requests

### Documentation
- Added `docs/payload-encryption-spring-boot.md` with full Spring Boot/Java integration guide
- Added `docs/REQUEST_ENCRYPTION_USAGE.md` with multi-language client examples
- Includes configuration, security best practices, and troubleshooting


## [1.6.1] - 2025-10-29

- auto create github release on tag


## [1.6.0] - 2025-10-29

- implement presentation signing endpoint


## [1.5.0] - 2025-10-27

### Security
- **Implemented comprehensive input validation** - Addresses "Insufficient Input Validation" security issue identified in SECURITY_REPORT.md
  - Added class-validator and class-transformer for DTO validation
  - Created validated DTOs (SignRequestDto, GenerateRequestDto) with security constraints
  - Enabled global ValidationPipe with security settings (whitelist, forbidNonWhitelisted)
  - Implemented length limits: identifiers (max 500 chars), secrets (max 1000 chars)
  - Added array size constraints: 1-10 secrets maximum
  - Pattern validation for identifiers (alphanumeric + `-_:.` only)
  - Enum validation for signatureType and keyType fields
  - Comprehensive validation test suite (validation.e2e-spec.ts)
  - make PBKDF2_ITERATIONS configurable through env
  - make ES256 generation NIST compliant

### Changed
- Updated main.ts to enable global input validation with security-focused configuration
- Updated app.controller.ts to use validated DTOs instead of plain interfaces
- Updated app.service.ts to use validated DTOs
- Exported DTOs from types/index.ts for easy import

### Fixed
- jest-e2e.json configuration path for test-setup.ts


## [1.4.1] - 2025-09-11

- fix app version read


## [1.4.0] - 2025-09-11

- fix release version

## [1.3.0] - 2025-09-11

- put complete keyId into vc jwt header

## [1.2.0] - 2025-09-09

## Fixed

- fix ES256 jose signatures

## [1.1.0] - 2025-08-25

- added PS256 key support

## [1.0.0] - 2025-08-07

### Added

- Automated release script with changelog detection
- Enhanced error handling for malformed requests
- Support for additional key algorithms
- added failed attempt cooldown cache

### Changed

- Improved logging format for better debugging
- Updated dependency versions for security patches

## [0.0.1] - 2024-01-01

### Added

- Initial key service implementation
- JWT signature support for Verifiable Credentials
- Data Integrity signature support for Verifiable Credentials
- Ed25519 key generation and management
- Public key retrieval endpoints
- Health check endpoints for Kubernetes
- Global exception handling with structured API responses
- TypeORM database integration
- Docker containerization support
- GitLab CI/CD pipeline configuration

### Security

- Secure key storage and management
- Environment-based configuration for sensitive data
