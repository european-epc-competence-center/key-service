# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
