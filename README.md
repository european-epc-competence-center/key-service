# Key Service

A secure NestJS-based cryptographic signing service for W3C Verifiable Credentials (VC Data Model 2.0) and Verifiable Presentations. The service implements multiple signature formats with enterprise-grade key management and multi-layer encryption.

**Version:** 1.5.0  
**License:** AGPL-3.0  
**Author:** Christian Fries  
**Node.js:** ≥22.0.0

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Database Setup](#database-setup)
- [Testing](#testing)
- [Docker](#docker)
- [API Endpoints](#api-endpoints)
- [Sample Requests](#sample-requests)
- [Security Features](#security-features)
- [Key Dependencies](#key-dependencies)
- [Project Structure](#project-structure)

## Features

- **Multiple Signature Formats**: JWT-VC, Data Integrity proofs (Ed25519Signature2020), and SD-JWT
- **Cryptographic Algorithms**: Ed25519, ES256, PS256 support
- **Secure Key Management**: Automatic key pair generation with PostgreSQL storage
- **Multi-Layer Encryption**: Keys encrypted with service + key access secrets
- **W3C Standards Compliance**: Full VC Data Model 2.0 and DID Core support
- **Input Validation**: Comprehensive security-focused validation using class-validator
- **Failed Attempt Protection**: Rate limiting with cooldown mechanisms
- **Health Checks**: Kubernetes-ready liveness and readiness probes
- **RESTful API**: Clean HTTP endpoints with comprehensive error handling
- **TypeScript**: Fully typed with extensive type definitions
- **Testing**: Comprehensive unit and integration test coverage
- **Docker Support**: Production-ready containers with PostgreSQL integration

## Installation

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Run in production mode
npm start
```

## Testing

The service includes comprehensive test coverage with both unit tests (using mocks) and end-to-end (E2E) tests (using a real PostgreSQL database).

### Quick Test Commands

```bash
# Run all tests (E2E + unit)
npm test

# Run all tests with coverage
npm run test:coverage
```

### Unit Tests

Run unit tests with mocked dependencies (no database required):

```bash
# Run all unit tests
npm run test:unit

# Run unit tests in watch mode
npm run test:unit:watch

# Run unit tests with coverage
npm run test:unit:coverage
```

### End-to-End (E2E) Tests

Run E2E tests with a real PostgreSQL database. These tests validate the full application stack including database operations, API endpoints, and integrations.

```bash
# Run E2E tests (requires database)
npm run test:e2e

# Run E2E tests in watch mode
npm run test:e2e:watch

# Run E2E tests with coverage
npm run test:e2e:coverage
```

### Test Database Management

```bash
# Start PostgreSQL test database
npm run test:db:start

# Stop and remove test database
npm run test:db:stop

# Run unit tests with database (start + test + stop)
npm run test:unit:with-db
```

The test database runs PostgreSQL 17 in Docker and is automatically configured with test credentials.

### Test Configuration

- **E2E Tests**: `apps/app/test/jest-e2e.json`
- **Unit Tests**: `apps/app/test/jest-unit.json`
- **Test Setup**: `apps/app/test/test-setup.ts`
- **Test Database**: `docker/docker-compose.test.yml`

### Test Coverage

The test suite includes:
- ✅ Key generation and storage
- ✅ Multi-secret encryption/decryption
- ✅ JWT-VC signing
- ✅ Data Integrity signing
- ✅ Input validation (comprehensive security tests)
- ✅ Failed attempt protection
- ✅ Health check endpoints
- ✅ Error handling and edge cases

## Database Setup

This service uses PostgreSQL to store encrypted keys. You can set up the database using Docker Compose:

```bash
# Start PostgreSQL database
docker-compose up -d postgres

# Wait for database to be ready
docker-compose logs -f postgres
```

## Environment Variables

The service is configured using environment variables. Create a `.env` file in the project root:

### Required Variables

```env
# Database Configuration
DB_HOST=localhost              # PostgreSQL host
DB_PORT=5432                   # PostgreSQL port
DB_USERNAME=postgres           # Database username
DB_PASSWORD=postgres           # Database password
DB_NAME=key_service           # Database name
DB_SSL=false                  # Enable SSL for database connection

# Application Configuration
NODE_ENV=development          # Environment: development, production
PORT=3000                     # Application port (default: 3000)
SIGNING_KEY_PATH=/run/secrets/signing-key  # Path to signing key file
```

### Optional Variables

```env
# CORS Configuration
CORS_ENABLED=true             # Enable/disable CORS (default: true)
CORS_ORIGINS=https://example.com,https://app.example.com  # Allowed origins (comma-separated, default: all)
CORS_METHODS=GET,POST,PUT,DELETE  # Allowed methods (default: GET,HEAD,PUT,PATCH,POST,DELETE)
CORS_CREDENTIALS=false        # Allow credentials (default: false)
CORS_MAX_AGE=86400           # Preflight cache duration in seconds (default: 86400)

# Security Configuration
PBKDF2_ITERATIONS=100000     # PBKDF2 iterations for key derivation (default: 100000)
```

### Production Recommendations

- Set `NODE_ENV=production` in production environments
- Always configure `CORS_ORIGINS` with specific trusted domains in production
- Use strong database passwords
- Enable `DB_SSL=true` for production database connections
- Store `SIGNING_KEY_PATH` secret in a secure location (e.g., Docker secrets, Kubernetes secrets)

### Manual Database Setup

If you prefer to set up PostgreSQL manually:

1. Install PostgreSQL
2. Create a database named `key_service`
3. Create a user with appropriate permissions
4. Update the environment variables accordingly

The application will automatically create the required tables on startup when `NODE_ENV` is not set to `production`.

### Database Migrations

The service uses TypeORM migrations for database schema management:

```bash
# Generate a new migration from entity changes
npm run migration:generate -- migrations/MigrationName

# Create a blank migration file
npm run migration:create -- migrations/MigrationName

# Run pending migrations
npm run migration:run

# Revert the last migration
npm run migration:revert
```

Migrations are stored in the `migrations/` directory and are automatically run on application startup in development mode.

## Docker

The service includes production-ready Docker containers with PostgreSQL integration.

### Using Docker Compose (Recommended)

The easiest way to run the service with all dependencies:

```bash
# Start all services (PostgreSQL + Key Service)
docker compose -f docker/docker-compose.yml up -d

# View logs
docker compose -f docker/docker-compose.yml logs -f

# Stop all services
docker compose -f docker/docker-compose.yml down

# Stop and remove volumes (cleans database)
docker compose -f docker/docker-compose.yml down -v
```

The Docker Compose setup includes:
- PostgreSQL 17 database with persistent storage
- Key Service with health checks
- Network isolation
- Volume mounting for signing keys

### Building Docker Image Manually

```bash
# Build production image
docker build -t key-service:latest -f docker/Dockerfile .

# Run with environment variables
docker run -p 3000:3000 \
  -e DB_HOST=postgres \
  -e DB_NAME=key_service \
  -e DB_USERNAME=postgres \
  -e DB_PASSWORD=postgres \
  key-service:latest
```

### Docker Health Checks

The container includes health checks that verify:
- Application is running
- HTTP server is responding
- Health endpoint returns 200 OK

### Docker Configuration

- **Dockerfile**: `docker/Dockerfile` - Multi-stage production build
- **Compose**: `docker/docker-compose.yml` - Full stack with PostgreSQL
- **Test Compose**: `docker/docker-compose.test.yml` - Test database only

## API Endpoints

### Sign Verifiable Credential

Sign a W3C Verifiable Credential with the specified signature format.

```
POST /sign/vc/:type
```

**Parameters:**

- `type`: Signature type - `jwt`, `data-integrity`, or `sd-jwt`

**Request Body:**

```json
{
  "verifiable": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential"],
    "issuer": "did:example:123",
    "issuanceDate": "2023-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:456",
      "name": "John Doe"
    }
  },
  "secrets": ["user-secret-key"],
  "identifier": "key-identifier"
}
```

**Response:**

Returns the signed credential in the format specified by the signature type.

### Sign Verifiable Presentation

Sign a W3C Verifiable Presentation with the specified signature format.

```
POST /sign/vp/:type
```

**Parameters:**

- `type`: Signature type - `jwt`, `data-integrity`, or `sd-jwt`

**Request Body:**

```json
{
  "verifiable": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "holder": "did:example:123",
    "verifiableCredential": [...]
  },
  "secrets": ["user-secret-key"],
  "identifier": "key-identifier",
  "challenge": "nonce-value",
  "domain": "example.com"
}
```

**Response:**

Returns the signed presentation in the format specified by the signature type.

### Generate Key Pair

Generate a new cryptographic key pair and store it encrypted in the database.

```
POST /generate
```

**Request Body:**

```json
{
  "secrets": ["user-secret-key"],
  "identifier": "key-identifier",
  "signatureType": "Ed25519",
  "keyType": "JWK"
}
```

**Parameters:**

- `secrets`: Array of 1-10 secrets for multi-layer encryption
- `identifier`: Unique identifier for the key (alphanumeric, `-_:.` allowed)
- `signatureType`: Algorithm - `Ed25519`, `ES256`, or `PS256`
- `keyType`: Key format - `JWK` or `VerificationKey2020`

**Response:**

Returns success confirmation without exposing the private key.

### Health Check

The service provides comprehensive health check endpoints optimized for Kubernetes:

#### `/health`

General health check endpoint that includes database connectivity check.

#### `/health/liveness`

Liveness probe endpoint for Kubernetes. Returns 200 if the application is running.

#### `/health/readiness`

Readiness probe endpoint for Kubernetes. Returns 200 if the application is ready to serve traffic (includes database connectivity check).

**Response Format:**

```json
{
  "status": "ok",
  "info": {
    "database": {
      "status": "up"
    }
  },
  "error": {},
  "details": {
    "database": {
      "status": "up"
    }
  }
}
```

## Sample Requests

### Generate a Key Pair

First, generate a key pair that will be used for signing:

```bash
curl -X POST http://localhost:3000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "secrets": ["my-secret-key"],
    "identifier": "my-signing-key",
    "signatureType": "Ed25519",
    "keyType": "JWK"
  }'
```

### Sign a Verifiable Credential (JWT)

```bash
curl -X POST http://localhost:3000/sign/vc/jwt \
  -H "Content-Type: application/json" \
  -d '{
    "verifiable": {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:123",
      "issuanceDate": "2023-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:456",
        "name": "John Doe"
      }
    },
    "secrets": ["my-secret-key"],
    "identifier": "my-signing-key"
  }'
```

### Sign a Verifiable Credential (Data Integrity)

```bash
curl -X POST http://localhost:3000/sign/vc/data-integrity \
  -H "Content-Type: application/json" \
  -d '{
    "verifiable": {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:123",
      "issuanceDate": "2023-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:example:456",
        "name": "John Doe"
      }
    },
    "secrets": ["my-secret-key"],
    "identifier": "my-signing-key"
  }'
```

### Sign a Verifiable Presentation

```bash
curl -X POST http://localhost:3000/sign/vp/jwt \
  -H "Content-Type: application/json" \
  -d '{
    "verifiable": {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiablePresentation"],
      "holder": "did:example:123",
      "verifiableCredential": []
    },
    "secrets": ["my-secret-key"],
    "identifier": "my-signing-key",
    "challenge": "random-nonce-12345",
    "domain": "example.com"
  }'
```

## Sample Responses

### Signed JWT Credential

**GS1 GO Sample**

```
eyJraWQiOiJkaWQ6d2ViOmNicHZzdmlwLXZjLmdzMXVzLm9yZyNJeXIwZndUdmRsRVJrOEVCWFZ1SXM3NjgyeW45ZGpjQng2aEdtemNhb2FzIiwiYWxnIjoiRVMyNTYifQ.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3JlZi5nczEub3JnL2dzMS92Yy9saWNlbnNlLWNvbnRleHQiXSwiaWQiOiJodHRwczovL2NicHZzdmlwLXZjLWFwaS5nczF1cy5vcmcvY3JlZGVudGlhbHMvMDgxMDE1OTU1IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkdTMUNvbXBhbnlQcmVmaXhMaWNlbnNlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6d2ViOmNicHZzdmlwLXZjLmdzMXVzLm9yZyIsIm5hbWUiOiJHUzEgVVMifSwibmFtZSI6IkdTMSBDb21wYW55IFByZWZpeCBMaWNlbnNlIiwiZGVzY3JpcHRpb24iOiJUSElTIEdTMSBESUdJVEFMIExJQ0VOU0UgQ1JFREVOVElBTCBJUyBGT1IgVEVTVElORyBQVVJQT1NFUyBPTkxZLiBBIEdTMSBDb21wYW55IFByZWZpeCBMaWNlbnNlIGlzIGlzc3VlZCBieSBhIEdTMSBNZW1iZXIgT3JnYW5pemF0aW9uIG9yIEdTMSBHbG9iYWwgT2ZmaWNlIGFuZCBhbGxvY2F0ZWQgdG8gYSB1c2VyIGNvbXBhbnkgb3IgdG8gaXRzZWxmIGZvciB0aGUgcHVycG9zZSBvZiBnZW5lcmF0aW5nIHRpZXIgMSBHUzEgaWRlbnRpZmljYXRpb24ga2V5cy4iLCJ2YWxpZEZyb20iOiIyMDI0LTAxLTI1VDEyOjMwOjAwLjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDp3ZWI6aGVhbHRoeXRvdHMubmV0Iiwib3JnYW5pemF0aW9uIjp7ImdzMTpwYXJ0eUdMTiI6IjA4MTAxNTk1NTAwMDAiLCJnczE6b3JnYW5pemF0aW9uTmFtZSI6IkhlYWx0aHkgVG90cyJ9LCJleHRlbmRzQ3JlZGVudGlhbCI6Imh0dHBzOi8vaWQuZ3MxLm9yZy92Yy9saWNlbnNlL2dzMV9wcmVmaXgvMDgiLCJsaWNlbnNlVmFsdWUiOiIwODEwMTU5NTUiLCJhbHRlcm5hdGl2ZUxpY2Vuc2VWYWx1ZSI6IjgxMDE1OTU1In0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2lkLmdzMS5vcmcvdmMvc2NoZW1hL3YxL2NvbXBhbnlwcmVmaXgiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9jYnB2c3ZpcC12Yy1hcGkuZ3MxdXMub3JnL3N0YXR1cy84MDFjNmNjNi00ZmM0LTRhYTMtYTM0Ny0zYjMxYTE3NWFjMTQjMTAwMTAiLCJ0eXBlIjoiQml0c3RyaW5nU3RhdHVzTGlzdEVudHJ5Iiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24iLCJzdGF0dXNMaXN0SW5kZXgiOiIxMDAxMCIsInN0YXR1c0xpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly9jYnB2c3ZpcC12Yy1hcGkuZ3MxdXMub3JnL3N0YXR1cy84MDFjNmNjNi00ZmM0LTRhYTMtYTM0Ny0zYjMxYTE3NWFjMTQvIn19.qP5k8uO9yuQdIWSl9ws5FlRFmUOzxgNgtWs8VFifVEjLWTUx1Hc1m4fIet7EF0njlelNy8G5SZarW7DDaWiJDA
```

### Signed Data Integrity Credential

```json
{
  "signedCredential": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential"],
    "issuer": "did:example:123",
    "issuanceDate": "2023-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:456",
      "name": "John Doe"
    },
    "proof": {
      "type": "Ed25519Signature2020",
      "created": "2023-01-01T00:00:00Z",
      "verificationMethod": "did:example:123#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
    }
  }
}
```

## Security Features

### Input Validation

The service implements comprehensive input validation to prevent injection attacks and buffer overflows:

- **Global ValidationPipe**: Enabled with security-focused configuration
- **DTO Validation**: All API requests validated using class-validator decorators
- **Security Constraints**:
  - Identifier max length: 500 characters
  - Secret max length: 1000 characters
  - Array size limits: 1-10 secrets per request
  - Pattern matching: Identifiers only allow alphanumeric characters and `-_:.`
  - Enum validation for signature and key types

### Multi-Layer Encryption

Keys are encrypted using multiple secrets to ensure security even if one secret is compromised:

- **Service Secret**: Application-level encryption key
- **Key Access Secret**: Per-key encryption secret
- **User Secrets**: User-provided secrets (1-10 per key)

### Failed Attempt Protection

- Rate limiting on key access attempts
- Configurable cooldown mechanisms
- Protection against brute force attacks

### Zero-Knowledge Architecture

- Private keys never exposed in decrypted form
- Keys only decrypted in memory during signing operations
- Secure memory clearing after use

## Key Dependencies

### Core Framework
- **@nestjs/core** & **@nestjs/common**: NestJS framework
- **@nestjs/typeorm**: TypeORM integration for database operations
- **@nestjs/terminus**: Health check endpoints

### Cryptography & Verifiable Credentials
- **@digitalbazaar/vc**: W3C Verifiable Credentials implementation
- **@digitalbazaar/ed25519-signature-2020**: Ed25519 signature suite for Data Integrity proofs
- **@digitalbazaar/ed25519-verification-key-2020**: Ed25519 key handling
- **jose**: JWT operations (JWT-VC signing)
- **@noble/curves**: Cryptographic curve operations
- **jsonld-signatures**: JSON-LD signature support

### Validation & Security
- **class-validator**: DTO validation decorators
- **class-transformer**: Request payload transformation
- **node-cache**: In-memory caching for failed attempts

### Database
- **typeorm**: TypeScript ORM
- **pg**: PostgreSQL client

## Project Structure

```
key-service/
├── apps/app/src/
│   ├── config/              # Configuration (CORS, database, rate limiting)
│   ├── filters/             # Global exception handling
│   ├── health/              # Health check endpoints
│   ├── key-services/        # Key management services
│   │   ├── key.service.ts   # Core key operations
│   │   ├── key-storage.service.ts
│   │   ├── secret.service.ts
│   │   └── failed-attempts-cache.service.ts
│   ├── signing-services/    # Credential signing services
│   │   ├── jwt-signing.service.ts
│   │   └── data-integrity-signing.service.ts
│   ├── types/               # TypeScript type definitions
│   ├── utils/               # Utility functions and logging
│   └── main.ts              # Application entry point
├── docker/                  # Docker configuration
├── migrations/              # Database migrations
├── docs/                    # Documentation
└── scripts/                 # Build and release scripts
```

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See the [LICENSE](LICENSE) file for details.

## Author

**Christian Fries**

## Repository

Repository: `git@gitlab.eecc.info:ssi/key-service.git`

## Contributing

This is a security-critical component. All changes should be thoroughly tested and reviewed for security implications.

## Documentation

- [Security and Key Management Concept](docs/security_and_key_management_concept.md)
- [Changelog](CHANGELOG.md)
- [Security Report](SECURITY_REPORT.md)
