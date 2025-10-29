# Testing Strategy & Patterns

## Test Architecture

### Two-Tier Testing Approach

#### Unit Tests (Mocked Dependencies)
- **Location**: Alongside source files (`.spec.ts`)
- **Command**: `npm run test:unit`
- **Purpose**: Business logic validation with mocked external dependencies
- **Configuration**: `apps/app/test/jest-unit.json`

#### Integration Tests (Real Database)
- **Location**: `apps/app/test/app.e2e-spec.ts`
- **Command**: `npm run test:e2e`
- **Purpose**: Full HTTP request/response cycle with real PostgreSQL
- **Configuration**: `apps/app/test/jest-e2e.json`

## Test Database Management

### Automated Test Database
```bash
# Start test database (automatically managed)
npm run test:db:start

# Stop test database
npm run test:db:stop

# Run tests with automatic database lifecycle
npm run test:unit:with-db
```

### Test Database Configuration
- **Container**: PostgreSQL 17 in Docker
- **Config File**: `apps/app/test/test-database.config.ts`
- **Compose File**: `docker/docker-compose.test.yml`
- **Isolation**: Separate database for testing

## Testing Patterns

### Service Testing
- Mock external dependencies (database, external APIs)
- Focus on business logic validation
- Test error conditions and edge cases
- Verify proper async/await handling

### E2E Testing Strategy  
- Full HTTP request/response testing
- Real database interactions
- Credential signing workflow validation
- API endpoint contract verification

### Test Utilities
- **Setup File**: `apps/app/test/test-setup.ts`
- Common test fixtures and helpers
- Database seeding utilities
- Mock service factories

## Coverage & Quality

### Test Coverage
```bash
npm run test:unit:coverage    # Unit test coverage
npm run test:e2e:coverage     # E2E test coverage  
npm run test:coverage         # Combined coverage
```

### Quality Gates
- TypeScript strict mode enforcement
- Comprehensive error scenario testing
- Security-focused test cases
- Performance validation for crypto operations

## Key Test Areas

### Cryptographic Operations
- Key generation validation
- Signature verification
- Multi-algorithm support (Ed25519, ES256, PS256)
- Error handling for invalid keys/secrets
- Verifiable Credential (VC) signing with JWT and Data Integrity
- Verifiable Presentation (VP) signing:
  - JWT: Enveloped credentials with multiple algorithms (Ed25519, ES256, PS256)
  - Data Integrity: Embedded credentials with Ed25519 proofs, challenge/domain support

### API Contract Testing
- Request/response validation
- Error response formatting
- HTTP status code correctness
- Parameter validation (enums, types)

### Security Testing
- Failed attempt rate limiting
- Secret validation requirements
- Encryption/decryption workflows
- Database security (no plaintext secrets)

### Database Integration
- Entity persistence
- Migration testing
- Connection handling
- Transaction rollback scenarios

## Test Commands Reference

```bash
# Run all tests
npm test

# Individual test suites
npm run test:unit         # Unit tests only
npm run test:e2e          # Integration tests only

# Watch mode
npm run test:unit:watch   # Unit tests with file watching
npm run test:e2e:watch    # E2E tests with file watching

# Coverage reports
npm run test:unit:coverage
npm run test:e2e:coverage
npm run test:coverage
```