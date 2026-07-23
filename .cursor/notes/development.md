# Development Guide

## Development Workflow

### Getting Started
```bash
npm install           # Install dependencies
npm run dev          # Start development server with hot reload
npm run test:db:start # Start test PostgreSQL database
```

### Code Organization

#### Service Pattern
- Services in `apps/app/src/` follow NestJS dependency injection
- Clear separation: KeyService → KeyStorageService → Database
- Each service has focused responsibility

#### Type-First Development
- All types defined in `apps/app/src/types/`
- Strong TypeScript typing throughout
- Enums for API parameters (`SignType`, `KeyType`)

#### Configuration Management
- Environment-based configuration in `apps/app/src/config/`
- No hardcoded values in business logic
- Centralized config files per concern

## Testing Strategy

### Prerequisite: test database
```bash
npm run test:db:start   # localhost:5433 / key_service_test
```
Unit and E2E both need this DB. One-shot: `npm run test:with-db` / `test:unit:with-db` / `test:e2e:with-db`.

### Unit Tests
- `npm run test:unit` (DB required — several suites use real TypeORM)
- Located alongside source (`.spec.ts`)

### Integration Tests (E2E)
- `npm run test:e2e` — same test DB (`DB_*` set in `test-setup.ts`)
- Full HTTP request/response cycle

See [testing.md](./testing.md) for commands and patterns.

## Build & Release

### Build Process
- TypeScript compilation with `nest build`
- Migration compilation included in build
- Production-ready bundle output

### Release Management
- Automated release script in `scripts/release.js`
- Semantic versioning (patch/minor/major)
- CHANGELOG.md automatically updated
- Version bumping integrated with git tags

### Version Commands
```bash
npm run release:patch  # Bug fixes
npm run release:minor  # New features
npm run release:major  # Breaking changes
```

## Code Style & Patterns

### NestJS Conventions
- Decorator-based architecture (`@Injectable`, `@Controller`)
- Module-based organization
- Dependency injection throughout

### Error Handling
- Custom exceptions in `apps/app/src/types/custom-exceptions.ts`
- Global exception filter for consistent API responses
- Proper HTTP status code mapping

### Async Patterns
- Promise-based service methods
- Proper error propagation
- Clean async/await usage

## Database Development

### Migration Workflow
```bash
npm run migration:generate  # Generate migration from entity changes
npm run migration:run      # Apply pending migrations
npm run migration:revert   # Rollback last migration
```

### Entity Management
- TypeORM entities in `apps/app/src/key-services/entities/`
- Database configuration in `apps/app/src/config/database.config.ts`
- Migration files in `migrations/` directory

## Dependencies & Security

- Direct versions in `package.json`; transitive CVEs via `overrides` (see `package.json`): `form-data`, `multer`, `undici` (pin `<7` — v8 breaks Jest), `js-yaml` (>=4.3.0), `brace-expansion` (per-major: 1.1.16 / 2.1.2 / 5.0.7), `body-parser` (>=2.3.0), `fast-uri` (>=3.1.4)
- Hold majors that break peers: `typescript` 5.x (ts-jest), `@types/node` 24.x, `@noble/curves` 1.x, `uint8arrays` 3.x; ignore npm `typeorm@1.x` (unrelated/yanked line — stay on `0.3.x`)
- `npm audit fix` for non-breaking fixes; avoid `npm audit fix --force` (downgrades NestJS/Jest)
- Node engine: `>=24.0.0`

## Environment Setup

### Required Environment Variables
- Database connection (DB_HOST, DB_PORT, DB_USERNAME, DB_PASSWORD, DB_NAME)
- Application config (NODE_ENV, SIGNING_KEY_PATH)
- CORS settings (optional, with defaults)
- Docker Compose: run `npm run docker:signing-key` before first `docker compose up` (creates gitignored `docker/signing-key`)
- Local `npm run dev` / `npm run start`: same script auto-generates `docker/signing-key` and sets `SIGNING_KEY_PATH`

### Development vs Production
- Development: Hot reload, detailed logging, permissive CORS
- Production: Optimized build, restricted CORS, minimal logging