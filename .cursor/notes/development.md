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

### Unit Tests
- Run with `npm run test:unit`
- Mock external dependencies
- Focus on business logic validation
- Located alongside source files (`.spec.ts`)

### Integration Tests (E2E)
- Run with `npm run test:e2e`
- Uses real PostgreSQL database
- Full HTTP request/response cycle testing
- Automatic database setup/teardown

### Test Database
- Separate test database configuration
- Docker Compose for isolated testing
- Clean slate for each test run

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

## Environment Setup

### Required Environment Variables
- Database connection (DB_HOST, DB_PORT, DB_USERNAME, DB_PASSWORD, DB_NAME)
- Application config (NODE_ENV, SIGNING_KEY_PATH)
- CORS settings (optional, with defaults)

### Development vs Production
- Development: Hot reload, detailed logging, permissive CORS
- Production: Optimized build, restricted CORS, minimal logging