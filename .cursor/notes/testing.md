# Testing Strategy & Patterns

## Prerequisites

**PostgreSQL is required for unit and E2E tests.** Many `*.spec.ts` suites use a real TypeORM connection (key, JWT, Data Integrity, app service), not only mocks.

```bash
npm run test:db:start   # postgres:17 on localhost:5433 / key_service_test
npm run test:db:stop
```

- Compose: `docker/docker-compose.test.yml`
- Jest setup (`apps/app/test/test-setup.ts`) aligns `TEST_DB_*` and `DB_*` (plain TCP, SSL off)
- One-shot wrappers: `test:with-db`, `test:unit:with-db`, `test:e2e:with-db`

## Test Architecture

### Unit Tests
- **Location**: Alongside source (`*.spec.ts`)
- **Command**: `npm run test:unit` (DB must be up)
- **Config**: `apps/app/test/jest-unit.json`
- Mix of mocked suites and DB-backed integration-style specs

### E2E Tests
- **Location**: `apps/app/test/*.e2e-spec.ts`
- **Command**: `npm run test:e2e` (same test DB via `DB_*` from test-setup)
- **Config**: `apps/app/test/jest-e2e.json`
- Full HTTP stack via `AppModule`

## Commands

```bash
npm run test:db:start
npm test                      # unit then e2e
npm run test:unit
npm run test:e2e
npm run test:unit:watch
npm run test:coverage
npm run test:with-db          # start → test → stop
npm run test:unit:with-db
npm run test:e2e:with-db
npm run test:perf              # signing timings; not part of `npm test`
```

CI (`.github/workflows/ci-cd.yml`) runs `test:unit` with a Postgres 17 service on port 5433.

## Patterns

### Env vars before imports
Config modules that read `process.env` at import time need vars set at module top level (before imports), not in `beforeAll`. See `payload-encryption.service.spec.ts`.

### Signing key
`SecretService` requires a signing key file (≥32 chars). E2E uses a temp key from `test-setup.ts`; some unit tests mock `fs.readFileSync`.

### Service / crypto coverage
- Key generation, multi-algorithm signing (Ed25519, ES256, PS256)
- JWT: VC/VP `iss` on JWS protected header; OID4VCI PoP keeps `iss` in body
- Data Integrity: proofs, challenge/domain
- Failed attempts, encryption, validation e2e

## Signing performance

`apps/app/test/signing.perf.spec.ts` (`npm run test:perf`, Jest config `apps/app/test/jest-perf.json`). Excluded from unit and e2e. Needs the test DB.

Each production sign pays three PBKDF2 derivations (`PBKDF2_ITERATIONS`, default 100000) unless `SecretService` still holds them: identifier hash, private-key decrypt, public-key decrypt, plus one indexed `findOne`. Hits reset a 10 second TTL. Cold samples in the perf spec call `clearDerivationCache()`. There is no decrypted-key cache. A cold sign is ~50 ms of PBKDF2; the database read is ~2 ms; a warm JWT sign is a few milliseconds; a cached-key JWT signature is ~0.2 ms. Warm Data Integrity canonicalization is a few milliseconds; the first sign after `JsonLdContextCache.reset()` is slower (~20–30 ms).

## Related files

- `apps/app/test/test-database.config.ts` — shared TypeORM test options
- `apps/app/test/test-setup.ts` — global Jest setup
- `apps/app/test/signing.perf.spec.ts` — JWT and Data Integrity signing timings (`npm run test:perf`)
- README “Local Testing” section
