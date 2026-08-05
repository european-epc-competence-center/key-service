// Global test setup
import "reflect-metadata";
import { jest } from "@jest/globals";
import { webcrypto } from "node:crypto";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// Polyfill crypto for environments where it's not available
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as any;
}

// Point AppModule (e2e) and any DB_* readers at the same test PostgreSQL as unit specs.
// Requires `npm run test:db:start` (or CI postgres service) — see docker/docker-compose.test.yml.
const testDbHost = process.env.TEST_DB_HOST || "localhost";
const testDbPort = process.env.TEST_DB_PORT || "5433";
const testDbUser =
  process.env.TEST_DB_USERNAME || process.env.TEST_DB_USER || "postgres";
const testDbPassword = process.env.TEST_DB_PASSWORD || "postgres";
const testDbName = process.env.TEST_DB_NAME || "key_service_test";

process.env.TEST_DB_HOST = testDbHost;
process.env.TEST_DB_PORT = testDbPort;
process.env.TEST_DB_USERNAME = testDbUser;
process.env.TEST_DB_USER = testDbUser;
process.env.TEST_DB_PASSWORD = testDbPassword;
process.env.TEST_DB_NAME = testDbName;

process.env.DB_HOST = testDbHost;
process.env.DB_PORT = testDbPort;
process.env.DB_USERNAME = testDbUser;
process.env.DB_PASSWORD = testDbPassword;
process.env.DB_NAME = testDbName;
process.env.DB_SSL = process.env.DB_SSL || "false";

// E2E tests bootstrap AppModule without mocking fs — provide a temporary signing key.
if (!process.env.SIGNING_KEY_PATH) {
  const signingKeyPath = path.join(
    os.tmpdir(),
    `key-service-test-signing-key-${process.pid}`
  );
  fs.writeFileSync(signingKeyPath, crypto.randomBytes(48).toString("base64"), {
    mode: 0o600,
  });
  process.env.SIGNING_KEY_PATH = signingKeyPath;
}

// Increase Jest timeout for database operations
jest.setTimeout(120000);

// Set up global test environment
beforeEach(() => {
  jest.clearAllMocks();
});
