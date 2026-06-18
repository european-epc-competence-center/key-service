// Global test setup
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
