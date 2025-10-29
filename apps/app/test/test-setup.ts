// Global test setup
import { jest } from "@jest/globals";
import { webcrypto } from "node:crypto";

// Polyfill crypto for environments where it's not available
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as any;
}

// Increase Jest timeout for database operations
jest.setTimeout(120000);

// Set up global test environment
beforeEach(() => {
  jest.clearAllMocks();
});
