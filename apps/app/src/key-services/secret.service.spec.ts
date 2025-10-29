import { Test, TestingModule } from "@nestjs/testing";
import { SecretService } from "./secret.service";
import * as fs from "fs";
import * as path from "path";
import { logError } from "../utils/log/logger";

// Mock the logger
jest.mock("../utils/log/logger", () => ({
  logError: jest.fn(),
}));

// Mock fs module
jest.mock("fs");

describe("SecretService", () => {
  let service: SecretService;
  let originalSigningKeyPath: string | undefined;
  let originalNodeEnv: string | undefined;

  const mockSecrets = ["test-secret-1", "test-secret-2"];
  const validSecret = "this-is-a-valid-secret-key-with-32-plus-characters";
  const shortSecret = "short";

  beforeEach(async () => {
    // Store original environment variables
    originalSigningKeyPath = process.env.SIGNING_KEY_PATH;
    originalNodeEnv = process.env.NODE_ENV;

    // Clear all mocks
    jest.clearAllMocks();

    // Mock fs.readFileSync to return a valid secret by default
    (fs.readFileSync as jest.Mock).mockReturnValue(validSecret);
  });

  afterEach(() => {
    // Restore original environment variables
    if (originalSigningKeyPath !== undefined) {
      process.env.SIGNING_KEY_PATH = originalSigningKeyPath;
    } else {
      delete process.env.SIGNING_KEY_PATH;
    }

    if (originalNodeEnv !== undefined) {
      process.env.NODE_ENV = originalNodeEnv;
    } else {
      delete process.env.NODE_ENV;
    }
  });

  describe("constructor", () => {
    it("should read secret from default path when SIGNING_KEY_PATH is not set", () => {
      delete process.env.SIGNING_KEY_PATH;

      const newService = new SecretService();

      expect(fs.readFileSync).toHaveBeenCalledWith(
        path.resolve("/run/secrets/signing-key"),
        "utf8"
      );
    });

    it("should read secret from custom path when SIGNING_KEY_PATH is set", () => {
      process.env.SIGNING_KEY_PATH = "/custom/path/key";

      const newService = new SecretService();

      expect(fs.readFileSync).toHaveBeenCalledWith(
        path.resolve("/custom/path/key"),
        "utf8"
      );
    });

    it("should trim whitespace from the secret", () => {
      (fs.readFileSync as jest.Mock).mockReturnValue(`  ${validSecret}  `);

      const newService = new SecretService();

      // Test by trying to encrypt/decrypt to ensure the service works
      const encrypted = newService.encrypt("test-data", mockSecrets);
      const decrypted = newService.decrypt(encrypted, mockSecrets);
      expect(decrypted).toBe("test-data");
    });

    it("should throw error if secret is too short", () => {
      process.env.NODE_ENV = "production";
      (fs.readFileSync as jest.Mock).mockReturnValue(shortSecret);

      expect(() => new SecretService()).toThrow(
        "Cannot start service without proper signing key in production"
      );
    });

    it("should throw error if secret is empty", () => {
      process.env.NODE_ENV = "production";
      (fs.readFileSync as jest.Mock).mockReturnValue("");

      expect(() => new SecretService()).toThrow(
        "Cannot start service without proper signing key in production"
      );
    });

    it("should throw error if secret becomes too short after trimming", () => {
      process.env.NODE_ENV = "production";
      // Secret with lots of whitespace but short actual content
      (fs.readFileSync as jest.Mock).mockReturnValue("   short   ");

      expect(() => new SecretService()).toThrow(
        "Cannot start service without proper signing key in production"
      );
    });

    it("should log error and throw in production when file read fails", () => {
      process.env.NODE_ENV = "production";
      (fs.readFileSync as jest.Mock).mockImplementation(() => {
        throw new Error("File not found");
      });

      expect(() => new SecretService()).toThrow(
        "Cannot start service without proper signing key in production"
      );
      expect(logError).toHaveBeenCalledWith(
        expect.stringContaining("Failed to read signing key")
      );
    });

    it("should use fallback secret in development when file read fails", () => {
      process.env.NODE_ENV = "development";
      (fs.readFileSync as jest.Mock).mockImplementation(() => {
        throw new Error("File not found");
      });

      const newService = new SecretService();

      expect(logError).toHaveBeenCalledWith(
        expect.stringContaining("Failed to read signing key")
      );

      // Test that the service still works with fallback secret
      const encrypted = newService.encrypt("test-data", mockSecrets);
      const decrypted = newService.decrypt(encrypted, mockSecrets);
      expect(decrypted).toBe("test-data");
    });

    it("should use fallback secret when NODE_ENV is not set and file read fails", () => {
      delete process.env.NODE_ENV;
      (fs.readFileSync as jest.Mock).mockImplementation(() => {
        throw new Error("File not found");
      });

      const newService = new SecretService();

      expect(logError).toHaveBeenCalledWith(
        expect.stringContaining("Failed to read signing key")
      );

      // Test that the service still works with fallback secret
      const encrypted = newService.encrypt("test-data", mockSecrets);
      const decrypted = newService.decrypt(encrypted, mockSecrets);
      expect(decrypted).toBe("test-data");
    });
  });

  describe("encrypt and decrypt", () => {
    beforeEach(async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [SecretService],
      }).compile();

      service = module.get<SecretService>(SecretService);
    });

    it("should encrypt and decrypt data successfully", () => {
      const testData = "sensitive-data-to-encrypt";

      const encrypted = service.encrypt(testData, mockSecrets);
      const decrypted = service.decrypt(encrypted, mockSecrets);

      expect(decrypted).toBe(testData);
    });

    it("should produce different encrypted outputs for same data", () => {
      const testData = "test-data";

      const encrypted1 = service.encrypt(testData, mockSecrets);
      const encrypted2 = service.encrypt(testData, mockSecrets);

      expect(encrypted1).not.toBe(encrypted2);

      // But both should decrypt to the same data
      expect(service.decrypt(encrypted1, mockSecrets)).toBe(testData);
      expect(service.decrypt(encrypted2, mockSecrets)).toBe(testData);
    });

    it("should encrypt data with correct format (salt:iv:authTag:encryptedData)", () => {
      const testData = "test-data";

      const encrypted = service.encrypt(testData, mockSecrets);
      const parts = encrypted.split(":");

      expect(parts).toHaveLength(4);
      // Salt should be 64 hex chars (32 bytes)
      expect(parts[0]).toHaveLength(64);
      // IV should be 32 hex chars (16 bytes)
      expect(parts[1]).toHaveLength(32);
      // Auth tag should be 32 hex chars (16 bytes)
      expect(parts[2]).toHaveLength(32);
      // Encrypted data should be hex string
      expect(parts[3]).toMatch(/^[0-9a-f]+$/);
    });

    it("should fail to decrypt with wrong secrets", () => {
      const testData = "test-data";
      const wrongSecrets = ["wrong-secret-1", "wrong-secret-2"];

      const encrypted = service.encrypt(testData, mockSecrets);

      expect(() => service.decrypt(encrypted, wrongSecrets)).toThrow();
    });

    it("should fail to decrypt with invalid format", () => {
      const invalidFormats = [
        "invalid",
        "salt:iv:tag", // Missing encrypted data
        "salt:iv:tag:data:extra", // Too many parts
        "invalid:format", // Too few parts
      ];

      invalidFormats.forEach((invalidFormat) => {
        expect(() => service.decrypt(invalidFormat, mockSecrets)).toThrow(
          "Invalid encrypted data format"
        );
      });
    });

    it("should handle empty secrets array", () => {
      const testData = "test-data";
      const emptySecrets: string[] = [];

      const encrypted = service.encrypt(testData, emptySecrets);
      const decrypted = service.decrypt(encrypted, emptySecrets);

      expect(decrypted).toBe(testData);
    });

    it("should be deterministic with same secrets order", () => {
      const testData = "test-data";
      const secrets1 = ["secret-a", "secret-b"];
      const secrets2 = ["secret-b", "secret-a"]; // Different order

      const encrypted1 = service.encrypt(testData, secrets1);
      const encrypted2 = service.encrypt(testData, secrets2);

      // Should be able to decrypt with either order since secrets are sorted
      expect(service.decrypt(encrypted1, secrets2)).toBe(testData);
      expect(service.decrypt(encrypted2, secrets1)).toBe(testData);
    });

    it("should handle unicode data", () => {
      const testData = "Hello 世界 🌍 café naïve résumé";

      const encrypted = service.encrypt(testData, mockSecrets);
      const decrypted = service.decrypt(encrypted, mockSecrets);

      expect(decrypted).toBe(testData);
    });

    it("should handle long data", () => {
      const testData = "x".repeat(10000);

      const encrypted = service.encrypt(testData, mockSecrets);
      const decrypted = service.decrypt(encrypted, mockSecrets);

      expect(decrypted).toBe(testData);
    });

    it("should encrypt and decrypt JavaScript objects", () => {
      const testObject = {
        id: 123,
        name: "Test User",
        email: "test@example.com",
        metadata: {
          created: "2023-01-01T00:00:00Z",
          active: true,
          roles: ["user", "admin"],
          settings: {
            theme: "dark",
            notifications: true,
          },
        },
        tags: ["tag1", "tag2", "tag3"],
        nullable: null,
      };

      const serialized = JSON.stringify(testObject);
      const encrypted = service.encrypt(serialized, mockSecrets);
      const decrypted = service.decrypt(encrypted, mockSecrets);
      const parsed = JSON.parse(decrypted);

      expect(parsed).toEqual(testObject);
      expect(parsed.id).toBe(123);
      expect(parsed.name).toBe("Test User");
      expect(parsed.metadata.roles).toEqual(["user", "admin"]);
      expect(parsed.metadata.settings.theme).toBe("dark");
      expect(parsed.nullable).toBeNull();
    });
  });
});
