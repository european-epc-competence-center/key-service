import { Test, TestingModule } from "@nestjs/testing";
import { PayloadEncryptionService } from "./payload-encryption.service";

describe("PayloadEncryptionService", () => {
  let service: PayloadEncryptionService;
  const testSecret = "12345678901234567890123456789012"; // 32 characters

  beforeAll(() => {
    // Set up environment for testing
    process.env.INTER_SERVICE_ENCRYPTION_ENABLED = "true";
    process.env.INTER_SERVICE_SHARED_SECRET = testSecret;
  });

  afterAll(() => {
    // Clean up
    delete process.env.INTER_SERVICE_ENCRYPTION_ENABLED;
    delete process.env.INTER_SERVICE_SHARED_SECRET;
  });

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PayloadEncryptionService],
    }).compile();

    service = module.get<PayloadEncryptionService>(PayloadEncryptionService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  it("should report enabled status correctly", () => {
    expect(service.isEnabled()).toBe(true);
  });

  describe("encrypt and decrypt", () => {
    it("should encrypt and decrypt a simple string", () => {
      const plaintext = "Hello, World!";
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
      expect(encrypted).not.toBe(plaintext);
    });

    it("should encrypt and decrypt a JSON string", () => {
      const jsonStr = JSON.stringify({ message: "test", value: 123 });
      const encrypted = service.encrypt(jsonStr);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(jsonStr);
    });

    it("should encrypt and decrypt empty string", () => {
      const plaintext = "";
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it("should encrypt and decrypt unicode characters", () => {
      const plaintext = "Hello 世界 🌍 Привет";
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it("should produce different ciphertext for same plaintext", () => {
      const plaintext = "Same message";
      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);

      // Different because of random IV
      expect(encrypted1).not.toBe(encrypted2);

      // But both decrypt to same plaintext
      expect(service.decrypt(encrypted1)).toBe(plaintext);
      expect(service.decrypt(encrypted2)).toBe(plaintext);
    });

    it("should return base64-encoded string", () => {
      const plaintext = "test";
      const encrypted = service.encrypt(plaintext);

      // Should be valid base64
      expect(() => Buffer.from(encrypted, "base64")).not.toThrow();

      // Should decode to contain colons (our format)
      const decoded = Buffer.from(encrypted, "base64").toString("utf8");
      expect(decoded).toContain(":");
    });
  });

  describe("encryptJson and decryptJson", () => {
    it("should encrypt and decrypt a JSON object", () => {
      const payload = {
        message: "test",
        value: 123,
        nested: { key: "value" },
      };

      const encrypted = service.encryptJson(payload);
      const decrypted = service.decryptJson(encrypted);

      expect(decrypted).toEqual(payload);
    });

    it("should handle arrays", () => {
      const payload = [1, 2, 3, "test", { key: "value" }];

      const encrypted = service.encryptJson(payload);
      const decrypted = service.decryptJson(encrypted);

      expect(decrypted).toEqual(payload);
    });

    it("should handle complex nested objects", () => {
      const payload = {
        user: {
          id: 123,
          name: "John Doe",
          roles: ["admin", "user"],
          metadata: {
            createdAt: "2025-10-30",
            settings: {
              theme: "dark",
              notifications: true,
            },
          },
        },
      };

      const encrypted = service.encryptJson(payload);
      const decrypted = service.decryptJson(encrypted);

      expect(decrypted).toEqual(payload);
    });
  });

  describe("error handling", () => {
    it("should throw error on invalid encrypted data format", () => {
      const invalidData = Buffer.from("invalid:format", "utf8").toString(
        "base64"
      );

      expect(() => service.decrypt(invalidData)).toThrow(
        "Invalid encrypted data format"
      );
    });

    it("should throw error on corrupted ciphertext", () => {
      const plaintext = "test";
      const encrypted = service.encrypt(plaintext);

      // Corrupt the encrypted data
      const decoded = Buffer.from(encrypted, "base64").toString("utf8");
      const parts = decoded.split(":");
      parts[2] = "corrupted";
      const corrupted = Buffer.from(parts.join(":"), "utf8").toString("base64");

      expect(() => service.decrypt(corrupted)).toThrow();
    });

    it("should throw error on invalid IV size", () => {
      // Create data with invalid IV
      const invalidData = Buffer.from(
        "aabbcc:1234567890abcdef1234567890abcdef:ciphertext",
        "utf8"
      ).toString("base64");

      expect(() => service.decrypt(invalidData)).toThrow("Invalid IV size");
    });

    it("should throw error on invalid auth tag size", () => {
      // Create data with 12-byte IV but invalid auth tag
      const invalidData = Buffer.from(
        "aabbccddeeff00112233:aabbcc:ciphertext",
        "utf8"
      ).toString("base64");

      expect(() => service.decrypt(invalidData)).toThrow(
        "Invalid auth tag size"
      );
    });

    it("should throw error on tampered data (auth tag verification)", () => {
      const plaintext = "sensitive data";
      const encrypted = service.encrypt(plaintext);

      // Tamper with the ciphertext
      const decoded = Buffer.from(encrypted, "base64").toString("utf8");
      const parts = decoded.split(":");
      const ciphertext = parts[2];
      // Flip a bit in the ciphertext
      const tamperedCiphertext =
        ciphertext.slice(0, -1) +
        (parseInt(ciphertext.slice(-1), 16) ^ 1).toString(16);
      parts[2] = tamperedCiphertext;

      const tampered = Buffer.from(parts.join(":"), "utf8").toString("base64");

      // Should throw because auth tag verification will fail
      expect(() => service.decrypt(tampered)).toThrow();
    });
  });

  describe("configuration", () => {
    it("should throw error if encryption is enabled but no secret configured", () => {
      process.env.INTER_SERVICE_ENCRYPTION_ENABLED = "true";
      delete process.env.INTER_SERVICE_SHARED_SECRET;

      expect(() => {
        // Force re-import to trigger config validation
        jest.resetModules();
        require("../config/payload-encryption.config");
      }).toThrow();

      // Restore
      process.env.INTER_SERVICE_SHARED_SECRET = testSecret;
    });
  });

  describe("disabled encryption", () => {
    let disabledService: PayloadEncryptionService;

    beforeEach(async () => {
      process.env.INTER_SERVICE_ENCRYPTION_ENABLED = "false";
      delete process.env.INTER_SERVICE_SHARED_SECRET;

      // Need to reload module to get new config
      jest.resetModules();
      const { PayloadEncryptionService } = require("./payload-encryption.service");

      const module: TestingModule = await Test.createTestingModule({
        providers: [PayloadEncryptionService],
      }).compile();

      disabledService = module.get<PayloadEncryptionService>(
        PayloadEncryptionService
      );
    });

    afterEach(() => {
      process.env.INTER_SERVICE_ENCRYPTION_ENABLED = "true";
      process.env.INTER_SERVICE_SHARED_SECRET = testSecret;
    });

    it("should report disabled status", () => {
      expect(disabledService.isEnabled()).toBe(false);
    });

    it("should throw error when trying to encrypt with disabled service", () => {
      expect(() => disabledService.encrypt("test")).toThrow(
        "Inter-service encryption is not enabled or configured"
      );
    });

    it("should throw error when trying to decrypt with disabled service", () => {
      expect(() => disabledService.decrypt("test")).toThrow(
        "Inter-service encryption is not enabled or configured"
      );
    });
  });
});

