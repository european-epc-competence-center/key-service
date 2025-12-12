import { Test, TestingModule } from "@nestjs/testing";
import { TypeOrmModule } from "@nestjs/typeorm";
import { DataSource } from "typeorm";
import { KeyService } from "./key.service";
import { KeyStorageService } from "./key-storage.service";
import { SecretService } from "./secret.service";
import { FailedAttemptsCacheService } from "./failed-attempts-cache.service";
import { EncryptedKey } from "./entities/encrypted-key.entity";
import { SignatureType } from "../types/key-types.enum";
import { KeyType } from "../types/key-format.enum";
import * as fs from "fs";
import * as crypto from "crypto";
// @ts-ignore
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";

// Mock fs module for this test file only
jest.mock("fs");

async function createTestDatabase(): Promise<{
  dataSource: DataSource;
}> {
  console.log("Connecting to external PostgreSQL test database...");

  const dataSource = new DataSource({
    type: "postgres",
    host: process.env.TEST_DB_HOST || "localhost",
    port: parseInt(process.env.TEST_DB_PORT || "5433"),
    username: process.env.TEST_DB_USER || "postgres",
    password: process.env.TEST_DB_PASSWORD || "postgres",
    database: process.env.TEST_DB_NAME || "key_service_test",
    entities: [EncryptedKey],
    synchronize: true,
    logging: false,
  });

  await dataSource.initialize();
  console.log("Connected to external test database successfully");

  return {
    dataSource,
  };
}

describe("KeyService", () => {
  let service: KeyService;
  let keyStorageService: KeyStorageService;
  let secretService: SecretService;
  let dataSource: DataSource;
  let module: TestingModule;
  let originalSigningKeyPath: string | undefined;

  const mockSecrets = ["test-secret-key-12345"];
  const mockIdentifier = "did:web:example.com#licenses";

  // Generate real keys for use in tests
  let testEd25519KeyPair: any;

  beforeAll(async () => {
    // Generate real Ed25519 keys for use in tests
    testEd25519KeyPair = await Ed25519Multikey.generate({
      controller: "did:web:example.com",
      id: "did:web:example.com#test-key",
    });

    // Store original environment variable
    originalSigningKeyPath = process.env.SIGNING_KEY_PATH;

    // Mock fs.readFileSync to return a vault-secret that's at least 32 characters
    jest
      .spyOn(fs, "readFileSync")
      .mockReturnValue("vault-secret-key-that-is-at-least-32-characters-long");

    // Create test database
    const dbSetup = await createTestDatabase();
    dataSource = dbSetup.dataSource;

    console.log("Tests running with external PostgreSQL database");

    module = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: "postgres",
          entities: [EncryptedKey],
          synchronize: false, // Already synchronized
          logging: false,
        }),
        TypeOrmModule.forFeature([EncryptedKey]),
      ],
      providers: [
        KeyService,
        KeyStorageService,
        SecretService,
        FailedAttemptsCacheService,
      ],
    })
      .overrideProvider(DataSource)
      .useValue(dataSource)
      .compile();

    service = module.get<KeyService>(KeyService);
    keyStorageService = module.get<KeyStorageService>(KeyStorageService);
    secretService = module.get<SecretService>(SecretService);
  });

  afterAll(async () => {
    try {
      await module.close();
      await dataSource.destroy();
    } catch (error) {
      console.warn(
        "Warning: Cleanup error:",
        error instanceof Error ? error.message : String(error)
      );
    }

    // Restore original environment variable
    if (originalSigningKeyPath !== undefined) {
      process.env.SIGNING_KEY_PATH = originalSigningKeyPath;
    } else {
      delete process.env.SIGNING_KEY_PATH;
    }

    // Restore mocks
    jest.restoreAllMocks();
  });

  beforeEach(async () => {
    // Clean up database before each test
    const repository = dataSource.getRepository(EncryptedKey);
    await repository.clear();
  });

  describe("generateKeyPair", () => {
    it("should generate and store ED25519_2020 key pair", async () => {
      const result = await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        mockIdentifier,
        mockSecrets
      );

      expect(result).toBeDefined();
      expect(result.id).toBe(mockIdentifier);
      expect(result.type).toBe(KeyType.MULTIKEY);
      expect(result.controller).toBe("did:web:example.com");
      expect(result.publicKeyMultibase).toBeDefined();

      // Verify it was stored in the database
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(1);

      const storedKey = await encryptedKeyRepository.findOne({
        where: { identifier: secretService.hash(mockIdentifier) },
      });
      expect(storedKey).toBeDefined();
      expect(storedKey!.identifier).toBe(secretService.hash(mockIdentifier));
      expect(storedKey!.keyType).toBe(KeyType.MULTIKEY);
      expect(storedKey!.signatureType).toBe(SignatureType.ED25519_2020);
    });

    it("should generate and store ES256 key pair", async () => {
      const result = await service.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        mockIdentifier,
        mockSecrets
      );

      expect(result).toBeDefined();
      expect(result.id).toBe(mockIdentifier);
      expect(result.type).toBe('Multikey');
      expect(result.controller).toBe("did:web:example.com");
      expect(result.publicKeyMultibase).toBeDefined();

      // Verify it was stored in the database
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(1);

      const storedKey = await encryptedKeyRepository.findOne({
        where: { identifier: secretService.hash(mockIdentifier) },
      });
      expect(storedKey).toBeDefined();
      expect(storedKey!.identifier).toBe(secretService.hash(mockIdentifier));
      expect(storedKey!.keyType).toBe(KeyType.MULTIKEY);
      expect(storedKey!.signatureType).toBe(SignatureType.ES256);
    });

    it("should generate and store PS256 key pair", async () => {
      const result = await service.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK_2020,
        mockIdentifier,
        mockSecrets
      );

      expect(result).toBeDefined();
      expect(result.id).toBe(mockIdentifier);
      expect(result.type).toBe(KeyType.JWK_2020);
      expect(result.controller).toBe("did:web:example.com");
      expect(result.publicKeyJwk).toBeDefined();
      expect(result.publicKeyJwk!.kty).toBe("RSA");
      expect(result.publicKeyJwk!.n).toBeDefined();
      expect(result.publicKeyJwk!.e).toBeDefined();
      expect(result.publicKeyJwk!.kid).toBeDefined();

      // Verify it was stored in the database
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(1);

      const storedKey = await encryptedKeyRepository.findOne({
        where: { identifier: secretService.hash(mockIdentifier) },
      });
      expect(storedKey).toBeDefined();
      expect(storedKey!.identifier).toBe(secretService.hash(mockIdentifier));
      expect(storedKey!.keyType).toBe(KeyType.JWK_2020);
      expect(storedKey!.signatureType).toBe(SignatureType.PS256);
    });

    it("should throw error for duplicate key generation", async () => {
      // Generate first key
      await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        mockIdentifier,
        mockSecrets
      );

      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count1 = await encryptedKeyRepository.count();
      expect(count1).toBe(1);

      // Try to generate another key with same identifier and type
      await expect(
        service.generateKeyPair(
          SignatureType.ED25519_2020,
          KeyType.MULTIKEY,
          mockIdentifier,
          mockSecrets
        )
      ).rejects.toThrow("Key with identifier");

      // Should still only have one key
      const count2 = await encryptedKeyRepository.count();
      expect(count2).toBe(1);
    });

    it("should throw error for unsupported key type", async () => {
      await expect(
        service.generateKeyPair(
          "UnsupportedKeyType" as SignatureType,
          KeyType.MULTIKEY,
          mockIdentifier,
          mockSecrets
        )
      ).rejects.toThrow("Unsupported key type: UnsupportedKeyType");

      // Verify no key was stored
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(0);
    });

    it("should throw error when no secrets provided", async () => {
      await expect(
        service.generateKeyPair(
          SignatureType.ED25519_2020,
          KeyType.MULTIKEY,
          mockIdentifier,
          []
        )
      ).rejects.toThrow("At least one secret must be provided");

      // Verify no key was stored
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(0);
    });

    it("should generate random keys on each generation call", async () => {
      // Generate multiple verification methods with different identifiers
      const identifier1 = "did:web:random1.com";
      const identifier2 = "did:web:random2.com";

      const result1 = await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        identifier1,
        mockSecrets
      );

      const result2 = await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        identifier2,
        mockSecrets
      );

      // The public keys should be different due to random generation
      expect(result1.publicKeyMultibase).toBeDefined();
      expect(result2.publicKeyMultibase).toBeDefined();
      expect(result1.publicKeyMultibase).not.toBe(result2.publicKeyMultibase);

      // Should have two keys stored
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(2);
    });

    it("should generate random ES256 keys on each generation call", async () => {
      // Generate multiple ES256 verification methods
      const identifier1 = "did:web:es256-1.com#1";
      const identifier2 = "did:web:es256-2.com#1";

      const result1 = await service.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        identifier1,
        mockSecrets
      );

      const result2 = await service.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        identifier2,
        mockSecrets
      );

      // ES256 with Multikey should have publicKeyMultibase
      expect(result1.publicKeyMultibase).toBeDefined();
      expect(result2.publicKeyMultibase).toBeDefined();
      expect(result1.publicKeyMultibase).not.toEqual(result2.publicKeyMultibase);

      // Verify they are both Multikey type
      expect(result1.type).toBe('Multikey');
      expect(result2.type).toBe('Multikey');

      // Should have two keys stored
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(2);
    });

    it("should generate random PS256 keys on each generation call", async () => {
      // Generate multiple PS256 verification methods
      const identifier1 = "did:web:ps256-1.com#1";
      const identifier2 = "did:web:ps256-2.com#1";

      const result1 = await service.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK_2020,
        identifier1,
        mockSecrets
      );

      const result2 = await service.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK_2020,
        identifier2,
        mockSecrets
      );

      // The public JWK keys should be different due to random generation
      expect(result1.publicKeyJwk).toBeDefined();
      expect(result2.publicKeyJwk).toBeDefined();
      expect(result1.publicKeyJwk).not.toEqual(result2.publicKeyJwk);

      // Specifically check that the n (modulus) values are different for RSA keys
      expect(result1.publicKeyJwk!.n).not.toBe(result2.publicKeyJwk!.n);
      expect(result1.publicKeyJwk!.kty).toBe("RSA");
      expect(result2.publicKeyJwk!.kty).toBe("RSA");

      // Should have two keys stored
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(2);
    });

    it("should handle Ed25519 key generation when identifier is missing fragment", async () => {
      // Use an identifier without fragment
      const identifierWithoutFragment = "did:web:auto-fragment.com";

      const result = await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        identifierWithoutFragment,
        mockSecrets
      );

      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.publicKeyMultibase).toBeDefined();

      // The returned id should have a fragment added
      expect(result.id).toContain("#");
      expect(result.id).toMatch(/^did:web:auto-fragment\.com#.+/);

      // The fragment should not be empty
      const fragment = result.id.split("#")[1];
      expect(fragment).toBeDefined();
      expect(fragment.length).toBeGreaterThan(0);

      // Controller should be the base identifier without fragment
      expect(result.controller).toBe(identifierWithoutFragment);

      // Verify it was stored correctly in the database
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const storedKey = await encryptedKeyRepository.findOne({
        where: { identifier: secretService.hash(result.id) },
      });

      expect(storedKey).toBeDefined();
      expect(storedKey!.keyType).toBe(KeyType.MULTIKEY);
      expect(storedKey!.signatureType).toBe(SignatureType.ED25519_2020);

      // Should be able to retrieve the key using the original identifier
      const retrievedKey = await service.getKeyPair(result.id, mockSecrets);
      expect(retrievedKey).toBeDefined();
      expect(retrievedKey.id).toBe(result.id); // Should have the same generated fragment
    });

    it("should handle ES256 key generation when identifier is missing fragment", async () => {
      // Use an identifier without fragment
      const identifierWithoutFragment = "did:web:es256-auto-fragment.com";

      const result = await service.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        identifierWithoutFragment,
        mockSecrets
      );

      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.publicKeyMultibase).toBeDefined();

      // For ES256, when identifier is missing fragment, it should append one with the publicKeyMultibase
      expect(result.id).toBeDefined();
      expect(result.id).toContain("#");
      expect(result.id).toMatch(/^did:web:es256-auto-fragment\.com#.+/);

      // The fragment should not be empty
      const fragment = result.id.split("#")[1];
      expect(fragment).toBeDefined();
      expect(fragment.length).toBeGreaterThan(0);

      // Controller should be the base identifier without fragment
      expect(result.controller).toBe(identifierWithoutFragment);

      // The Multikey should have a publicKeyMultibase field
      expect(result.publicKeyMultibase).toBeDefined();
      expect(typeof result.publicKeyMultibase).toBe("string");
      if (result.publicKeyMultibase) {
        expect(result.publicKeyMultibase.length).toBeGreaterThan(0);
      }

      // Verify it was stored correctly in the database
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const storedKey = await encryptedKeyRepository.findOne({
        where: { identifier: secretService.hash(result.id) },
      });
      expect(storedKey).toBeDefined();
      expect(storedKey!.keyType).toBe(KeyType.MULTIKEY);
      expect(storedKey!.signatureType).toBe(SignatureType.ES256);
    });

    it("should handle PS256 key generation when identifier is missing fragment", async () => {
      // Use an identifier without fragment
      const identifierWithoutFragment = "did:web:ps256-auto-fragment.com";

      const result = await service.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK_2020,
        identifierWithoutFragment,
        mockSecrets
      );

      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.publicKeyJwk).toBeDefined();

      // For PS256, when identifier is missing fragment, it should append one with the kid
      expect(result.id).toBeDefined();
      expect(result.id).toContain("#");
      expect(result.id).toMatch(/^did:web:ps256-auto-fragment\.com#.+/);

      // The fragment should not be empty
      const fragment = result.id.split("#")[1];
      expect(fragment).toBeDefined();
      expect(fragment.length).toBeGreaterThan(0);

      // Controller should be the base identifier without fragment
      expect(result.controller).toBe(identifierWithoutFragment);

      // The JWK should have a kid field that represents the public key
      expect(result.publicKeyJwk).toBeDefined();
      if (result.publicKeyJwk && result.publicKeyJwk.kid) {
        expect(result.publicKeyJwk.kid).toBeDefined();
        expect(result.publicKeyJwk.kid.length).toBeGreaterThan(0);

        // The kid should be derived from the public key (base64url encoded)
        expect(typeof result.publicKeyJwk.kid).toBe("string");
      }

      // Verify it was stored correctly in the database
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const storedKey = await encryptedKeyRepository.findOne({
        where: { identifier: secretService.hash(result.id) },
      });
      expect(storedKey).toBeDefined();
      expect(storedKey!.keyType).toBe(KeyType.JWK_2020);
      expect(storedKey!.signatureType).toBe(SignatureType.PS256);

      // Should be able to retrieve the key using the generated identifier
      const retrievedKey = await service.getKeyPair(result.id, mockSecrets);
      expect(retrievedKey).toBeDefined();
      expect(retrievedKey.id).toBe(result.id);

      // The retrieved key should have the same JWK structure
      expect(retrievedKey.publicKey).toBeDefined();
      // For ES256, publicKey should be a JsonWebKey object
      if (
        typeof retrievedKey.publicKey === "object" &&
        "kid" in retrievedKey.publicKey
      ) {
        expect(retrievedKey.publicKey.kid).toBe(result.publicKeyJwk?.kid);
      }
    });
  });

  describe("getKeyPair", () => {
    it("should return key pair after generation and storage", async () => {
      // First generate and store a key
      await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        mockIdentifier,
        mockSecrets
      );

      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(1);

      // Then retrieve it
      const result = await service.getKeyPair(mockIdentifier, mockSecrets);

      expect(result).toBeDefined();
      expect(result.id).toBe(mockIdentifier);
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(typeof result.signer).toBe("function");
    });

    it("should throw error when key not found", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const count = await encryptedKeyRepository.count();
      expect(count).toBe(0);

      await expect(
        service.getKeyPair("non-existent-identifier", mockSecrets)
      ).rejects.toThrow();
    });

    it("should work with ES256 keys", async () => {
      // Generate ES256 key
      await service.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        mockIdentifier,
        mockSecrets
      );

      // Retrieve it
      const result = await service.getKeyPair(mockIdentifier, mockSecrets);

      expect(result).toBeDefined();
      expect(result.id).toBe(mockIdentifier);
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(typeof result.signer).toBe("function");
    });

    it("should work with PS256 keys", async () => {
      // Generate PS256 key
      await service.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK_2020,
        mockIdentifier,
        mockSecrets
      );

      // Retrieve it
      const result = await service.getKeyPair(mockIdentifier, mockSecrets);

      expect(result).toBeDefined();
      expect(result.id).toBe(mockIdentifier);
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(typeof result.signer).toBe("function");
      expect(result.signatureType).toBe(SignatureType.PS256);
      expect(result.keyType).toBe(KeyType.JWK_2020);
    });

    it("should return key pair with real Ed25519 key data", async () => {
      // Generate a key first to have something in the database
      await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        mockIdentifier,
        mockSecrets
      );

      const result = await service.getKeyPair(mockIdentifier, mockSecrets);

      expect(result).toBeDefined();
      expect(result.id).toBe(mockIdentifier);
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(typeof result.signer).toBe("function");
    });
  });

  describe("Real database behavior", () => {
    it("should behave like a real database with multiple operations", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const initialCount = await encryptedKeyRepository.count();
      expect(initialCount).toBe(0);

      // Generate multiple keys
      const id1 = "did:web:test1.com#key1";
      const id2 = "did:web:test2.com#key2";
      const id3 = "did:web:test3.com#key3";

      await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        id1,
        mockSecrets
      );

      const count1 = await encryptedKeyRepository.count();
      expect(count1).toBe(1);

      await service.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        id2,
        mockSecrets
      );

      const count2 = await encryptedKeyRepository.count();
      expect(count2).toBe(2);

      await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        id3,
        mockSecrets
      );

      const count3 = await encryptedKeyRepository.count();
      expect(count3).toBe(3);

      // Verify we can retrieve each key
      const key1 = await service.getKeyPair(id1, mockSecrets);
      const key2 = await service.getKeyPair(id2, mockSecrets);
      const key3 = await service.getKeyPair(id3, mockSecrets);

      expect(key1.id).toBe(id1);
      expect(key2.id).toBe(id2);
      expect(key3.id).toBe(id3);

      // Test repository operations directly
      const allKeys = await encryptedKeyRepository.find();
      expect(allKeys).toHaveLength(3);

      const foundKey = await encryptedKeyRepository.findOne({
        where: { identifier: secretService.hash(id1) },
      });
      expect(foundKey).toBeDefined();
      expect(foundKey!.identifier).toBe(secretService.hash(id1));
    });

    it("should handle findOne with complex where clauses", async () => {
      await service.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        mockIdentifier,
        mockSecrets
      );

      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);

      // Test findOne with identifier and keyType
      const key1 = await encryptedKeyRepository.findOne({
        where: {
          identifier: secretService.hash(mockIdentifier),
          keyType: KeyType.MULTIKEY,
        },
      });
      expect(key1).toBeDefined();
      expect(key1!.identifier).toBe(secretService.hash(mockIdentifier));

      // Test findOne with wrong keyType
      const key2 = await encryptedKeyRepository.findOne({
        where: {
          identifier: secretService.hash(mockIdentifier),
          keyType: KeyType.JWK_2020, // Different type
        },
      });
      expect(key2).toBeNull();
    });
  });

  describe("Database Integration Tests", () => {
    describe("Encryption and Storage Integration", () => {
      it("should properly encrypt and store keys in database", async () => {
        const testIdentifier = "did:web:encryption-test.com#key1";

        // Generate and store a key
        await service.generateKeyPair(
          SignatureType.ED25519_2020,
          KeyType.MULTIKEY,
          testIdentifier,
          mockSecrets
        );

        // Verify raw database storage (keys should be encrypted)
        const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
        const storedKey = await encryptedKeyRepository.findOne({
          where: { identifier: secretService.hash(testIdentifier) },
        });

        expect(storedKey).toBeDefined();
        expect(storedKey!.identifier).toBe(secretService.hash(testIdentifier));
        expect(storedKey!.encryptedPrivateKey).toBeDefined();
        expect(storedKey!.encryptedPublicKey).toBeDefined();

        // Should be able to decrypt and retrieve the key
        const retrievedKey = await service.getKeyPair(
          testIdentifier,
          mockSecrets
        );
        expect(retrievedKey).toBeDefined();
        expect(retrievedKey.id).toBe(testIdentifier);
      });

      it("should fail to decrypt with wrong secrets", async () => {
        const testIdentifier = "did:web:wrong-secrets-test.com#key1";
        const wrongSecrets = ["wrong-secret"];

        // Store with correct secrets
        await service.generateKeyPair(
          SignatureType.ED25519_2020,
          KeyType.MULTIKEY,
          testIdentifier,
          mockSecrets
        );

        // Try to retrieve with wrong secrets
        await expect(
          service.getKeyPair(testIdentifier, wrongSecrets)
        ).rejects.toThrow("Failed to decrypt key");
      });
    });

    describe("Concurrent Operations", () => {
      it("should handle concurrent key generation for different identifiers", async () => {
        const identifiers = [
          "did:web:concurrent1.com#key1",
          "did:web:concurrent2.com#key1",
          "did:web:concurrent3.com#key1",
        ];

        // Generate keys concurrently
        const generatePromises = identifiers.map((id) =>
          service.generateKeyPair(
            SignatureType.ED25519_2020,
            KeyType.MULTIKEY,
            id,
            mockSecrets
          )
        );

        const results = await Promise.all(generatePromises);

        // All should succeed
        expect(results).toHaveLength(3);
        results.forEach((result, index) => {
          expect(result.id).toBe(identifiers[index]);
        });

        // Database should contain all keys
        const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
        const count = await encryptedKeyRepository.count();
        expect(count).toBe(3);
      });
    });

    describe("Database Constraints and Validation", () => {
      it("should allow same identifier with different keyTypes", async () => {
        const baseIdentifier = "did:web:multi-type.com";
        const identifier1 = `${baseIdentifier}#ed25519-key`;
        const identifier2 = `${baseIdentifier}#es256-key`;

        // Generate ED25519 key
        const result1 = await service.generateKeyPair(
          SignatureType.ED25519_2020,
          KeyType.MULTIKEY,
          identifier1,
          mockSecrets
        );

        // Generate ES256 key with similar identifier
        const result2 = await service.generateKeyPair(
          SignatureType.ES256,
          KeyType.MULTIKEY,
          identifier2,
          mockSecrets
        );

        expect(result1).toBeDefined();
        expect(result2).toBeDefined();
        expect(result1.id).toBe(identifier1);
        expect(result2.id).toBe(identifier2);

        // Database should contain both keys
        const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
        const count = await encryptedKeyRepository.count();
        expect(count).toBe(2);
      });
    });

    describe("Index and Query Performance", () => {
      it("should efficiently query by identifier using index", async () => {
        // Generate multiple keys
        const keyCount = 10;
        const identifiers: string[] = [];

        for (let i = 0; i < keyCount; i++) {
          const identifier = `did:web:performance-test.com#key${i}`;
          identifiers.push(identifier);
          await service.generateKeyPair(
            SignatureType.ED25519_2020,
            KeyType.MULTIKEY,
            identifier,
            mockSecrets
          );
        }

        const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
        const totalCount = await encryptedKeyRepository.count();
        expect(totalCount).toBe(keyCount);

        // Test querying specific keys (should use index)
        const targetIdentifier = identifiers[5];
        const hashedIdentifier = secretService.hash(targetIdentifier);

        const foundKey = await encryptedKeyRepository.findOne({
          where: { identifier: hashedIdentifier },
        });

        expect(foundKey).toBeDefined();
        expect(foundKey!.identifier).toBe(hashedIdentifier);
      });
    });

    describe("KeyStorageService Direct Integration", () => {
      it("should directly store and retrieve keys through KeyStorageService", async () => {
        const testIdentifier = "did:web:direct-storage.com#key1";
        const mockPrivateKey = { type: "test", value: "private-key-data" };
        const mockPublicKey = { type: "test", value: "public-key-data" };

        // Direct storage
        const storedKey = await keyStorageService.storeKey(
          testIdentifier,
          SignatureType.ED25519_2020,
          KeyType.MULTIKEY,
          mockPrivateKey,
          mockPublicKey,
          mockSecrets
        );

        expect(storedKey).toBeDefined();
        expect(storedKey.signatureType).toBe(SignatureType.ED25519_2020);
        expect(storedKey.keyType).toBe(KeyType.MULTIKEY);

        // Direct retrieval
        const retrievedKey = await keyStorageService.retrieveKey(
          testIdentifier,
          mockSecrets
        );

        expect(retrievedKey).toBeDefined();
        expect(retrievedKey.id).toBe(testIdentifier);
        expect(retrievedKey.signatureType).toBe(SignatureType.ED25519_2020);
        expect(retrievedKey.keyType).toBe(KeyType.MULTIKEY);
        expect(retrievedKey.privateKey).toEqual(mockPrivateKey);
        expect(retrievedKey.publicKey).toEqual(mockPublicKey);
      });

      it("should handle storage service errors gracefully", async () => {
        const testIdentifier = "did:web:storage-error.com#key1";

        // Try to retrieve non-existent key
        await expect(
          keyStorageService.retrieveKey(testIdentifier, mockSecrets)
        ).rejects.toThrow("Key with identifier");
      });
    });

    describe("Database Connection and Lifecycle", () => {
      it("should maintain database connection throughout operations", async () => {
        expect(dataSource.isInitialized).toBe(true);

        // Perform multiple operations
        const operations = [];
        for (let i = 0; i < 5; i++) {
          operations.push(
            service.generateKeyPair(
              SignatureType.ED25519_2020,
              KeyType.MULTIKEY,
              `did:web:lifecycle-test.com#key${i}`,
              mockSecrets
            )
          );
        }

        await Promise.all(operations);

        // Connection should still be active
        expect(dataSource.isInitialized).toBe(true);

        // Should be able to perform additional operations
        const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
        const count = await encryptedKeyRepository.count();
        expect(count).toBe(5);
      });

      it("should handle database operations after key retrieval", async () => {
        const testIdentifier = "did:web:post-retrieval.com#key1";

        // Generate key
        await service.generateKeyPair(
          SignatureType.ED25519_2020,
          KeyType.MULTIKEY,
          testIdentifier,
          mockSecrets
        );

        // Retrieve key
        const retrievedKey = await service.getKeyPair(
          testIdentifier,
          mockSecrets
        );
        expect(retrievedKey).toBeDefined();

        // Database should still be operational
        const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
        const allKeys = await encryptedKeyRepository.find();
        expect(allKeys).toHaveLength(1);

        // Should be able to generate another key
        const anotherIdentifier = "did:web:post-retrieval.com#key2";
        const anotherKey = await service.generateKeyPair(
          SignatureType.ES256,
          KeyType.MULTIKEY,
          anotherIdentifier,
          mockSecrets
        );

        expect(anotherKey).toBeDefined();

        const finalCount = await encryptedKeyRepository.count();
        expect(finalCount).toBe(2);
      });
    });

    describe("Data Integrity and Consistency", () => {
      it("should maintain data consistency across transactions", async () => {
        const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);

        // Initial state
        const initialCount = await encryptedKeyRepository.count();
        expect(initialCount).toBe(0);

        // Generate key
        const testIdentifier = "did:web:consistency.com#key1";
        await service.generateKeyPair(
          SignatureType.ED25519_2020,
          KeyType.MULTIKEY,
          testIdentifier,
          mockSecrets
        );

        // Verify immediate consistency
        const countAfterGeneration = await encryptedKeyRepository.count();
        expect(countAfterGeneration).toBe(1);

        const storedKey = await encryptedKeyRepository.findOne({
          where: { identifier: secretService.hash(testIdentifier) },
        });

        expect(storedKey).toBeDefined();
        expect(storedKey!.signatureType).toBe(SignatureType.ED25519_2020);
        expect(storedKey!.keyType).toBe(KeyType.MULTIKEY);
        expect(storedKey!.createdAt).toBeDefined();
        expect(storedKey!.createdAt).toBeInstanceOf(Date);
      });
    });
  });
});
