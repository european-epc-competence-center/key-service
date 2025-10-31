import { Test, TestingModule } from "@nestjs/testing";
import { TypeOrmModule } from "@nestjs/typeorm";
import { DataSource } from "typeorm";
import { DataIntegritySigningService } from "./data-integrity-signing.service";
import { KeyService } from "../key-services/key.service";
import { KeyStorageService } from "../key-services/key-storage.service";
import { SecretService } from "../key-services/secret.service";
import { FailedAttemptsCacheService } from "../key-services/failed-attempts-cache.service";
import { DocumentLoaderService } from "../utils/document-loader.service";
import { EncryptedKey } from "../key-services/entities/encrypted-key.entity";
import {
  VerifiableCredential,
  Proof,
} from "../types/verifiable-credential.types";
// @ts-ignore
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import * as fs from "fs";
import { SignatureType } from "../types/key-types.enum";
import { KeyType } from "../types/key-format.enum";

// Mock fs module for this test file only
jest.mock("fs");

// Increase timeout for this test file to allow fetching remote context URLs
jest.setTimeout(120000); // 2 minutes

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

describe("DataIntegritySigningService", () => {
  let service: DataIntegritySigningService;
  let keyService: KeyService;
  let keyStorageService: KeyStorageService;
  let secretService: SecretService;
  let documentLoaderService: DocumentLoaderService;
  let dataSource: DataSource;
  let module: TestingModule;
  let originalSigningKeyPath: string | undefined;

  const mockSecrets = ["test-secret-key-12345"];

  const exampleCredentialV1: VerifiableCredential = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
    ],
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
    issuer: "did:example:issuer",
    credentialSubject: {
      id: "did:example:subject",
      degree: {
        type: "BachelorDegree",
        name: "Baccalauréat en musiques numériques",
      },
    },
  };

  const exampleCredentialV2: VerifiableCredential = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2",
    ],
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
    issuer: "did:example:issuer",
    validFrom: "2024-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:subject",
      degree: {
        type: "BachelorDegree",
        name: "Baccalauréat en musiques numériques",
      },
    },
  };

  const exampleCredentialV1WithIssuanceDate: VerifiableCredential = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
    ],
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
    issuer: "did:example:issuer",
    issuanceDate: "2023-06-15T10:30:00Z",
    credentialSubject: {
      id: "did:example:subject",
      degree: {
        type: "BachelorDegree",
        name: "Baccalauréat en musiques numériques",
      },
    },
  };

  const exampleCredentialV2WithoutValidFrom: VerifiableCredential = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2",
    ],
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
    issuer: "did:example:issuer",
    credentialSubject: {
      id: "did:example:subject",
      degree: {
        type: "BachelorDegree",
        name: "Baccalauréat en musiques numériques",
      },
    },
  };

  beforeAll(async () => {
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
        DataIntegritySigningService,
        KeyService,
        KeyStorageService,
        SecretService,
        DocumentLoaderService,
        FailedAttemptsCacheService,
      ],
    })
      .overrideProvider(DataSource)
      .useValue(dataSource)
      .compile();

    service = module.get<DataIntegritySigningService>(
      DataIntegritySigningService
    );
    keyService = module.get<KeyService>(KeyService);
    keyStorageService = module.get<KeyStorageService>(KeyStorageService);
    secretService = module.get<SecretService>(SecretService);
    documentLoaderService = module.get<DocumentLoaderService>(
      DocumentLoaderService
    );
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

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("sign", () => {
    it("should sign a VC V1 verifiable credential with Ed25519 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signVC(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      expect(result.type).toEqual(exampleCredentialV1.type);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that the Ed25519-2020 context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/suites/ed25519-2020/v1"
      );
      // Verify original contexts are preserved
      expect(result["@context"]).toContain(
        "https://www.w3.org/2018/credentials/v1"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/2018/credentials/examples/v1"
      );

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signVC(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      expect(result.type).toEqual(exampleCredentialV2.type);
      expect(result.validFrom).toEqual(exampleCredentialV2.validFrom);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify that the Ed25519-2020 context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/suites/ed25519-2020/v1"
      );
      // Verify original contexts are preserved
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and preserve existing issuanceDate", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-with-date";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signVC(
        exampleCredentialV1WithIssuanceDate,
        verificationMethod,
        mockSecrets
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      // Verify that the Ed25519-2020 context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/suites/ed25519-2020/v1"
      );
      // Verify original contexts are preserved
      expect(result["@context"]).toContain(
        "https://www.w3.org/2018/credentials/v1"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/2018/credentials/examples/v1"
      );
      expect(result.type).toEqual(exampleCredentialV1WithIssuanceDate.type);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV1WithIssuanceDate.credentialSubject
      );

      // Verify issuanceDate was preserved
      expect(result.issuanceDate).toBe("2023-06-15T10:30:00Z");

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and set issuanceDate if absent", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-no-date";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signVC(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      // Verify that the Ed25519-2020 context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/suites/ed25519-2020/v1"
      );
      // Verify original contexts are preserved
      expect(result["@context"]).toContain(
        "https://www.w3.org/2018/credentials/v1"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/2018/credentials/examples/v1"
      );
      expect(result.type).toEqual(exampleCredentialV1.type);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify issuanceDate was set since it was absent
      expect(result.issuanceDate).toBeDefined();
      expect(typeof result.issuanceDate).toBe("string");
      // Should be a valid ISO date string
      expect(
        new Date(result.issuanceDate!).toISOString().replace(/\.\d{3}Z$/, "Z")
      ).toBe(result.issuanceDate);

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair and preserve existing validFrom", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-with-date";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signVC(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      // Verify that the Ed25519-2020 context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/suites/ed25519-2020/v1"
      );
      // Verify original contexts are preserved
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );
      expect(result.type).toEqual(exampleCredentialV2.type);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify validFrom was preserved
      expect(result.validFrom).toBe("2024-01-01T00:00:00Z");

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair and leave validFrom empty if absent", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-no-date";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signVC(
        exampleCredentialV2WithoutValidFrom,
        verificationMethod,
        mockSecrets
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      // Verify that the Ed25519-2020 context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/suites/ed25519-2020/v1"
      );
      // Verify original contexts are preserved
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );
      expect(result.type).toEqual(exampleCredentialV2WithoutValidFrom.type);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV2WithoutValidFrom.credentialSubject
      );

      // Verify validFrom was NOT set (should remain undefined for V2 credentials)
      expect(result.validFrom).toBeUndefined();

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V1 verifiable credential with ES256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#es256-test-key";

      // Generate an ES256 key pair
      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signVC(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("EcdsaSecp256r1Signature2019");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Verify the credential content is preserved
      expect(result.type).toEqual(exampleCredentialV1.type);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with ES256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#es256-v2-key";

      // Generate an ES256 key pair
      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signVC(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("EcdsaSecp256r1Signature2019");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Verify the credential content is preserved
      expect(result.type).toEqual(exampleCredentialV2.type);
      expect(result.validFrom).toEqual(exampleCredentialV2.validFrom);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");
    });

    it("should throw error when key not found", async () => {
      const verificationMethod = "did:web:nonexistent.com#key";

      await expect(
        service.signVC(exampleCredentialV1, verificationMethod, mockSecrets)
      ).rejects.toThrow();
    });

    it("should handle database operations and maintain consistency", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const initialCount = await encryptedKeyRepository.count();
      expect(initialCount).toBe(0);

      // Generate multiple Ed25519 keys for different credentials
      const verificationMethod1 = "did:web:test1.com#key1";
      const verificationMethod2 = "did:web:test2.com#key2";

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod1,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod2,
        mockSecrets
      );

      const count = await encryptedKeyRepository.count();
      expect(count).toBe(2);

      // Sign with both keys
      const result1 = await service.signVC(
        exampleCredentialV1,
        verificationMethod1,
        mockSecrets
      );

      const result2 = await service.signVC(
        exampleCredentialV2,
        verificationMethod2,
        mockSecrets
      );

      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
      expect(result1.proof).toBeDefined();
      expect(result2.proof).toBeDefined();

      // Proofs should be different due to different keys and timestamps
      const proof1 = Array.isArray(result1.proof)
        ? result1.proof[0]
        : result1.proof;
      const proof2 = Array.isArray(result2.proof)
        ? result2.proof[0]
        : result2.proof;

      expect(proof1?.proofValue).not.toBe(proof2?.proofValue);
      expect(proof1?.verificationMethod).not.toBe(proof2?.verificationMethod);
    });
  });

  describe("Verifiable Presentation Signing", () => {
    it("should sign a presentation with a single enveloped credential (V2)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:example.com#key1";

      // Generate key for signing
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod,
        mockSecrets
      );

      // Sign a credential first
      const signedCredential = await service.signVC(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Create presentation with embedded credential
      const presentation: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        type: ["VerifiablePresentation", "ExamplePresentation"],
        verifiableCredential: [signedCredential],
      };

      // Sign the presentation
      const signedPresentation = await service.signVP(
        presentation,
        verificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBe(verificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify presentation content
      expect(signedPresentation.type).toContain("VerifiablePresentation");
      expect(signedPresentation.type).toContain("ExamplePresentation");
      expect(signedPresentation.id).toBe(
        "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5"
      );
      expect(Array.isArray(signedPresentation.verifiableCredential)).toBe(true);
      expect(signedPresentation.verifiableCredential).toHaveLength(1);
    });

    it("should sign a presentation with multiple embedded credentials", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod1 = "did:web:example.com#key1";
      const verificationMethod2 = "did:web:example.com#key2";
      const presentationVerificationMethod = "did:web:holder.com#holderKey";

      // Generate keys for signing credentials
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod1,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod2,
        mockSecrets
      );

      // Generate key for signing presentation
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign multiple credentials
      const signedCredential1 = await service.signVC(
        exampleCredentialV2,
        verificationMethod1,
        mockSecrets
      );

      const signedCredential2 = await service.signVC(
        exampleCredentialV1WithIssuanceDate,
        verificationMethod2,
        mockSecrets
      );

      // Create presentation with multiple embedded credentials
      const presentation: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:4a8c1234-5678-4abc-b123-456789abcdef",
        type: ["VerifiablePresentation"],
        holder: "did:web:holder.com",
        verifiableCredential: [signedCredential1, signedCredential2],
      };

      // Sign the presentation
      const signedPresentation = await service.signVP(
        presentation,
        presentationVerificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify presentation content
      expect(signedPresentation.type).toContain("VerifiablePresentation");
      expect(signedPresentation.holder).toBe("did:web:holder.com");
      expect(Array.isArray(signedPresentation.verifiableCredential)).toBe(true);
      expect(signedPresentation.verifiableCredential).toHaveLength(2);
    });

    it("should sign a presentation with challenge and domain", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey";
      const presentationVerificationMethod = "did:web:holder.com#presKey";

      // Generate keys
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        credentialVerificationMethod,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign credential
      const signedCredential = await service.signVC(
        exampleCredentialV2,
        credentialVerificationMethod,
        mockSecrets
      );

      // Create and sign presentation with challenge and domain
      const presentation: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:12345678-1234-5678-1234-567812345678",
        type: ["VerifiablePresentation"],
        verifiableCredential: [signedCredential],
      };

      const challenge = "test-challenge-12345";
      const domain = "https://example.com";

      const signedPresentation = await service.signVP(
        presentation,
        presentationVerificationMethod,
        mockSecrets,
        challenge,
        domain
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("Ed25519Signature2020");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.challenge).toBe(challenge);
      expect(proof?.domain).toBe(domain);
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
    });

    it("should sign a presentation with ES256 key pair", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey";
      const presentationVerificationMethod = "did:web:holder.com#es256PresKey";

      // Generate Ed25519 key for credential
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        credentialVerificationMethod,
        mockSecrets
      );

      // Generate ES256 key for presentation
      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign credential
      const signedCredential = await service.signVC(
        exampleCredentialV2,
        credentialVerificationMethod,
        mockSecrets
      );

      const presentation: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:es256-test-presentation",
        type: ["VerifiablePresentation"],
        verifiableCredential: [signedCredential],
      };

      // Sign the presentation with ES256 key
      const signedPresentation = await service.signVP(
        presentation,
        presentationVerificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("EcdsaSecp256r1Signature2019");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Verify holder was automatically set
      expect(signedPresentation.holder).toBe("did:web:holder.com");
    });

    it("should automatically set holder if not provided", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:holder.com#holderKey";

      // Generate key
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.VERIFICATION_KEY_2020,
        verificationMethod,
        mockSecrets
      );

      // Sign credential
      const signedCredential = await service.signVC(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Create presentation without holder
      const presentation: any = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        id: "urn:uuid:test-presentation",
        type: ["VerifiablePresentation"],
        verifiableCredential: [signedCredential],
      };

      // Sign the presentation
      const signedPresentation = await service.signVP(
        presentation,
        verificationMethod,
        mockSecrets
      );

      // Verify holder was automatically set to the key's controller
      expect(signedPresentation.holder).toBe("did:web:holder.com");
    });
  });
});
