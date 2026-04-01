import { Test, TestingModule } from "@nestjs/testing";
import { TypeOrmModule } from "@nestjs/typeorm";
import { DataSource } from "typeorm";
import { JwtSigningService } from "./jwt-signing.service";
import { KeyService } from "../key-services/key.service";
import { KeyStorageService } from "../key-services/key-storage.service";
import { SecretService } from "../key-services/secret.service";
import { FailedAttemptsCacheService } from "../key-services/failed-attempts-cache.service";
import { EncryptedKey } from "../key-services/entities/encrypted-key.entity";
import {
  VerifiableCredential,
  VerifiablePresentation,
} from "../types/verifiable-credential.types";
import * as fs from "fs";
import { SignatureType } from "../types/key-types.enum";
import { KeyType } from "../types/key-format.enum";
import { ECJsonWebKey, JsonWebKey, RSAJsonWebKey } from "../types/keypair.types";
import { VerificationMethod } from "../types/verification-method.types";
import * as jose from "jose";
// @ts-ignore
import * as EcdsaMultikey from "@digitalbazaar/ecdsa-multikey";
// @ts-ignore
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
// @ts-ignore
import * as RsaMultikey from "@eecc/rsa-multikey";

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

// Helper functions for signature verification in tests
async function verifyJwtSignature(
  jwt: string,
  verificationMethod: VerificationMethod,
  secrets: string[],
  keyService: KeyService
): Promise<boolean> {
  try {
    // Parse JWT header to get the algorithm
    const parts = jwt.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT structure");
    }

    const header = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );
    const alg = header.alg;

    // Distinguish by algorithm
    if (alg === "ES256") {

      // can handle both notations multikey and json web key
      const keyPair = await EcdsaMultikey.from(verificationMethod);
      // Convert multikey to JWK format for verification
      const publicKeyJwk = await EcdsaMultikey.toJwk({
        keyPair: keyPair,
        secretKey: false,
      }) as ECJsonWebKey;

      // Basic validation: check that we have the required key components
      const hasValidComponents =
        publicKeyJwk.x && publicKeyJwk.y && publicKeyJwk.kty === "EC";
      if (!hasValidComponents) {
        throw new Error("Invalid ES256 public key components");
      }

      await jose.jwtVerify(
        jwt,
        await jose.importJWK({ ...publicKeyJwk, alg: "ES256" } as jose.JWK),
        {
          algorithms: ["ES256"],
        }
      );
      return true;
    } else if (alg === "Ed25519") {
      // can handle both notations multikey and json web key
      const keyPair = await Ed25519Multikey.from(verificationMethod);
      // Convert multikey to JWK format for verification
      const ed25519PublicKeyJwk = await Ed25519Multikey.toJwk({
        keyPair: keyPair,
        secretKey: false,
      }) as JsonWebKey;

      // Basic validation: check that we have the required key components
      const hasValidEd25519Components =
        ed25519PublicKeyJwk.x &&
        ed25519PublicKeyJwk.kty === "OKP" &&
        ed25519PublicKeyJwk.crv === "Ed25519";
      if (!hasValidEd25519Components) {
        throw new Error("Invalid Ed25519 public key components");
      }

      await jose.jwtVerify(
        jwt,
        await jose.importJWK({
          ...ed25519PublicKeyJwk,
          alg: "Ed25519",
        } as jose.JWK),
        {
          algorithms: ["Ed25519"],
        }
      );
      return true;
    } else if (alg === "PS256") {
      // can handle both notations multikey and json web key
      const keyPair = await RsaMultikey.from(verificationMethod);
      // Convert multikey to JWK format for verification
      const publicKeyJwk = await RsaMultikey.toJwk({
        keyPair: keyPair,
        secretKey: false,
      }) as RSAJsonWebKey;

      // Basic validation: check that we have the required key components
      const hasValidComponents =
        publicKeyJwk.n && publicKeyJwk.e && publicKeyJwk.kty === "RSA";
      if (!hasValidComponents) {
        throw new Error("Invalid PS256 public key components");
      }

      await jose.jwtVerify(
        jwt,
        await jose.importJWK({ ...publicKeyJwk, alg: "PS256" } as jose.JWK),
        {
          algorithms: ["PS256"],
        }
      );
      return true;
    }

    return false;
  } catch (error: any) {
    console.log(error);
    return false;
  }
}

describe("JwtSigningService", () => {
  let service: JwtSigningService;
  let keyService: KeyService;
  let keyStorageService: KeyStorageService;
  let secretService: SecretService;
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
        JwtSigningService,
        KeyService,
        KeyStorageService,
        SecretService,
        FailedAttemptsCacheService,
      ],
    })
      .overrideProvider(DataSource)
      .useValue(dataSource)
      .compile();

    service = module.get<JwtSigningService>(JwtSigningService);
    keyService = module.get<KeyService>(KeyService);
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

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("sign", () => {
    it("should sign a VC V1 verifiable credential with Ed25519 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV1["@context"]);
      expect(payload.type).toEqual(exampleCredentialV1.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyJwtSignature(
        result,
        verificationMethodObj,
        mockSecrets,
        keyService
      );
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V1 verifiable credential with Ed25519 key pair (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-jwk";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV1["@context"]);
      expect(payload.type).toEqual(exampleCredentialV1.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyJwtSignature(
        result,
        verificationMethodObj,
        mockSecrets,
        keyService
      );
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V1 verifiable credential with ES256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#es256-key";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "ES256");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV1["@context"]);
      expect(payload.type).toEqual(exampleCredentialV1.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyJwtSignature(
        result,
        verificationMethodObj,
        mockSecrets,
        keyService
      );
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V1 verifiable credential with ES256 key pair (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#es256-key-jwk";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "ES256");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV1["@context"]);
      expect(payload.type).toEqual(exampleCredentialV1.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyJwtSignature(
        result,
        verificationMethodObj,
        mockSecrets,
        keyService
      );
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(payload).toHaveProperty("validFrom");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV2["@context"]);
      expect(payload.type).toEqual(exampleCredentialV2.type);
      expect(payload.validFrom).toEqual(exampleCredentialV2.validFrom);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-jwk";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(payload).toHaveProperty("validFrom");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV2["@context"]);
      expect(payload.type).toEqual(exampleCredentialV2.type);
      expect(payload.validFrom).toEqual(exampleCredentialV2.validFrom);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with ES256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-es256-key";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "ES256");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(payload).toHaveProperty("validFrom");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV2["@context"]);
      expect(payload.type).toEqual(exampleCredentialV2.type);
      expect(payload.validFrom).toEqual(exampleCredentialV2.validFrom);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with ES256 key pair (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-es256-key-jwk";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "ES256");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(payload).toHaveProperty("validFrom");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV2["@context"]);
      expect(payload.type).toEqual(exampleCredentialV2.type);
      expect(payload.validFrom).toEqual(exampleCredentialV2.validFrom);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V1 verifiable credential with PS256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#ps256-key";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "PS256");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV1["@context"]);
      expect(payload.type).toEqual(exampleCredentialV1.type);
      expect(payload.issuanceDate).toEqual(exampleCredentialV1.issuanceDate);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyJwtSignature(
        result,
        verificationMethodObj,
        mockSecrets,
        keyService
      );
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V2 verifiable credential with PS256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-ps256-key";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "PS256");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(payload).toHaveProperty("validFrom");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV2["@context"]);
      expect(payload.type).toEqual(exampleCredentialV2.type);
      expect(payload.validFrom).toEqual(exampleCredentialV2.validFrom);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and preserve existing issuanceDate (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-with-date-jwk";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1WithIssuanceDate,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Verify issuanceDate was preserved
      expect(payload.issuanceDate).toBe("2023-06-15T10:30:00Z");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(
        exampleCredentialV1WithIssuanceDate["@context"]
      );
      expect(payload.type).toEqual(exampleCredentialV1WithIssuanceDate.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1WithIssuanceDate.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and preserve existing issuanceDate", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-with-date";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1WithIssuanceDate,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Verify issuanceDate was preserved
      expect(payload.issuanceDate).toBe("2023-06-15T10:30:00Z");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(
        exampleCredentialV1WithIssuanceDate["@context"]
      );
      expect(payload.type).toEqual(exampleCredentialV1WithIssuanceDate.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1WithIssuanceDate.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and set issuanceDate if absent (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-no-date-jwk";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Verify issuanceDate was set since it was absent
      expect(payload.issuanceDate).toBeDefined();
      expect(typeof payload.issuanceDate).toBe("string");
      // Should be a valid ISO date string
      expect(
        new Date(payload.issuanceDate).toISOString().replace(/\.\d{3}Z$/, "Z")
      ).toBe(payload.issuanceDate);

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV1["@context"]);
      expect(payload.type).toEqual(exampleCredentialV1.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and set issuanceDate if absent", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-no-date";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Verify issuanceDate was set since it was absent
      expect(payload.issuanceDate).toBeDefined();
      expect(typeof payload.issuanceDate).toBe("string");
      // Should be a valid ISO date string
      expect(
        new Date(payload.issuanceDate).toISOString().replace(/\.\d{3}Z$/, "Z")
      ).toBe(payload.issuanceDate);

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV1["@context"]);
      expect(payload.type).toEqual(exampleCredentialV1.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair and preserve existing validFrom (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-with-date-jwk";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(payload).toHaveProperty("validFrom");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Verify validFrom was preserved
      expect(payload.validFrom).toBe("2024-01-01T00:00:00Z");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV2["@context"]);
      expect(payload.type).toEqual(exampleCredentialV2.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair and preserve existing validFrom", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-with-date";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(payload).toHaveProperty("validFrom");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Verify validFrom was preserved
      expect(payload.validFrom).toBe("2024-01-01T00:00:00Z");

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(exampleCredentialV2["@context"]);
      expect(payload.type).toEqual(exampleCredentialV2.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair and leave validFrom empty if absent (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-no-date-jwk";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2WithoutValidFrom,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Verify validFrom was NOT set (should remain undefined for V2 credentials)
      expect(payload.validFrom).toBeUndefined();

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(
        exampleCredentialV2WithoutValidFrom["@context"]
      );
      expect(payload.type).toEqual(exampleCredentialV2WithoutValidFrom.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2WithoutValidFrom.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair and leave validFrom empty if absent", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-no-date";

      // Generate a key pair first
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result = await service.signCredential(
        exampleCredentialV2WithoutValidFrom,
        verificationMethod,
        mockSecrets
      );

      // Assert
      // Check that result is a valid JWT string
      expect(result).toBeDefined();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);

      // Check JWT structure (header.payload.signature)
      const parts = result.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      expect(header).toHaveProperty("alg", "Ed25519");
      expect(header).toHaveProperty("kid");
      expect(typeof header.kid).toBe("string");
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(payload).toHaveProperty("@context");
      expect(payload).toHaveProperty("type");
      expect(payload).toHaveProperty("issuer");
      expect(payload).toHaveProperty("credentialSubject");
      expect(header).toHaveProperty("iat");
      expect(typeof header.iat).toBe("number");

      // Verify validFrom was NOT set (should remain undefined for V2 credentials)
      expect(payload.validFrom).toBeUndefined();

      // Validate signature format (should be base64url encoded)
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that the original credential data is preserved
      expect(payload["@context"]).toEqual(
        exampleCredentialV2WithoutValidFrom["@context"]
      );
      expect(payload.type).toEqual(exampleCredentialV2WithoutValidFrom.type);
      expect(payload.credentialSubject).toEqual(
        exampleCredentialV2WithoutValidFrom.credentialSubject
      );

      // Verify that issuer was updated to match the key pair
      expect(payload.issuer).toBeDefined();
      expect(typeof payload.issuer).toBe("string");
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should throw error when key not found", async () => {
      const verificationMethod = "did:web:nonexistent.com#key";

      await expect(
        service.signCredential(exampleCredentialV1, verificationMethod, mockSecrets)
      ).rejects.toThrow();
    });

    it("should set typ openid4vci-proof+jwt via signProofOfPossession (credential)", async () => {
      const verificationMethod = "did:web:example.com#key-typ";

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      const signedJwt = await service.signProofOfPossession(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets,
      );

      const parts = signedJwt.split(".");
      expect(parts).toHaveLength(3);
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      expect(header.typ).toBe("openid4vci-proof+jwt");
      expect(header.alg).toBe("Ed25519");
      expect(header.kid).toBe(verificationMethod);
      expect(header).not.toHaveProperty("iat");
      expect(header).not.toHaveProperty("iss");
      expect(typeof payload.iat).toBe("number");
      expect(payload.iss).toBe(verificationMethod.split("#")[0]);
    });

    it("should handle database operations and maintain consistency", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const initialCount = await encryptedKeyRepository.count();
      expect(initialCount).toBe(0);

      // Generate multiple keys for different credentials
      const verificationMethod1 = "did:web:test1.com#key1";
      const verificationMethod2 = "did:web:test2.com#key2";

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod1,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        verificationMethod2,
        mockSecrets
      );

      const count = await encryptedKeyRepository.count();
      expect(count).toBe(2);

      // Sign with both keys
      const result1 = await service.signCredential(
        exampleCredentialV1,
        verificationMethod1,
        mockSecrets
      );

      const result2 = await service.signCredential(
        exampleCredentialV2,
        verificationMethod2,
        mockSecrets
      );

      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
      expect(result1).not.toBe(result2);

      // Validate both JWT structures
      const parts1 = result1.split(".");
      const parts2 = result2.split(".");

      expect(parts1).toHaveLength(3);
      expect(parts2).toHaveLength(3);

      const header1 = JSON.parse(
        Buffer.from(parts1[0], "base64url").toString()
      );
      const header2 = JSON.parse(
        Buffer.from(parts2[0], "base64url").toString()
      );

      expect(header1.alg).toBe("Ed25519");
      expect(header2.alg).toBe("ES256");
      expect(header1.iss).toBe(verificationMethod1.split("#")[0]);
      expect(header2.iss).toBe(verificationMethod2.split("#")[0]);
    });

    it("should handle database operations and maintain consistency (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const initialCount = await encryptedKeyRepository.count();
      expect(initialCount).toBe(0);

      // Generate multiple keys for different credentials
      const verificationMethod1 = "did:web:test1.com#key1-jwk";
      const verificationMethod2 = "did:web:test2.com#key2-jwk";

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod1,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        verificationMethod2,
        mockSecrets
      );

      const count = await encryptedKeyRepository.count();
      expect(count).toBe(2);

      // Sign with both keys
      const result1 = await service.signCredential(
        exampleCredentialV1,
        verificationMethod1,
        mockSecrets
      );

      const result2 = await service.signCredential(
        exampleCredentialV2,
        verificationMethod2,
        mockSecrets
      );

      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
      expect(result1).not.toBe(result2);

      // Validate both JWT structures
      const parts1 = result1.split(".");
      const parts2 = result2.split(".");

      expect(parts1).toHaveLength(3);
      expect(parts2).toHaveLength(3);

      const header1 = JSON.parse(
        Buffer.from(parts1[0], "base64url").toString()
      );
      const header2 = JSON.parse(
        Buffer.from(parts2[0], "base64url").toString()
      );

      expect(header1.alg).toBe("Ed25519");
      expect(header2.alg).toBe("ES256");
      expect(header1.iss).toBe(verificationMethod1.split("#")[0]);
      expect(header2.iss).toBe(verificationMethod2.split("#")[0]);
    });
  });

  describe("OpenID4VCI proof JWT (signProofOfPossession*)", () => {
    it("should sign a VC as OID4VCI proof JWT with extra JOSE header fields", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:example.com#key-oid4vci-vc";

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets,
      );

      const signedJwt = await service.signProofOfPossession(
        exampleCredentialV1,
        verificationMethod,
        mockSecrets,
        {
          custom: "header-passthrough",
        },
      );

      const parts = signedJwt.split(".");
      expect(parts).toHaveLength(3);
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

      // Appendix F.1: JOSE header — typ, alg, kid; other header params from additionalHeaders
      expect(header.typ).toBe("openid4vci-proof+jwt");
      expect(header.alg).toBe("Ed25519");
      expect(header.kid).toBe(verificationMethod);
      expect(header.custom).toBe("header-passthrough");
      expect(header).not.toHaveProperty("iat");
      expect(header).not.toHaveProperty("iss");

      // Appendix F.1: JWT body — iat, iss (optional), aud/nonce when applicable
      expect(typeof payload.iat).toBe("number");
      expect(payload.iss).toBe(verificationMethod.split("#")[0]);
      expect(payload.type).toEqual(exampleCredentialV1.type);
      expect(payload.issuer).toBe("did:web:example.com");
    });

    it("should sign a VP as OID4VCI proof JWT with nonce and aud in the JWT body", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:example.com#key-oid4vci-vp";

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets,
      );

      const signedCredentialJWT = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets,
      );

      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:oid4vci-vp-test",
        type: ["VerifiablePresentation"],
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      const cNonce = "c_nonce-from-issuer-oid4vci-test";
      const credentialIssuerId = "https://credential-issuer.example.com";

      const signedPresentation = await service.signProofOfPossession(
        presentation,
        verificationMethod,
        mockSecrets,
        cNonce,
        credentialIssuerId,
      );

      const parts = signedPresentation.split(".");
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

      // Appendix F.1: JOSE header — no iat/iss/nonce/aud (those are JWT body claims)
      expect(header.typ).toBe("openid4vci-proof+jwt");
      expect(header.kid).toBe(verificationMethod);
      expect(header).not.toHaveProperty("iat");
      expect(header).not.toHaveProperty("iss");
      expect(header).not.toHaveProperty("nonce");
      expect(header).not.toHaveProperty("aud");

      expect(typeof payload.iat).toBe("number");
      expect(payload.iss).toBe(verificationMethod.split("#")[0]);
      expect(payload.nonce).toBe(cNonce);
      expect(payload.aud).toBe(credentialIssuerId);
      expect(payload.type).toContain("VerifiablePresentation");
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
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Sign a credential first
      const signedCredentialJWT = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Create presentation with enveloped credential
      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        type: ["VerifiablePresentation", "ExamplePresentation"],
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      // Sign the presentation
      const signedPresentation = await service.signPresentation(
        presentation,
        verificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();
      expect(typeof signedPresentation).toBe("string");

      // Validate JWT structure
      const parts = signedPresentation.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      expect(header.alg).toBe("Ed25519");
      expect(header.kid).toBe(verificationMethod);
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString()
      );
      expect(payload.type).toContain("VerifiablePresentation");
      expect(payload.type).toContain("ExamplePresentation");
      expect(payload.id).toBe("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5");
      expect(Array.isArray(payload.verifiableCredential)).toBe(true);
      expect(payload.verifiableCredential).toHaveLength(1);
      expect(payload.verifiableCredential[0].type).toBe(
        "EnvelopedVerifiableCredential"
      );
      expect(payload.verifiableCredential[0].id).toBe(
        `data:application/vc+jwt,${signedCredentialJWT}`
      );
      expect(header.iat).toBeDefined();
    });

    it("should sign a presentation with a single enveloped credential (V2) (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:example.com#key1-jwk";

      // Generate key for signing
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Sign a credential first
      const signedCredentialJWT = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      // Create presentation with enveloped credential
      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        type: ["VerifiablePresentation", "ExamplePresentation"],
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      // Sign the presentation
      const signedPresentation = await service.signPresentation(
        presentation,
        verificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();
      expect(typeof signedPresentation).toBe("string");

      // Validate JWT structure
      const parts = signedPresentation.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      expect(header.alg).toBe("Ed25519");
      expect(header.kid).toBe(verificationMethod);
      expect(header.iss).toBe(verificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString()
      );
      expect(payload.type).toContain("VerifiablePresentation");
      expect(payload.type).toContain("ExamplePresentation");
      expect(payload.id).toBe("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5");
      expect(Array.isArray(payload.verifiableCredential)).toBe(true);
      expect(payload.verifiableCredential).toHaveLength(1);
      expect(payload.verifiableCredential[0].type).toBe(
        "EnvelopedVerifiableCredential"
      );
      expect(payload.verifiableCredential[0].id).toBe(
        `data:application/vc+jwt,${signedCredentialJWT}`
      );
      expect(header.iat).toBeDefined();
    });

    it("should sign a presentation with multiple enveloped credentials", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod1 = "did:web:example.com#key1";
      const verificationMethod2 = "did:web:example.com#key2";
      const presentationVerificationMethod = "did:web:holder.com#holderKey";

      // Generate keys for signing credentials
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod1,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        verificationMethod2,
        mockSecrets
      );

      // Generate key for signing presentation
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign multiple credentials
      const signedCredentialJWT1 = await service.signCredential(
        exampleCredentialV2,
        verificationMethod1,
        mockSecrets
      );

      const signedCredentialJWT2 = await service.signCredential(
        exampleCredentialV1WithIssuanceDate,
        verificationMethod2,
        mockSecrets
      );

      // Create presentation with multiple enveloped credentials
      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:4a8c1234-5678-4abc-b123-456789abcdef",
        type: ["VerifiablePresentation"],
        holder: "did:web:holder.com",
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT1}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT2}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      // Sign the presentation
      const signedPresentation = await service.signPresentation(
        presentation,
        presentationVerificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();
      expect(typeof signedPresentation).toBe("string");

      // Validate JWT structure
      const parts = signedPresentation.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      expect(header.alg).toBe("Ed25519");
      expect(header.kid).toBe(presentationVerificationMethod);
      expect(header.iss).toBe(presentationVerificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString()
      );
      expect(payload.type).toContain("VerifiablePresentation");
      expect(payload.holder).toBe("did:web:holder.com");
      expect(Array.isArray(payload.verifiableCredential)).toBe(true);
      expect(payload.verifiableCredential).toHaveLength(2);
      expect(payload.verifiableCredential[0].type).toBe(
        "EnvelopedVerifiableCredential"
      );
      expect(payload.verifiableCredential[1].type).toBe(
        "EnvelopedVerifiableCredential"
      );
      expect(header.iat).toBeDefined();
    });

    it("should sign a presentation with multiple enveloped credentials (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod1 = "did:web:example.com#key1-jwk";
      const verificationMethod2 = "did:web:example.com#key2-jwk";
      const presentationVerificationMethod = "did:web:holder.com#holderKey-jwk";

      // Generate keys for signing credentials
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod1,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        verificationMethod2,
        mockSecrets
      );

      // Generate key for signing presentation
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign multiple credentials
      const signedCredentialJWT1 = await service.signCredential(
        exampleCredentialV2,
        verificationMethod1,
        mockSecrets
      );

      const signedCredentialJWT2 = await service.signCredential(
        exampleCredentialV1WithIssuanceDate,
        verificationMethod2,
        mockSecrets
      );

      // Create presentation with multiple enveloped credentials
      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:4a8c1234-5678-4abc-b123-456789abcdef",
        type: ["VerifiablePresentation"],
        holder: "did:web:holder.com",
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT1}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT2}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      // Sign the presentation
      const signedPresentation = await service.signPresentation(
        presentation,
        presentationVerificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();
      expect(typeof signedPresentation).toBe("string");

      // Validate JWT structure
      const parts = signedPresentation.split(".");
      expect(parts).toHaveLength(3);

      // Decode and validate header
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      expect(header.alg).toBe("Ed25519");
      expect(header.kid).toBe(presentationVerificationMethod);
      expect(header.iss).toBe(presentationVerificationMethod.split("#")[0]);

      // Decode and validate payload
      const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString()
      );
      expect(payload.type).toContain("VerifiablePresentation");
      expect(payload.holder).toBe("did:web:holder.com");
      expect(Array.isArray(payload.verifiableCredential)).toBe(true);
      expect(payload.verifiableCredential).toHaveLength(2);
      expect(payload.verifiableCredential[0].type).toBe(
        "EnvelopedVerifiableCredential"
      );
      expect(payload.verifiableCredential[1].type).toBe(
        "EnvelopedVerifiableCredential"
      );
      expect(header.iat).toBeDefined();
    });

    it("should sign a presentation with ES256 algorithm", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey";
      const presentationVerificationMethod = "did:web:holder.com#presKey";

      // Generate keys
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        credentialVerificationMethod,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign credential
      const signedCredentialJWT = await service.signCredential(
        exampleCredentialV2,
        credentialVerificationMethod,
        mockSecrets
      );

      // Create and sign presentation with ES256
      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:12345678-1234-5678-1234-567812345678",
        type: ["VerifiablePresentation"],
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      const signedPresentation = await service.signPresentation(
        presentation,
        presentationVerificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();

      // Validate header shows ES256
      const parts = signedPresentation.split(".");
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      expect(header.alg).toBe("ES256");
      expect(header.kid).toBe(presentationVerificationMethod);
      expect(header.iss).toBe(presentationVerificationMethod.split("#")[0]);
    });

    it("should sign a presentation with ES256 algorithm (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey-jwk";
      const presentationVerificationMethod = "did:web:holder.com#presKey-jwk";

      // Generate keys
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        credentialVerificationMethod,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign credential
      const signedCredentialJWT = await service.signCredential(
        exampleCredentialV2,
        credentialVerificationMethod,
        mockSecrets
      );

      // Create and sign presentation with ES256
      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:12345678-1234-5678-1234-567812345678",
        type: ["VerifiablePresentation"],
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      const signedPresentation = await service.signPresentation(
        presentation,
        presentationVerificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();

      // Validate header shows ES256
      const parts = signedPresentation.split(".");
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      expect(header.alg).toBe("ES256");
      expect(header.kid).toBe(presentationVerificationMethod);
      expect(header.iss).toBe(presentationVerificationMethod.split("#")[0]);
    });

    it("should sign a presentation with PS256 algorithm", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey";
      const presentationVerificationMethod = "did:web:holder.com#presKey";

      // Generate keys
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        credentialVerificationMethod,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign credential
      const signedCredentialJWT = await service.signCredential(
        exampleCredentialV1WithIssuanceDate,
        credentialVerificationMethod,
        mockSecrets
      );

      // Create and sign presentation with PS256
      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:abcdef12-3456-7890-abcd-ef1234567890",
        type: ["VerifiablePresentation"],
        holder: "did:web:holder.com",
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      const signedPresentation = await service.signPresentation(
        presentation,
        presentationVerificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();

      // Validate header shows PS256
      const parts = signedPresentation.split(".");
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      expect(header.alg).toBe("PS256");
      expect(header.kid).toBe(presentationVerificationMethod);
      expect(header.iss).toBe(presentationVerificationMethod.split("#")[0]);
    });

    it("should sign a presentation with PS256 algorithm (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey-jwk";
      const presentationVerificationMethod = "did:web:holder.com#presKey-jwk";

      // Generate keys
      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        credentialVerificationMethod,
        mockSecrets
      );

      await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        presentationVerificationMethod,
        mockSecrets
      );

      // Sign credential
      const signedCredentialJWT = await service.signCredential(
        exampleCredentialV1WithIssuanceDate,
        credentialVerificationMethod,
        mockSecrets
      );

      // Create and sign presentation with PS256
      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:abcdef12-3456-7890-abcd-ef1234567890",
        type: ["VerifiablePresentation"],
        holder: "did:web:holder.com",
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      const signedPresentation = await service.signPresentation(
        presentation,
        presentationVerificationMethod,
        mockSecrets
      );

      expect(signedPresentation).toBeDefined();

      // Validate header shows PS256
      const parts = signedPresentation.split(".");
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      expect(header.alg).toBe("PS256");
      expect(header.kid).toBe(presentationVerificationMethod);
      expect(header.iss).toBe(presentationVerificationMethod.split("#")[0]);
    });

    it("should merge additional JOSE headers on OID4VCI proof JWT (signProofOfPossession)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:example.com#key-iat";

      await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      const signedCredentialJWT = await service.signCredential(
        exampleCredentialV2,
        verificationMethod,
        mockSecrets
      );

      const presentation: VerifiablePresentation = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        type: ["VerifiablePresentation"],
        verifiableCredential: [
          {
            "@context": "https://www.w3.org/ns/credentials/v2",
            id: `data:application/vc+jwt,${signedCredentialJWT}`,
            type: "EnvelopedVerifiableCredential",
          } as any,
        ],
      };

      const signedPresentation = await service.signProofOfPossession(
        presentation,
        verificationMethod,
        mockSecrets,
        "challenge-val",
        "https://issuer.example.com",
        { custom: "x" },
      );

      const parts = signedPresentation.split(".");
      const header = JSON.parse(
        Buffer.from(parts[0], "base64url").toString()
      );
      const payload = JSON.parse(
        Buffer.from(parts[1], "base64url").toString()
      );

      // OID4VCI F.1: proof claims live in the JWT body, not the JOSE header
      expect(header.typ).toBe("openid4vci-proof+jwt");
      expect(header.custom).toBe("x");
      expect(header.kid).toBe(verificationMethod);
      expect(header).not.toHaveProperty("iat");
      expect(header).not.toHaveProperty("iss");
      expect(header).not.toHaveProperty("nonce");
      expect(header).not.toHaveProperty("aud");
      expect(typeof payload.iat).toBe("number");
      expect(payload.nonce).toBe("challenge-val");
      expect(payload.aud).toBe("https://issuer.example.com");
      expect(payload.iss).toBe(verificationMethod.split("#")[0]);
    });
  });
});
