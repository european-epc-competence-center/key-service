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
  VerifiablePresentation,
} from "../types/verifiable-credential.types";

import * as fs from "fs";
import { SignatureType } from "../types/key-types.enum";
import { KeyType } from "../types/key-format.enum";
import { VerificationMethod } from "../types/verification-method.types";
// @ts-ignore
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
// @ts-ignore
import jsigs from "jsonld-signatures";
// @ts-ignore
import { verify as verifyPresentation } from "@digitalbazaar/vc";
// @ts-ignore
import {cryptosuite as eddsaRdfc2022CryptoSuite} from "@digitalbazaar/eddsa-rdfc-2022-cryptosuite";
// @ts-ignore
import {cryptosuite as ecdsaRdfc2019CryptoSuite} from "@digitalbazaar/ecdsa-rdfc-2019-cryptosuite";
// @ts-ignore
import {cryptosuite as rsaRdfc2025CryptoSuite} from "@eecc/rsa-rdfc-2025-cryptosuite";
// @ts-ignore
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
// @ts-ignore
import * as EcdsaMultikey from "@digitalbazaar/ecdsa-multikey";
// @ts-ignore
import * as RsaMultikey from "@eecc/rsa-multikey";

// Mock fs module for this test file only
jest.mock("fs");

// Increase timeout for this test file to allow fetching remote context URLs
jest.setTimeout(120000); // 2 minutes

// Default challenge string for presentation tests
const DEFAULT_CHALLENGE = "test-challenge-12345";

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
async function verifyDataIntegrityCredential(
  credential: VerifiableCredential,
  verificationMethodObj: VerificationMethod
): Promise<boolean> {
  try {
    // Extract cryptosuite from proof to determine key type
    const proof = Array.isArray(credential.proof) ? credential.proof[0] : credential.proof;
    if (!proof || proof.type !== "DataIntegrityProof" || !proof.cryptosuite) {
      throw new Error("Invalid or missing DataIntegrityProof with cryptosuite");
    }
    
    const cryptosuiteName = proof.cryptosuite;
    let cryptosuite;
    
    // Determine cryptosuite based on cryptosuite name
    if (cryptosuiteName === "eddsa-rdfc-2022") {
      cryptosuite = eddsaRdfc2022CryptoSuite;
    } else if (cryptosuiteName === "ecdsa-rdfc-2019") {
      cryptosuite = ecdsaRdfc2019CryptoSuite;
    } else if (cryptosuiteName === "rsa-rdfc-2025") {
      cryptosuite = rsaRdfc2025CryptoSuite;
    } else {
      throw new Error(`Unsupported cryptosuite: ${cryptosuiteName}`);
    }

    // DataIntegrityProof will use cryptosuite.createVerifier internally during verification
    const suite = new DataIntegrityProof({
      cryptosuite,
    });

    // Create a documentLoader that can resolve the verification method
    const baseDocumentLoader = await DocumentLoaderService.getDocumentLoader();
    const documentLoader = async (url: string) => {
      console.log("DocumentLoader requested URL:", url);
      
      // If the URL matches our verification method ID, return the verificationMethodObj
      if (url === verificationMethodObj.id) {
        console.log("Returning verificationMethodObj for:", url);
        return {
          contextUrl: null,
          documentUrl: url,
          document: verificationMethodObj,
        };
      }
      
      // If the URL is the controller (DID), return a minimal DID document with the verification method
      if (url === verificationMethodObj.controller) {
        console.log("Returning DID document for controller:", url);
        return {
          contextUrl: null,
          documentUrl: url,
          document: {
            "@context": ["https://www.w3.org/ns/did/v1"],
            id: verificationMethodObj.controller,
            verificationMethod: [verificationMethodObj],
            assertionMethod: [verificationMethodObj.id],
            authentication: [verificationMethodObj.id],
          },
        };
      }
      
      // Handle DID URLs (did:web:example.com)
      if (url.startsWith("did:")) {
        console.log("Handling DID URL:", url);
        // Extract the DID from the verification method if it matches
        const didFromVerificationMethod = verificationMethodObj.id.split("#")[0];
        if (url === didFromVerificationMethod || url === verificationMethodObj.controller) {
          return {
            contextUrl: null,
            documentUrl: url,
            document: {
              "@context": ["https://www.w3.org/ns/did/v1"],
              id: url,
              verificationMethod: [verificationMethodObj],
              assertionMethod: [verificationMethodObj.id],
              authentication: [verificationMethodObj.id],
            },
          };
        }
      }
      
      // Otherwise, use the base documentLoader
      try {
        return await baseDocumentLoader(url);
      } catch (error: any) {
        console.log("Base documentLoader failed for URL:", url, "Error:", error?.message);
        throw error;
      }
    };

    const result = await jsigs.verify(credential, {
      suite,
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader,
    });
    
    if (!result.verified) {
      console.log("Verification failed. Result:", JSON.stringify(result, null, 2));
      if (result.error) {
        console.log("Verification error:", result.error);
      }
      if (result.proofResults) {
        console.log("Proof results:", JSON.stringify(result.proofResults, null, 2));
      }
    }
    
    return result.verified === true;
  } catch (error: any) {
    console.log("Verification exception:", error);
    console.log("Error message:", error?.message);
    console.log("Error stack:", error?.stack);
    if (error?.details) {
      console.log("Error details:", JSON.stringify(error.details, null, 2));
    }
    return false;
  }
}

async function verifyDataIntegrityPresentation(
  presentation: VerifiablePresentation,
  verificationMethodObj: VerificationMethod,
  challenge: string = DEFAULT_CHALLENGE,
  domain?: string
): Promise<boolean> {
  try {
    // Extract cryptosuite from proof to determine key type
    const proof = Array.isArray(presentation.proof) ? presentation.proof[0] : presentation.proof;
    if (!proof || proof.type !== "DataIntegrityProof" || !proof.cryptosuite) {
      throw new Error("Invalid or missing DataIntegrityProof with cryptosuite");
    }
    
    const cryptosuiteName = proof.cryptosuite;
    let cryptosuite;
    
    // Determine cryptosuite based on cryptosuite name
    if (cryptosuiteName === "eddsa-rdfc-2022") {
      cryptosuite = eddsaRdfc2022CryptoSuite;
    } else if (cryptosuiteName === "ecdsa-rdfc-2019") {
      cryptosuite = ecdsaRdfc2019CryptoSuite;
    } else if (cryptosuiteName === "rsa-rdfc-2025") {
      cryptosuite = rsaRdfc2025CryptoSuite;
    } else {
      throw new Error(`Unsupported cryptosuite: ${cryptosuiteName}`);
    }

    // DataIntegrityProof will use cryptosuite.createVerifier internally during verification
    const suite = new DataIntegrityProof({
      cryptosuite,
    });

    // Create a documentLoader that can resolve the verification method
    const baseDocumentLoader = await DocumentLoaderService.getDocumentLoader();
    const documentLoader = async (url: string) => {
      
      // If the URL matches our verification method ID, return the verificationMethodObj
      if (url === verificationMethodObj.id) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: verificationMethodObj,
        };
      }
      
      // If the URL is the controller (DID), return a minimal DID document with the verification method
      if (url === verificationMethodObj.controller) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: {
            "@context": ["https://www.w3.org/ns/did/v1"],
            id: verificationMethodObj.controller,
            verificationMethod: [verificationMethodObj],
            assertionMethod: [verificationMethodObj.id],
            authentication: [verificationMethodObj.id],
          },
        };
      }
      
      // Handle DID URLs (did:web:example.com)
      if (url.startsWith("did:")) {
        // Extract the DID from the verification method if it matches
        const didFromVerificationMethod = verificationMethodObj.id.split("#")[0];
        if (url === didFromVerificationMethod || url === verificationMethodObj.controller) {
          return {
            contextUrl: null,
            documentUrl: url,
            document: {
              "@context": ["https://www.w3.org/ns/did/v1"],
              id: url,
              verificationMethod: [verificationMethodObj],
              assertionMethod: [verificationMethodObj.id],
              authentication: [verificationMethodObj.id],
            },
          };
        }
      }
      
      // Otherwise, use the base documentLoader
      try {
        return await baseDocumentLoader(url);
      } catch (error: any) {
        throw error;
      }
    };

    const result = await verifyPresentation({
      presentation,
      suite,
      documentLoader,
      challenge,
      domain,
    });
    
    if (!result.verified) {
      console.log("Presentation verification failed. Result:", JSON.stringify(result, null, 2));
      if (result.error) {
        console.log("Verification error:", result.error);
      }
      if (result.proofResults) {
        console.log("Proof results:", JSON.stringify(result.proofResults, null, 2));
      }
    }
    
    return result.verified === true;
  } catch (error: any) {
    console.log("Presentation verification exception:", error);
    console.log("Error message:", error?.message);
    console.log("Error stack:", error?.stack);
    if (error?.details) {
      console.log("Error details:", JSON.stringify(error.details, null, 2));
    }
    return false;
  }
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

  const exampleRenderedCredentialV2: any = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://ref.gs1.org/gs1/vc/license-context",
      "https://digitalbazaar.github.io/vc-render-method-context/contexts/v1.jsonld",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "id": "https://example.com/credentials/123",
    "type": [
      "VerifiableCredential",
      "ExampleCredential"
    ],
    "issuer": {
      "id": "did:example:issuer",
      "name": "Example Issuer"
    },
    "name": "Example Credential with Render Method",
    "description": "This is a test credential with a renderMethod property.",
    "validFrom": "2024-01-25T12:30:00.000Z",
    "credentialSubject": {
      "id": "did:web:gs1.github.io:GS1DigitalLicenses:dids:fake_mc_did",
      "organization": {
        "gs1:partyGLN": "0810159550000",
        "gs1:organizationName": "Healthy Tots"
      },
      "extendsCredential": "https://gs1.github.io/GS1DigitalLicenses/samples/gs1-prefix-license-sample.jwt",
      "licenseValue": "081015955",
      "alternativeLicenseValue": "81015955"
    },
    "credentialSchema": {
      "id": "https://gs1.github.io/GS1DigitalLicenses/schemas/companyprefix.json",
      "type": "JsonSchema"
    },
    "credentialStatus": {
      "id": "https://gs1.github.io/GS1DigitalLicenses/status/mo_status_list.jwt#10010",
      "type": "BitstringStatusListEntry",
      "statusPurpose": "revocation",
      "statusListIndex": "10010",
      "statusListCredential": "https://gs1.github.io/GS1DigitalLicenses/status/mo_status_list.jwt"
    },
    "renderMethod": [
      {
        "id": "https://example.com/templates/template.svg",
        "type": "SvgRenderingTemplate2023",
        "name": "Web Display",
        "css3MediaQuery": "@media (min-aspect-ratio: 3/1)"
      }
    ]
  }

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

    // Reset credential objects by removing any proofs that may have been added
    // The @digitalbazaar/vc issue() function mutates the credential object
    delete (exampleCredentialV1 as any).proof;
    delete (exampleCredentialV2 as any).proof;
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      expect(result.type).toEqual(exampleCredentialV1.type);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that the Data Integrity context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(
        result,
        verificationMethodObj
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      expect(result.type).toEqual(exampleCredentialV1.type);
      expect(result.credentialSubject).toEqual(
        exampleCredentialV1.credentialSubject
      );

      // Verify that the Data Integrity context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(
        result,
        verificationMethodObj
      );
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V2 verifiable credential with Ed25519 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
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

    it("should sign a VC V2 verifiable credential with Ed25519 key pair (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-jwk";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
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

      // Verify original contexts are preserved
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and preserve existing issuanceDate", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-with-date";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      // Verify that the Data Integrity context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and preserve existing issuanceDate (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-with-date-jwk";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      // Verify that the Data Integrity context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      // Verify that the Data Integrity context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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

    it("should sign a VC V1 verifiable credential with Ed25519 key pair and set issuanceDate if absent (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#test-key-no-date-jwk";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Verify the credential content is preserved
      // Verify that the Data Integrity context is added during signing
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

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

    it("should sign a VC V2 verifiable credential with Ed25519 key pair and preserve existing validFrom (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-with-date-jwk";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

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
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

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

    it("should sign a VC V2 verifiable credential with Ed25519 key pair and leave validFrom empty if absent (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#v2-key-no-date-jwk";

      // Generate a key pair first
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBeDefined();
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

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

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V1 verifiable credential with ES256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#es256-test-key";

      // Generate an ES256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("ecdsa-rdfc-2019");
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

      // Verify that the Data Integrity context is present for ES256 signatures
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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

    it("should sign a VC V1 verifiable credential with ES256 key pair (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#es256-test-key-jwk";

      // Generate an ES256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("ecdsa-rdfc-2019");
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

      // Verify that the Data Integrity context is present for ES256 signatures
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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

    it("should sign a VC V2 verifiable credential with ES256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#es256-v2-key";

      // Generate an ES256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("ecdsa-rdfc-2019");
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

    it("should sign a VC V2 verifiable credential with ES256 key pair (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#es256-v2-key-jwk";

      // Generate an ES256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("ecdsa-rdfc-2019");
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

      // Verify original contexts are preserved
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Verify issuer was updated to match the key pair controller
      expect(result.issuer).toBe("did:web:example.com");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a VC V1 verifiable credential with PS256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#ps256-test-key";

      // Generate a PS256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("rsa-rdfc-2025");
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

      // Verify that the jws-2020 context is present for PS256 signatures
      expect(result["@context"]).toContain(
        "https://w3id.org/security/data-integrity/v2"
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

    it("should sign a VC V2 verifiable credential with PS256 key pair", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#ps256-v2-key";

      // Generate a PS256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("rsa-rdfc-2025");
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

    it("should sign a VC V2 verifiable credential with PS256 key pair (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:web:example.com#ps256-v2-key-jwk";

      // Generate a PS256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
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
      expect(proof?.type).toBe("DataIntegrityProof");
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

      const verificationMethodObj1 = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod1,
        mockSecrets
      );

      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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

    it("should handle database operations and maintain consistency (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      const initialCount = await encryptedKeyRepository.count();
      expect(initialCount).toBe(0);

      // Generate multiple Ed25519 keys for different credentials
      const verificationMethod1 = "did:web:test1.com#key1-jwk";
      const verificationMethod2 = "did:web:test2.com#key2-jwk";

      const verificationMethodObj1 = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod1,
        mockSecrets
      );

      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
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
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
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

    it("should sign a presentation with a single enveloped credential (V2) (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:example.com#key1-jwk";

      // Generate key for signing
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
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
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
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
      const verificationMethodObj1 = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod1,
        mockSecrets
      );

      const verificationMethodObj2 = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod2,
        mockSecrets
      );

      // Generate key for signing presentation
      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
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

    it("should sign a presentation with multiple embedded credentials (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod1 = "did:web:example.com#key1-jwk";
      const verificationMethod2 = "did:web:example.com#key2-jwk";
      const presentationVerificationMethod = "did:web:holder.com#holderKey-jwk";

      // Generate keys for signing credentials
      const verificationMethodObj1 = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod1,
        mockSecrets
      );

      const verificationMethodObj2 = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod2,
        mockSecrets
      );

      // Generate key for signing presentation
      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
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
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
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
      const credentialVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        credentialVerificationMethod,
        mockSecrets
      );

      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.challenge).toBe(challenge);
      expect(proof?.domain).toBe(domain);
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
    });

    it("should sign a presentation with challenge and domain (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey-jwk";
      const presentationVerificationMethod = "did:web:holder.com#presKey-jwk";

      // Generate keys
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        credentialVerificationMethod,
        mockSecrets
      );

      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
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
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        credentialVerificationMethod,
        mockSecrets
      );

      // Generate ES256 key for presentation
      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
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
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("ecdsa-rdfc-2019");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Verify original contexts are preserved
      expect(signedPresentation["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(signedPresentation["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Verify holder was automatically set
      expect(signedPresentation.holder).toBe("did:web:holder.com");

    });

    it("should sign a presentation with ES256 key pair (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey-jwk";
      const presentationVerificationMethod = "did:web:holder.com#es256PresKey-jwk";

      // Generate Ed25519 key for credential
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        credentialVerificationMethod,
        mockSecrets
      );

      // Generate ES256 key for presentation
      const presentationVerificationMethodObj = await keyService.generateKeyPair(
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
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Verify original contexts are preserved
      expect(signedPresentation["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(signedPresentation["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Verify holder was automatically set
      expect(signedPresentation.holder).toBe("did:web:holder.com");

    });

    it("should automatically set holder if not provided", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:holder.com#holderKey";

      // Generate key
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
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
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      // Verify holder was automatically set to the key's controller
      expect(signedPresentation.holder).toBe("did:web:holder.com");
    });

    it("should automatically set holder if not provided (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const verificationMethod = "did:web:holder.com#holderKey-jwk";

      // Generate key
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
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
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      // Verify holder was automatically set to the key's controller
      expect(signedPresentation.holder).toBe("did:web:holder.com");
    });

    it("should sign a presentation with PS256 key pair", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey";
      const presentationVerificationMethod = "did:web:holder.com#ps256PresKey";

      // Generate Ed25519 key for credential
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        credentialVerificationMethod,
        mockSecrets
      );

      // Generate PS256 key for presentation
      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
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
        id: "urn:uuid:ps256-test-presentation",
        type: ["VerifiablePresentation"],
        verifiableCredential: [signedCredential],
      };

      // Sign the presentation with PS256 key
      const signedPresentation = await service.signVP(
        presentation,
        presentationVerificationMethod,
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("rsa-rdfc-2025");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Verify original contexts are preserved
      expect(signedPresentation["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(signedPresentation["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Verify holder was automatically set
      expect(signedPresentation.holder).toBe("did:web:holder.com");
    });

    it("should sign a presentation with PS256 key pair (JWK)", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKey-jwk";
      const presentationVerificationMethod = "did:web:holder.com#ps256PresKey-jwk";

      // Generate Ed25519 key for credential
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        credentialVerificationMethod,
        mockSecrets
      );

      // Generate PS256 key for presentation
      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
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
        id: "urn:uuid:ps256-test-presentation",
        type: ["VerifiablePresentation"],
        verifiableCredential: [signedCredential],
      };

      // Sign the presentation with PS256 key
      const signedPresentation = await service.signVP(
        presentation,
        presentationVerificationMethod,
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      // Handle both single proof and proof array cases
      const proof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Verify original contexts are preserved
      expect(signedPresentation["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(signedPresentation["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Verify holder was automatically set
      expect(signedPresentation.holder).toBe("did:web:holder.com");
    });

    it("should sign a presentation with challenge and domain using PS256", async () => {
      const encryptedKeyRepository = dataSource.getRepository(EncryptedKey);
      await encryptedKeyRepository.clear();

      const credentialVerificationMethod = "did:web:issuer.com#credKeyPs256";
      const presentationVerificationMethod = "did:web:holder.com#ps256PresKeyChallenge";

      // Generate keys
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        credentialVerificationMethod,
        mockSecrets
      );

      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
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

      // Create and sign presentation with challenge and domain
      const presentation: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "urn:uuid:ps256-challenge-presentation",
        type: ["VerifiablePresentation"],
        verifiableCredential: [signedCredential],
      };

      const challenge = "ps256-test-challenge-67890";
      const domain = "https://ps256.example.com";

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
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("rsa-rdfc-2025");
      expect(proof?.verificationMethod).toBe(presentationVerificationMethod);
      expect(proof?.proofPurpose).toBe("authentication");
      expect(proof?.challenge).toBe(challenge);
      expect(proof?.domain).toBe(domain);
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Verify the signature with the generated public key
    });
  });

  describe("Render Credential Signing", () => {
    it("should sign a V2 credential with renderMethod using Ed25519 and preserve all properties", async () => {
      // Arrange
      const verificationMethod = "did:example:issuer#render-key";

      // Generate an Ed25519 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Create a fresh copy of the credential for this test
      const credentialCopy = JSON.parse(JSON.stringify(exampleRenderedCredentialV2));

      // Act
      const result: any = await service.signVC(
        credentialCopy,
        verificationMethod,
        mockSecrets
      );

      // Assert - Proof exists and is valid
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBe("assertionMethod");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Assert - RenderMethod is preserved
      expect(result.renderMethod).toBeDefined();
      expect(Array.isArray(result.renderMethod)).toBe(true);
      expect(result.renderMethod).toHaveLength(1);
      
      const renderMethods = Array.isArray(result.renderMethod)
        ? result.renderMethod
        : [result.renderMethod!];
      expect(renderMethods[0].id).toBe(
        "https://example.com/templates/template.svg"
      );
      expect(renderMethods[0].type).toBe("SvgRenderingTemplate2023");
      expect(renderMethods[0].name).toBe("Web Display");

      // Assert - All contexts are preserved including render method context
      expect(result["@context"]).toBeDefined();
      expect(Array.isArray(result["@context"])).toBe(true);
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Assert - Other credential properties are preserved
      expect(result.id).toBe(credentialCopy.id);
      expect(result.type).toEqual(credentialCopy.type);
      expect(result.name).toBe(credentialCopy.name);
      expect(result.description).toBe(credentialCopy.description);
      expect(result.validFrom).toBe(credentialCopy.validFrom);
      expect(result.credentialSubject).toEqual(
        credentialCopy.credentialSubject
      );

      // Assert - Issuer structure is preserved (with updated id)
      expect(result.issuer).toBeDefined();
      expect(typeof result.issuer).toBe("object");
      expect((result.issuer as any).id).toBe("did:example:issuer");
      expect((result.issuer as any).name).toBe("Example Issuer");
    });

    it("should sign a V2 credential with renderMethod using Ed25519 and preserve all properties (JWK)", async () => {
      // Arrange
      const verificationMethod = "did:example:issuer#render-key-jwk";

      // Generate an Ed25519 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Create a fresh copy of the credential for this test
      const credentialCopy = JSON.parse(JSON.stringify(exampleRenderedCredentialV2));

      // Act
      const result: any = await service.signVC(
        credentialCopy,
        verificationMethod,
        mockSecrets
      );

      // Assert - Proof exists and is valid
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBe("assertionMethod");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();

      // Assert - RenderMethod is preserved
      expect(result.renderMethod).toBeDefined();
      expect(Array.isArray(result.renderMethod)).toBe(true);
      expect(result.renderMethod).toHaveLength(1);
      
      const renderMethods = Array.isArray(result.renderMethod)
        ? result.renderMethod
        : [result.renderMethod!];
      expect(renderMethods[0].id).toBe(
        "https://example.com/templates/template.svg"
      );
      expect(renderMethods[0].type).toBe("SvgRenderingTemplate2023");
      expect(renderMethods[0].name).toBe("Web Display");

      // Assert - All contexts are preserved including render method context
      expect(result["@context"]).toBeDefined();
      expect(Array.isArray(result["@context"])).toBe(true);
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Assert - Other credential properties are preserved
      expect(result.id).toBe(credentialCopy.id);
      expect(result.type).toEqual(credentialCopy.type);
      expect(result.name).toBe(credentialCopy.name);
      expect(result.description).toBe(credentialCopy.description);
      expect(result.validFrom).toBe(credentialCopy.validFrom);
      expect(result.credentialSubject).toEqual(
        credentialCopy.credentialSubject
      );

      // Assert - Issuer structure is preserved (with updated id)
      expect(result.issuer).toBeDefined();
      expect(typeof result.issuer).toBe("object");
      expect((result.issuer as any).id).toBe("did:example:issuer");
      expect((result.issuer as any).name).toBe("Example Issuer");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a V2 credential with renderMethod using ES256 and preserve all properties", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const verificationMethod = "did:example:es256issuer#es256-render-key";

      // Generate an ES256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Create a fresh copy of the credential for this test
      const credentialCopy = JSON.parse(JSON.stringify(exampleRenderedCredentialV2));

      // Act
      const result: any = await service.signVC(
        credentialCopy,
        verificationMethod,
        mockSecrets
      );

      // Assert - Proof exists and is valid
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("ecdsa-rdfc-2019");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBe("assertionMethod");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Assert - RenderMethod is preserved
      expect(result.renderMethod).toBeDefined();
      expect(Array.isArray(result.renderMethod)).toBe(true);
      expect(result.renderMethod).toHaveLength(1);
      
      const renderMethodsES256 = Array.isArray(result.renderMethod)
        ? result.renderMethod
        : [result.renderMethod!];
      expect(renderMethodsES256[0].id).toBe(
        "https://example.com/templates/template.svg"
      );
      expect(renderMethodsES256[0].type).toBe("SvgRenderingTemplate2023");
      expect(renderMethodsES256[0].name).toBe("Web Display");

      // Assert - All contexts are preserved including render method context
      expect(result["@context"]).toBeDefined();
      expect(Array.isArray(result["@context"])).toBe(true);
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Assert - Other credential properties are preserved
      expect(result.id).toBe(credentialCopy.id);
      expect(result.type).toEqual(credentialCopy.type);
      expect(result.name).toBe(credentialCopy.name);
      expect(result.description).toBe(credentialCopy.description);
      expect(result.validFrom).toBe(credentialCopy.validFrom);
      expect(result.credentialSubject).toEqual(
        credentialCopy.credentialSubject
      );

      // Assert - Issuer structure is preserved (with updated id)
      expect(result.issuer).toBeDefined();
      expect(typeof result.issuer).toBe("object");
      expect((result.issuer as any).id).toBe("did:example:es256issuer");
      expect((result.issuer as any).name).toBe("Example Issuer");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a V2 credential with renderMethod using ES256 and preserve all properties (JWK)", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const verificationMethod = "did:example:es256issuer#es256-render-key-jwk";

      // Generate an ES256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ES256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Create a fresh copy of the credential for this test
      const credentialCopy = JSON.parse(JSON.stringify(exampleRenderedCredentialV2));

      // Act
      const result: any = await service.signVC(
        credentialCopy,
        verificationMethod,
        mockSecrets
      );

      // Assert - Proof exists and is valid
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("ecdsa-rdfc-2019");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBe("assertionMethod");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Assert - RenderMethod is preserved
      expect(result.renderMethod).toBeDefined();
      expect(Array.isArray(result.renderMethod)).toBe(true);
      expect(result.renderMethod).toHaveLength(1);
      
      const renderMethodsES256 = Array.isArray(result.renderMethod)
        ? result.renderMethod
        : [result.renderMethod!];
      expect(renderMethodsES256[0].id).toBe(
        "https://example.com/templates/template.svg"
      );
      expect(renderMethodsES256[0].type).toBe("SvgRenderingTemplate2023");
      expect(renderMethodsES256[0].name).toBe("Web Display");

      // Assert - All contexts are preserved including render method context
      expect(result["@context"]).toBeDefined();
      expect(Array.isArray(result["@context"])).toBe(true);
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Assert - Other credential properties are preserved
      expect(result.id).toBe(credentialCopy.id);
      expect(result.type).toEqual(credentialCopy.type);
      expect(result.name).toBe(credentialCopy.name);
      expect(result.description).toBe(credentialCopy.description);
      expect(result.validFrom).toBe(credentialCopy.validFrom);
      expect(result.credentialSubject).toEqual(
        credentialCopy.credentialSubject
      );

      // Assert - Issuer structure is preserved (with updated id)
      expect(result.issuer).toBeDefined();
      expect(typeof result.issuer).toBe("object");
      expect((result.issuer as any).id).toBe("did:example:es256issuer");
      expect((result.issuer as any).name).toBe("Example Issuer");
    });

    it("should sign a credential with multiple renderMethod entries", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const verificationMethod = "did:web:example.com#multi-render-key";

      const credentialWithMultipleRenders: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "https://example.com/credentials/456",
        "type": ["VerifiableCredential", "ExampleCredential"],
        "issuer": "did:web:example.com",
        "validFrom": "2024-01-01T00:00:00Z",
        "credentialSubject": {
          "id": "did:example:subject",
          "degree": {
            "type": "MasterDegree",
            "name": "Master of Science"
          }
        },
        "renderMethod": [
          {
            "id": "https://example.com/templates/mobile.svg",
            "type": "SvgRenderingTemplate2023",
            "name": "Mobile Display"
          },
          {
            "id": "https://example.com/templates/desktop.svg",
            "type": "SvgRenderingTemplate2023",
            "name": "Desktop Display"
          }
        ]
      };

      // Generate an Ed25519 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result: any = await service.signVC(
        credentialWithMultipleRenders,
        verificationMethod,
        mockSecrets
      );

      // Assert - Proof exists
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Assert - All renderMethod entries are preserved
      expect(result.renderMethod).toBeDefined();
      expect(Array.isArray(result.renderMethod)).toBe(true);
      expect(result.renderMethod).toHaveLength(2);

      const multipleRenderMethods = Array.isArray(result.renderMethod)
        ? result.renderMethod
        : [result.renderMethod!];

      expect(multipleRenderMethods[0].id).toBe(
        "https://example.com/templates/mobile.svg"
      );
      expect(multipleRenderMethods[0].type).toBe("SvgRenderingTemplate2023");
      expect(multipleRenderMethods[0].name).toBe("Mobile Display");

      expect(multipleRenderMethods[1].id).toBe(
        "https://example.com/templates/desktop.svg"
      );
      expect(multipleRenderMethods[1].type).toBe("SvgRenderingTemplate2023");
      expect(multipleRenderMethods[1].name).toBe("Desktop Display");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a credential with multiple renderMethod entries (JWK)", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const verificationMethod = "did:web:example.com#multi-render-key-jwk";

      const credentialWithMultipleRenders: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "https://example.com/credentials/456",
        "type": ["VerifiableCredential", "ExampleCredential"],
        "issuer": "did:web:example.com",
        "validFrom": "2024-01-01T00:00:00Z",
        "credentialSubject": {
          "id": "did:example:subject",
          "degree": {
            "type": "MasterDegree",
            "name": "Master of Science"
          }
        },
        "renderMethod": [
          {
            "id": "https://example.com/templates/mobile.svg",
            "type": "SvgRenderingTemplate2023",
            "name": "Mobile Display"
          },
          {
            "id": "https://example.com/templates/desktop.svg",
            "type": "SvgRenderingTemplate2023",
            "name": "Desktop Display"
          }
        ]
      };

      // Generate an Ed25519 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result: any = await service.signVC(
        credentialWithMultipleRenders,
        verificationMethod,
        mockSecrets
      );

      // Assert - Proof exists
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      // Assert - All renderMethod entries are preserved
      expect(result.renderMethod).toBeDefined();
      expect(Array.isArray(result.renderMethod)).toBe(true);
      expect(result.renderMethod).toHaveLength(2);

      const multipleRenderMethods = Array.isArray(result.renderMethod)
        ? result.renderMethod
        : [result.renderMethod!];

      expect(multipleRenderMethods[0].id).toBe(
        "https://example.com/templates/mobile.svg"
      );
      expect(multipleRenderMethods[0].type).toBe("SvgRenderingTemplate2023");
      expect(multipleRenderMethods[0].name).toBe("Mobile Display");

      expect(multipleRenderMethods[1].id).toBe(
        "https://example.com/templates/desktop.svg"
      );
      expect(multipleRenderMethods[1].type).toBe("SvgRenderingTemplate2023");
      expect(multipleRenderMethods[1].name).toBe("Desktop Display");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a credential with renderMethod and then include it in a presentation", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const credentialVerificationMethod = "did:example:issuer#cred-key";
      const presentationVerificationMethod = "did:example:holder#pres-key";

      // Generate keys
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        credentialVerificationMethod,
        mockSecrets
      );

      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.MULTIKEY,
        presentationVerificationMethod,
        mockSecrets
      );

      // Create a fresh copy of the credential for this test
      const credentialCopy = JSON.parse(JSON.stringify(exampleRenderedCredentialV2));

      // Act - Sign the rendered credential
      const signedCredential = await service.signVC(
        credentialCopy,
        credentialVerificationMethod,
        mockSecrets
      );

      // Create and sign a presentation containing the rendered credential
      const presentation: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:rendered-credential-presentation",
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [signedCredential]
      };

      const signedPresentation: any = await service.signVP(
        presentation,
        presentationVerificationMethod,
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      // Assert - Presentation is signed
      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      const presentationProof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(presentationProof).toBeDefined();
      expect(presentationProof?.type).toBe("DataIntegrityProof");
      expect(presentationProof?.proofPurpose).toBe("authentication");

      // Assert - Embedded credential still has renderMethod
      expect(signedPresentation.verifiableCredential).toBeDefined();
      expect(Array.isArray(signedPresentation.verifiableCredential)).toBe(true);
      expect(signedPresentation.verifiableCredential).toHaveLength(1);

      const verifiableCredentials = Array.isArray(signedPresentation.verifiableCredential)
        ? signedPresentation.verifiableCredential
        : [signedPresentation.verifiableCredential];
      const embeddedCredential = verifiableCredentials[0];
      expect(embeddedCredential.renderMethod).toBeDefined();
      expect(Array.isArray(embeddedCredential.renderMethod)).toBe(true);
      expect(embeddedCredential.renderMethod).toHaveLength(1);
      
      const embeddedRenderMethods = Array.isArray(embeddedCredential.renderMethod)
        ? embeddedCredential.renderMethod
        : [embeddedCredential.renderMethod!];
      expect(embeddedRenderMethods[0].id).toBe(
        "https://example.com/templates/template.svg"
      );

      // Assert - Credential proof is preserved
      expect(embeddedCredential.proof).toBeDefined();

    });

    it("should sign a credential with renderMethod and then include it in a presentation (JWK)", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const credentialVerificationMethod = "did:example:issuer#cred-key-jwk";
      const presentationVerificationMethod = "did:example:holder#pres-key-jwk";

      // Generate keys
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        credentialVerificationMethod,
        mockSecrets
      );

      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.ED25519_2020,
        KeyType.JWK,
        presentationVerificationMethod,
        mockSecrets
      );

      // Create a fresh copy of the credential for this test
      const credentialCopy = JSON.parse(JSON.stringify(exampleRenderedCredentialV2));

      // Act - Sign the rendered credential
      const signedCredential = await service.signVC(
        credentialCopy,
        credentialVerificationMethod,
        mockSecrets
      );

      // Create and sign a presentation containing the rendered credential
      const presentation: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:rendered-credential-presentation",
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [signedCredential]
      };

      const signedPresentation: any = await service.signVP(
        presentation,
        presentationVerificationMethod,
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      // Assert - Presentation is signed
      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      const presentationProof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(presentationProof).toBeDefined();
      expect(presentationProof?.type).toBe("DataIntegrityProof");
      expect(presentationProof?.cryptosuite).toBe("eddsa-rdfc-2022");
      expect(presentationProof?.proofPurpose).toBe("authentication");

      // Assert - Embedded credential still has renderMethod
      expect(signedPresentation.verifiableCredential).toBeDefined();
      expect(Array.isArray(signedPresentation.verifiableCredential)).toBe(true);
      expect(signedPresentation.verifiableCredential).toHaveLength(1);

      const verifiableCredentials = Array.isArray(signedPresentation.verifiableCredential)
        ? signedPresentation.verifiableCredential
        : [signedPresentation.verifiableCredential];
      const embeddedCredential = verifiableCredentials[0];
      expect(embeddedCredential.renderMethod).toBeDefined();
      expect(Array.isArray(embeddedCredential.renderMethod)).toBe(true);
      expect(embeddedCredential.renderMethod).toHaveLength(1);
      
      const embeddedRenderMethods = Array.isArray(embeddedCredential.renderMethod)
        ? embeddedCredential.renderMethod
        : [embeddedCredential.renderMethod!];
      expect(embeddedRenderMethods[0].id).toBe(
        "https://example.com/templates/template.svg"
      );

      // Assert - Credential proof is preserved
      expect(embeddedCredential.proof).toBeDefined();

    });

    it("should sign a V2 credential with renderMethod using PS256 and preserve all properties", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const verificationMethod = "did:example:ps256issuer#ps256-render-key";

      // Generate a PS256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Create a fresh copy of the credential for this test
      const credentialCopy = JSON.parse(JSON.stringify(exampleRenderedCredentialV2));

      // Act
      const result: any = await service.signVC(
        credentialCopy,
        verificationMethod,
        mockSecrets
      );

      // Assert - Proof exists and is valid
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("rsa-rdfc-2025");
      expect(proof?.verificationMethod).toBeDefined();
      expect(proof?.proofPurpose).toBe("assertionMethod");
      expect(proof?.created).toBeDefined();
      expect(proof?.proofValue).toBeDefined();
      expect(proof?.proofValue).toMatch(/^z/); // Should start with multibase header

      // Assert - RenderMethod is preserved
      expect(result.renderMethod).toBeDefined();
      expect(Array.isArray(result.renderMethod)).toBe(true);
      expect(result.renderMethod).toHaveLength(1);
      
      const renderMethodsPS256 = Array.isArray(result.renderMethod)
        ? result.renderMethod
        : [result.renderMethod!];
      expect(renderMethodsPS256[0].id).toBe(
        "https://example.com/templates/template.svg"
      );
      expect(renderMethodsPS256[0].type).toBe("SvgRenderingTemplate2023");
      expect(renderMethodsPS256[0].name).toBe("Web Display");

      // Assert - All contexts are preserved including render method context
      expect(result["@context"]).toBeDefined();
      expect(Array.isArray(result["@context"])).toBe(true);
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/v2"
      );
      expect(result["@context"]).toContain(
        "https://www.w3.org/ns/credentials/examples/v2"
      );

      // Assert - Other credential properties are preserved
      expect(result.id).toBe(credentialCopy.id);
      expect(result.type).toEqual(credentialCopy.type);
      expect(result.name).toBe(credentialCopy.name);
      expect(result.description).toBe(credentialCopy.description);
      expect(result.validFrom).toBe(credentialCopy.validFrom);
      expect(result.credentialSubject).toEqual(
        credentialCopy.credentialSubject
      );

      // Assert - Issuer structure is preserved (with updated id)
      expect(result.issuer).toBeDefined();
      expect(typeof result.issuer).toBe("object");
      expect((result.issuer as any).id).toBe("did:example:ps256issuer");
      expect((result.issuer as any).name).toBe("Example Issuer");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a credential with multiple renderMethod entries using PS256", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const verificationMethod = "did:web:example.com#ps256-multi-render-key";

      const credentialWithMultipleRenders: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "https://example.com/credentials/ps256-multi",
        "type": ["VerifiableCredential", "ExampleCredential"],
        "issuer": "did:web:example.com",
        "validFrom": "2024-01-01T00:00:00Z",
        "credentialSubject": {
          "id": "did:example:subject",
          "degree": {
            "type": "MasterDegree",
            "name": "Master of Science"
          }
        },
        "renderMethod": [
          {
            "id": "https://example.com/templates/ps256-mobile.svg",
            "type": "SvgRenderingTemplate2023",
            "name": "PS256 Mobile Display"
          },
          {
            "id": "https://example.com/templates/ps256-desktop.svg",
            "type": "SvgRenderingTemplate2023",
            "name": "PS256 Desktop Display"
          },
          {
            "id": "https://example.com/templates/ps256-print.svg",
            "type": "SvgRenderingTemplate2023",
            "name": "PS256 Print Display"
          }
        ]
      };

      // Generate a PS256 key pair
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        verificationMethod,
        mockSecrets
      );

      // Act
      const result: any = await service.signVC(
        credentialWithMultipleRenders,
        verificationMethod,
        mockSecrets
      );

      // Assert - Proof exists
      expect(result).toBeDefined();
      expect(result.proof).toBeDefined();

      const proof = Array.isArray(result.proof)
        ? result.proof[0]
        : result.proof;
      expect(proof).toBeDefined();
      expect(proof?.type).toBe("DataIntegrityProof");
      expect(proof?.cryptosuite).toBe("rsa-rdfc-2025");

      // Assert - All renderMethod entries are preserved
      expect(result.renderMethod).toBeDefined();
      expect(Array.isArray(result.renderMethod)).toBe(true);
      expect(result.renderMethod).toHaveLength(3);

      const multipleRenderMethods = Array.isArray(result.renderMethod)
        ? result.renderMethod
        : [result.renderMethod!];

      expect(multipleRenderMethods[0].id).toBe(
        "https://example.com/templates/ps256-mobile.svg"
      );
      expect(multipleRenderMethods[0].type).toBe("SvgRenderingTemplate2023");
      expect(multipleRenderMethods[0].name).toBe("PS256 Mobile Display");

      expect(multipleRenderMethods[1].id).toBe(
        "https://example.com/templates/ps256-desktop.svg"
      );
      expect(multipleRenderMethods[1].type).toBe("SvgRenderingTemplate2023");
      expect(multipleRenderMethods[1].name).toBe("PS256 Desktop Display");

      expect(multipleRenderMethods[2].id).toBe(
        "https://example.com/templates/ps256-print.svg"
      );
      expect(multipleRenderMethods[2].type).toBe("SvgRenderingTemplate2023");
      expect(multipleRenderMethods[2].name).toBe("PS256 Print Display");

      // Verify the signature with the generated public key
      const isSignatureValid = await verifyDataIntegrityCredential(result, verificationMethodObj);
      expect(isSignatureValid).toBe(true);
    });

    it("should sign a rendered credential with PS256 and include it in a presentation", async () => {
      // Arrange - Clear database for this test
      const repository = dataSource.getRepository(EncryptedKey);
      await repository.clear();
      
      const credentialVerificationMethod = "did:example:ps256issuer#ps256-cred-key";
      const presentationVerificationMethod = "did:example:ps256holder#ps256-pres-key";

      // Generate PS256 keys
      const verificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        credentialVerificationMethod,
        mockSecrets
      );

      const presentationVerificationMethodObj = await keyService.generateKeyPair(
        SignatureType.PS256,
        KeyType.JWK,
        presentationVerificationMethod,
        mockSecrets
      );

      // Create a fresh copy of the credential for this test
      const credentialCopy = JSON.parse(JSON.stringify(exampleRenderedCredentialV2));

      // Act - Sign the rendered credential with PS256
      const signedCredential = await service.signVC(
        credentialCopy,
        credentialVerificationMethod,
        mockSecrets
      );

      // Create and sign a presentation containing the rendered credential
      const presentation: any = {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:ps256-rendered-credential-presentation",
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [signedCredential]
      };

      const signedPresentation: any = await service.signVP(
        presentation,
        presentationVerificationMethod,
        mockSecrets,
        DEFAULT_CHALLENGE
      );

      // Assert - Presentation is signed with PS256
      expect(signedPresentation).toBeDefined();
      expect(signedPresentation.proof).toBeDefined();

      const presentationProof = Array.isArray(signedPresentation.proof)
        ? signedPresentation.proof[0]
        : signedPresentation.proof;
      expect(presentationProof).toBeDefined();
      expect(presentationProof?.type).toBe("DataIntegrityProof");
      expect(presentationProof?.cryptosuite).toBe("rsa-rdfc-2025");
      expect(presentationProof?.proofPurpose).toBe("authentication");
      expect(presentationProof?.proofValue).toMatch(/^z/);

      // Assert - Embedded credential still has renderMethod
      expect(signedPresentation.verifiableCredential).toBeDefined();
      expect(Array.isArray(signedPresentation.verifiableCredential)).toBe(true);
      expect(signedPresentation.verifiableCredential).toHaveLength(1);

      const verifiableCredentials = Array.isArray(signedPresentation.verifiableCredential)
        ? signedPresentation.verifiableCredential
        : [signedPresentation.verifiableCredential];
      const embeddedCredential = verifiableCredentials[0];
      expect(embeddedCredential.renderMethod).toBeDefined();
      expect(Array.isArray(embeddedCredential.renderMethod)).toBe(true);
      expect(embeddedCredential.renderMethod).toHaveLength(1);
      
      const embeddedRenderMethods = Array.isArray(embeddedCredential.renderMethod)
        ? embeddedCredential.renderMethod
        : [embeddedCredential.renderMethod!];
      expect(embeddedRenderMethods[0].id).toBe(
        "https://example.com/templates/template.svg"
      );

      // Assert - Credential proof is preserved and is PS256
      expect(embeddedCredential.proof).toBeDefined();
      const credentialProof = Array.isArray(embeddedCredential.proof)
        ? embeddedCredential.proof[0]
        : embeddedCredential.proof;
      expect(credentialProof?.type).toBe("DataIntegrityProof");
      expect(credentialProof?.proofValue).toMatch(/^z/);

    });
  });
});
