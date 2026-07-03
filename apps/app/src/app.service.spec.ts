import { Test, TestingModule } from "@nestjs/testing";
import { BadRequestException } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { DataSource } from "typeorm";
import * as fs from "fs";
import * as crypto from "crypto";

import { AppService } from "./app.service";
import { JwtSigningService } from "./signing-services/jwt-signing.service";
import { DataIntegritySigningService } from "./signing-services/data-integrity-signing.service";
import { KeyService } from "./key-services/key.service";
import { KeyStorageService } from "./key-services/key-storage.service";
import { SecretService } from "./key-services/secret.service";
import { FailedAttemptsCacheService } from "./key-services/failed-attempts-cache.service";
import { PayloadEncryptionService } from "./key-services/payload-encryption.service";
import { DocumentLoaderService } from "./utils/document-loader.service";
import { EncryptedKey } from "./key-services/entities/encrypted-key.entity";
import { SignatureType } from "./types/key-types.enum";
import { KeyType } from "./types/key-format.enum";

// Use a real (throwaway) PostgreSQL test database, same pattern as key.service.spec.ts.
jest.mock("fs");

async function createTestDatabase(): Promise<DataSource> {
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
  return dataSource;
}

describe("AppService.signRaw", () => {
  let service: AppService;
  let keyService: KeyService;
  let dataSource: DataSource;
  let module: TestingModule;

  const secrets = ["test-secret-123"];
  const ed25519Id = "did:web:example.com#ed25519";
  const es256Id = "did:web:example.com#es256";

  beforeAll(async () => {
    // The vault secret is normally read from a file; feed a fixed 32+ char value.
    jest
      .spyOn(fs, "readFileSync")
      .mockReturnValue("vault-secret-key-that-is-at-least-32-characters-long");

    dataSource = await createTestDatabase();

    module = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: "postgres",
          entities: [EncryptedKey],
          synchronize: false,
          logging: false,
        }),
        TypeOrmModule.forFeature([EncryptedKey]),
      ],
      providers: [
        AppService,
        JwtSigningService,
        DataIntegritySigningService,
        KeyService,
        KeyStorageService,
        SecretService,
        FailedAttemptsCacheService,
        PayloadEncryptionService,
        DocumentLoaderService,
      ],
    })
      .overrideProvider(DataSource)
      .useValue(dataSource)
      .compile();

    service = module.get<AppService>(AppService);
    keyService = module.get<KeyService>(KeyService);
  });

  afterAll(async () => {
    // module.close() already tears down the connection; guard the redundant destroy.
    try {
      await module?.close();
      if (dataSource?.isInitialized) {
        await dataSource.destroy();
      }
    } catch {
      // ignore cleanup errors
    }
    jest.restoreAllMocks();
  });

  beforeEach(async () => {
    await dataSource.getRepository(EncryptedKey).clear();
  });

  // Signs `input` with the key at `identifier` and asserts it round-trips against that key's verifier.
  async function expectSignRoundTrip(identifier: string, input: Buffer) {
    const { signature } = await service.signRaw({
      identifier,
      secrets,
      data: input.toString("base64"),
    });

    const signatureBytes = Buffer.from(signature, "base64");
    expect(signatureBytes.length).toBeGreaterThan(0);

    const keyPair = await keyService.getKeyPair(identifier, secrets);
    const verifier = await keyPair.verifier!();
    const valid = await verifier.verify({
      data: new Uint8Array(input),
      signature: new Uint8Array(signatureBytes),
    });
    expect(valid).toBe(true);
  }

  it("signs arbitrary-length bytes with an Ed25519 key and the signature verifies", async () => {
    await keyService.generateKeyPair(
      SignatureType.ED25519_2020,
      KeyType.MULTIKEY,
      ed25519Id,
      secrets,
    );

    await expectSignRoundTrip(ed25519Id, crypto.randomBytes(100));
    await expectSignRoundTrip(ed25519Id, crypto.randomBytes(64));
  });

  it("signs with an ES256 key and the signature verifies", async () => {
    await keyService.generateKeyPair(
      SignatureType.ES256,
      KeyType.MULTIKEY,
      es256Id,
      secrets,
    );

    await expectSignRoundTrip(es256Id, crypto.randomBytes(48));
  });

  it("rejects input that decodes to zero bytes", async () => {
    await keyService.generateKeyPair(
      SignatureType.ED25519_2020,
      KeyType.MULTIKEY,
      ed25519Id,
      secrets,
    );

    await expect(
      service.signRaw({
        identifier: ed25519Id,
        secrets,
        data: "=", // non-empty string, decodes to no bytes

      }),
    ).rejects.toThrow(BadRequestException);
  });

  it("fails when the secrets are wrong", async () => {
    await keyService.generateKeyPair(
      SignatureType.ED25519_2020,
      KeyType.MULTIKEY,
      ed25519Id,
      secrets,
    );

    await expect(
      service.signRaw({
        identifier: ed25519Id,
        secrets: ["wrong-secret"],
        data: crypto.randomBytes(64).toString("base64"),
      }),
    ).rejects.toThrow(/Failed to decrypt/);
  });
});
