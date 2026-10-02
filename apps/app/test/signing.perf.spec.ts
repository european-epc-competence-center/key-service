import { Test, TestingModule } from "@nestjs/testing";
import { TypeOrmModule } from "@nestjs/typeorm";
import { DataSource, Repository } from "typeorm";
import { JwtSigningService } from "../src/signing-services/jwt-signing.service";
import { DataIntegritySigningService } from "../src/signing-services/data-integrity-signing.service";
import { KeyService } from "../src/key-services/key.service";
import { KeyStorageService } from "../src/key-services/key-storage.service";
import { SecretService } from "../src/key-services/secret.service";
import { FailedAttemptsCacheService } from "../src/key-services/failed-attempts-cache.service";
import { EncryptedKey } from "../src/key-services/entities/encrypted-key.entity";
import { SignatureType } from "../src/types/key-types.enum";
import { KeyType } from "../src/types/key-format.enum";
import { KeyPair } from "../src/types/keypair.types";
import { VerifiableCredential } from "../src/types/verifiable-credential.types";
import { JsonLdContextCache } from "../src/utils/jsonld-context-cache";

/**
 * Measures JWT and Data Integrity credential signing.
 *
 * SecretService caches each PBKDF2 output on the service instance. A hit
 * resets a 10 second TTL, so an idle derivation is dropped and one that is
 * still used stays cached. Cold samples below call clearDerivationCache()
 * before each measurement. "PBKDF2 cache warm" is a repeated sign within
 * that TTL. "Key cached" additionally skips getKeyPair, which the service
 * does not do. Data Integrity also compares a cold JSON-LD context cache
 * with the warm in-process cache.
 *
 * Run with `npm run test:perf` (not part of `npm test`).
 */

const SAMPLES = 5;
const SECRETS = ["perf-test-secret"];
const ITERATIONS = parseInt(process.env.PBKDF2_ITERATIONS || "100000", 10);

interface Stats {
  min: number;
  median: number;
  max: number;
}

interface Phase {
  algorithm: string;
  phase: string;
  stats: Stats;
}

function statsOf(samples: number[]): Stats {
  const sorted = [...samples].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median =
    sorted.length % 2 === 0
      ? (sorted[mid - 1] + sorted[mid]) / 2
      : sorted[mid];
  return { min: sorted[0], median, max: sorted[sorted.length - 1] };
}

async function once(fn: () => unknown): Promise<number> {
  const start = performance.now();
  await fn();
  return performance.now() - start;
}

function ms(value: number): string {
  return value.toFixed(1).padStart(8);
}

function credential(): VerifiableCredential {
  return {
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
}

function named(
  phases: Phase[],
  algorithm: string,
  name: string
): Stats {
  const found = phases.find(
    (entry) => entry.algorithm === algorithm && entry.phase === name
  );
  if (!found) {
    throw new Error(`missing phase ${algorithm} / ${name}`);
  }
  return found.stats;
}

describe("signing performance", () => {
  let moduleRef: TestingModule;
  let dataSource: DataSource;
  let jwtSigningService: JwtSigningService;
  let dataIntegritySigningService: DataIntegritySigningService;
  let keyService: KeyService;
  let secretService: SecretService;
  let repository: Repository<EncryptedKey>;
  const phases: Phase[] = [];

  beforeAll(async () => {
    dataSource = new DataSource({
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

    moduleRef = await Test.createTestingModule({
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
        JwtSigningService,
        DataIntegritySigningService,
        KeyService,
        KeyStorageService,
        SecretService,
        FailedAttemptsCacheService,
      ],
    })
      .overrideProvider(DataSource)
      .useValue(dataSource)
      .compile();

    jwtSigningService = moduleRef.get(JwtSigningService);
    dataIntegritySigningService = moduleRef.get(DataIntegritySigningService);
    keyService = moduleRef.get(KeyService);
    secretService = moduleRef.get(SecretService);
    repository = dataSource.getRepository(EncryptedKey);
    await repository.clear();
  });

  afterAll(async () => {
    printReport(phases);
    await moduleRef?.close();
    if (dataSource?.isInitialized) {
      await dataSource.destroy();
    }
  });

  it.each([SignatureType.ED25519_2020, SignatureType.ES256])(
    "measures %s signing with and without a cached key",
    async (algorithm) => {
      const identifier = `did:example:perf#${algorithm}`;
      await keyService.generateKeyPair(
        algorithm,
        KeyType.MULTIKEY,
        identifier,
        SECRETS
      );

      const hashedIdentifier = secretService.hash(identifier);
      const stored = await repository.findOne({
        where: { identifier: hashedIdentifier },
      });
      if (!stored) {
        throw new Error(`stored key missing for ${algorithm}`);
      }

      const held = await keyService.getKeyPair(identifier, SECRETS);
      const record = async (phase: string, stats: Stats | Promise<Stats>) => {
        phases.push({ algorithm, phase, stats: await stats });
      };
      const uncached = (fn: () => unknown) => () => {
        secretService.clearDerivationCache();
        return fn();
      };

      await record(
        "identifier hash (PBKDF2)",
        sample(SAMPLES, uncached(() => secretService.hash(identifier)))
      );
      await record(
        "identifier hash (PBKDF2 cache warm)",
        sample(SAMPLES, () => secretService.hash(identifier))
      );
      await record(
        "db findOne",
        sample(SAMPLES, () =>
          repository.findOne({ where: { identifier: hashedIdentifier } })
        )
      );
      await record(
        "decrypt private key (PBKDF2)",
        sample(SAMPLES, uncached(() =>
          secretService.decrypt(stored.encryptedPrivateKey, SECRETS)
        ))
      );
      await record(
        "decrypt private key (PBKDF2 cache warm)",
        sample(SAMPLES, () =>
          secretService.decrypt(stored.encryptedPrivateKey, SECRETS)
        )
      );
      await record(
        "decrypt public key (PBKDF2)",
        sample(SAMPLES, uncached(() =>
          secretService.decrypt(stored.encryptedPublicKey, SECRETS)
        ))
      );
      await record(
        "getKeyPair (hash + db + both decrypts + multikey)",
        sample(SAMPLES, uncached(() => keyService.getKeyPair(identifier, SECRETS)))
      );
      await record(
        "signer() on a held key",
        sample(SAMPLES, () => held.signer())
      );
      await record(
        "jwt sign, key not cached",
        sample(SAMPLES, uncached(() =>
          jwtSigningService.signCredential(credential(), identifier, SECRETS)
        ))
      );
      await record(
        "jwt sign, PBKDF2 cache warm",
        sample(SAMPLES, () =>
          jwtSigningService.signCredential(credential(), identifier, SECRETS)
        )
      );

      const cachedKey = jest
        .spyOn(keyService, "getKeyPair")
        .mockResolvedValue(held);
      try {
        await record(
          "jwt sign, key cached",
          sample(SAMPLES, () =>
            jwtSigningService.signCredential(credential(), identifier, SECRETS)
          )
        );

        JsonLdContextCache.reset();
        const coldMs = await once(() =>
          dataIntegritySigningService.signCredential(
            credential(),
            identifier,
            SECRETS
          )
        );
        await record("di sign, key cached, context cache cold", {
          min: coldMs,
          median: coldMs,
          max: coldMs,
        });
        await record(
          "di sign, key cached, context cache warm",
          sample(
            SAMPLES,
            () =>
              dataIntegritySigningService.signCredential(
                credential(),
                identifier,
                SECRETS
              ),
            false
          )
        );
      } finally {
        cachedKey.mockRestore();
      }

      await record(
        "di sign, key not cached, context cache warm",
        sample(SAMPLES, uncached(() =>
          dataIntegritySigningService.signCredential(
            credential(),
            identifier,
            SECRETS
          )
        ))
      );
      await record(
        "di sign, PBKDF2 cache warm, context cache warm",
        sample(SAMPLES, () =>
          dataIntegritySigningService.signCredential(
            credential(),
            identifier,
            SECRETS
          )
        )
      );

      await expectRetrievalCounts(
        identifier,
        held,
        secretService,
        keyService,
        jwtSigningService,
        dataIntegritySigningService
      );
      assertTimingPitfalls(phases, algorithm);
    }
  );
});

/**
 * Warm-cache samples must not include another cold compile, so the first
 * measured call is the sample itself.
 */
async function sample(
  count: number,
  fn: () => unknown,
  warmup = true
): Promise<Stats> {
  if (warmup) {
    await fn();
  }
  const samples: number[] = [];
  for (let i = 0; i < count; i++) {
    const start = performance.now();
    await fn();
    samples.push(performance.now() - start);
  }
  return statsOf(samples);
}

async function expectRetrievalCounts(
  identifier: string,
  held: KeyPair,
  secretService: SecretService,
  keyService: KeyService,
  jwtSigningService: JwtSigningService,
  dataIntegritySigningService: DataIntegritySigningService
): Promise<void> {
  const hashSpy = jest.spyOn(secretService, "hash");
  const decryptSpy = jest.spyOn(secretService, "decrypt");
  const findSpy = jest.spyOn(Repository.prototype, "findOne");
  const fetchSpy = jest.spyOn(globalThis, "fetch");

  const reset = () => {
    hashSpy.mockClear();
    decryptSpy.mockClear();
    findSpy.mockClear();
    fetchSpy.mockClear();
  };

  try {
    reset();
    const jwt = await jwtSigningService.signCredential(
      credential(),
      identifier,
      SECRETS
    );
    expect(jwt.split(".")).toHaveLength(3);
    expect(hashSpy).toHaveBeenCalledTimes(1);
    expect(decryptSpy).toHaveBeenCalledTimes(2);
    expect(findSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).not.toHaveBeenCalled();

    reset();
    const cachedKey = jest
      .spyOn(keyService, "getKeyPair")
      .mockResolvedValue(held);
    try {
      await jwtSigningService.signCredential(credential(), identifier, SECRETS);
      expect(hashSpy).not.toHaveBeenCalled();
      expect(decryptSpy).not.toHaveBeenCalled();
      expect(findSpy).not.toHaveBeenCalled();
    } finally {
      cachedKey.mockRestore();
    }

    reset();
    const signed = await dataIntegritySigningService.signCredential(
      credential(),
      identifier,
      SECRETS
    );
    expect(signed.proof).toBeDefined();
    expect(hashSpy).toHaveBeenCalledTimes(1);
    expect(decryptSpy).toHaveBeenCalledTimes(2);
    expect(findSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).not.toHaveBeenCalled();
  } finally {
    hashSpy.mockRestore();
    decryptSpy.mockRestore();
    findSpy.mockRestore();
    fetchSpy.mockRestore();
  }
}

function assertTimingPitfalls(phases: Phase[], algorithm: string): void {
  const hash = named(phases, algorithm, "identifier hash (PBKDF2)");
  const hashWarm = named(
    phases,
    algorithm,
    "identifier hash (PBKDF2 cache warm)"
  );
  const db = named(phases, algorithm, "db findOne");
  const privateDecrypt = named(
    phases,
    algorithm,
    "decrypt private key (PBKDF2)"
  );
  const privateDecryptWarm = named(
    phases,
    algorithm,
    "decrypt private key (PBKDF2 cache warm)"
  );
  const publicDecrypt = named(phases, algorithm, "decrypt public key (PBKDF2)");
  const jwtUncached = named(phases, algorithm, "jwt sign, key not cached");
  const jwtWarm = named(phases, algorithm, "jwt sign, PBKDF2 cache warm");
  const jwtCached = named(phases, algorithm, "jwt sign, key cached");
  const diUncached = named(
    phases,
    algorithm,
    "di sign, key not cached, context cache warm"
  );
  const diCached = named(
    phases,
    algorithm,
    "di sign, key cached, context cache warm"
  );
  const diWarm = named(
    phases,
    algorithm,
    "di sign, PBKDF2 cache warm, context cache warm"
  );

  const derivation =
    hash.median + privateDecrypt.median + publicDecrypt.median;

  expect(derivation).toBeGreaterThan(db.median * 5);
  expect(hash.median).toBeGreaterThan(hashWarm.median * 5);
  expect(privateDecrypt.median).toBeGreaterThan(privateDecryptWarm.median * 5);
  expect(jwtUncached.median).toBeGreaterThan(jwtWarm.median * 2);
  expect(jwtUncached.median).toBeGreaterThan(jwtCached.median * 2);
  expect(derivation).toBeGreaterThan(jwtCached.median);
  expect(publicDecrypt.median).toBeGreaterThan(db.median * 3);
  expect(diUncached.median).toBeGreaterThan(diCached.median);
  expect(diUncached.median).toBeGreaterThan(diWarm.median);
}

function printReport(phases: Phase[]): void {
  if (phases.length === 0) {
    return;
  }
  const header = `${"algorithm".padEnd(10)} ${"phase".padEnd(56)} ${"min".padStart(8)} ${"median".padStart(8)} ${"max".padStart(8)}`;
  const lines = [
    "",
    `Signing performance (PBKDF2 iterations=${ITERATIONS}, samples=${SAMPLES}, times in ms)`,
    header,
    "-".repeat(header.length),
  ];
  for (const entry of phases) {
    lines.push(
      `${entry.algorithm.padEnd(10)} ${entry.phase.padEnd(56)} ${ms(entry.stats.min)} ${ms(entry.stats.median)} ${ms(entry.stats.max)}`
    );
  }

  lines.push("");
  for (const algorithm of [SignatureType.ED25519_2020, SignatureType.ES256]) {
    if (!phases.some((entry) => entry.algorithm === algorithm)) {
      continue;
    }
    const hash = named(phases, algorithm, "identifier hash (PBKDF2)");
    const db = named(phases, algorithm, "db findOne");
    const privateDecrypt = named(
      phases,
      algorithm,
      "decrypt private key (PBKDF2)"
    );
    const publicDecrypt = named(
      phases,
      algorithm,
      "decrypt public key (PBKDF2)"
    );
    const hashWarm = named(
      phases,
      algorithm,
      "identifier hash (PBKDF2 cache warm)"
    );
    const jwtUncached = named(phases, algorithm, "jwt sign, key not cached");
    const jwtWarm = named(phases, algorithm, "jwt sign, PBKDF2 cache warm");
    const jwtCached = named(phases, algorithm, "jwt sign, key cached");
    const diUncached = named(
      phases,
      algorithm,
      "di sign, key not cached, context cache warm"
    );
    const diCached = named(
      phases,
      algorithm,
      "di sign, key cached, context cache warm"
    );
    const diCold = named(
      phases,
      algorithm,
      "di sign, key cached, context cache cold"
    );
    const diWarm = named(
      phases,
      algorithm,
      "di sign, PBKDF2 cache warm, context cache warm"
    );
    const derivation =
      hash.median + privateDecrypt.median + publicDecrypt.median;
    lines.push(
      `${algorithm}: key derivation cold ${derivation.toFixed(0)} ms (hash ${hash.median.toFixed(1)} / warm ${hashWarm.median.toFixed(1)} + private ${privateDecrypt.median.toFixed(1)} + public ${publicDecrypt.median.toFixed(1)}), db ${db.median.toFixed(1)} ms`
    );
    lines.push(
      `${algorithm}: jwt cold ${jwtUncached.median.toFixed(1)} ms, PBKDF2 cache warm ${jwtWarm.median.toFixed(1)} ms, key cached ${jwtCached.median.toFixed(1)} ms`
    );
    lines.push(
      `${algorithm}: data integrity cold ${diUncached.median.toFixed(1)} ms, PBKDF2 cache warm ${diWarm.median.toFixed(1)} ms, key cached ${diCached.median.toFixed(1)} ms; context cold ${diCold.median.toFixed(1)} ms`
    );
  }
  lines.push("");
  console.log(lines.join("\n"));
}
