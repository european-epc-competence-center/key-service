import { Injectable, OnModuleDestroy } from "@nestjs/common";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import NodeCache from "node-cache";
import { logError, logWarn } from "../utils/log/logger";
import { ConfigurationException } from "../types/custom-exceptions";

/** Idle time after which an unused PBKDF2 output is dropped. A hit resets this. */
const DERIVATION_CACHE_TTL_SECONDS = 10;
const DERIVATION_CACHE_MAX_KEYS = 1000;

function positiveInt(value: string | undefined, fallback: number): number {
  const parsed = parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

@Injectable()
export class SecretService implements OnModuleDestroy {
  private readonly secret: string;
  private readonly iterations: number; // PBKDF2 iterations (OWASP recommended minimum)
  private readonly derivationCacheMaxKeys: number;
  private readonly derivationCache: NodeCache;

  constructor() {
    this.derivationCacheMaxKeys = positiveInt(
      process.env.PBKDF2_CACHE_MAX_KEYS,
      DERIVATION_CACHE_MAX_KEYS
    );
    this.derivationCache = new NodeCache({
      stdTTL: DERIVATION_CACHE_TTL_SECONDS,
      checkperiod: DERIVATION_CACHE_TTL_SECONDS,
      useClones: false,
    });

    // Configure iterations from environment variable with default of 100000
    this.iterations = parseInt(process.env.PBKDF2_ITERATIONS || '100000', 10);

    if (this.iterations < 100000) {
      logWarn("PBKDF2_ITERATIONS is less than 100000, which is not recommended");
    }

    const keyPath = process.env.SIGNING_KEY_PATH || "/run/secrets/signing-key";
    let secretContent: string;
    try {
      secretContent = fs.readFileSync(path.resolve(keyPath), "utf8").trim();
    } catch (err) {
      logError(`Failed to read signing key from ${keyPath}: ${err}`);
      throw new ConfigurationException(
        "Cannot start service without a valid signing key"
      );
    }

    if (!secretContent || secretContent.length < 32) {
      throw new ConfigurationException(
        "Signing key must be at least 32 characters long"
      );
    }

    this.secret = secretContent;
  }

  onModuleDestroy(): void {
    this.derivationCache.close();
  }

  /** Drops cached PBKDF2 outputs. Tests use this to measure a cold derivation. */
  clearDerivationCache(): void {
    this.derivationCache.flushAll();
  }

  private deriveKey(
    password: string,
    salt: Buffer,
    length: number = 32
  ): Buffer {
    const cacheKey = this.derivationCacheKey(password, salt, length);
    const cached = this.derivationCache.get<Buffer>(cacheKey);
    if (cached) {
      // Sliding TTL: keep the result while callers still use it.
      this.derivationCache.ttl(cacheKey, DERIVATION_CACHE_TTL_SECONDS);
      return Buffer.from(cached);
    }

    const derived = crypto.pbkdf2Sync(
      password,
      salt,
      this.iterations,
      length,
      "sha256"
    );
    this.storeDerivedKey(cacheKey, derived);
    return Buffer.from(derived);
  }

  /** Evicts the oldest entry when full. A later miss calculates that entry again. */
  private storeDerivedKey(cacheKey: string, derived: Buffer): void {
    const keys = this.derivationCache.keys();
    if (
      keys.length >= this.derivationCacheMaxKeys &&
      keys[0] !== undefined
    ) {
      this.derivationCache.del(keys[0]);
    }
    this.derivationCache.set(cacheKey, derived);
  }

  private derivationCacheKey(
    password: string,
    salt: Buffer,
    length: number
  ): string {
    const header = Buffer.alloc(12);
    header.writeUInt32BE(this.iterations, 0);
    header.writeUInt32BE(length, 4);
    header.writeUInt32BE(salt.length, 8);
    return crypto
      .createHash("sha256")
      .update(header)
      .update(salt)
      .update(password, "utf8")
      .digest("hex");
  }

  private getEncryptionKey(
    externalSecrets: string[],
    salt: Buffer,
    length: number = 32
  ): Buffer {
    // Combine secrets in a consistent, deterministic way
    const joinedSecrets = externalSecrets
      ? externalSecrets.sort().join("")
      : "";
    const combinedSecret = joinedSecrets + this.secret;

    return this.deriveKey(combinedSecret, salt, length);
  }

  public encrypt(data: string, secrets: string[]): string {
    const salt = crypto.randomBytes(32); // Increased salt size to 256 bits
    const iv = crypto.randomBytes(16); // AES block size

    const cipher = crypto.createCipheriv(
      "aes-256-gcm", // Use GCM for authenticated encryption
      this.getEncryptionKey(secrets, salt),
      iv
    );

    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");

    // Get authentication tag for GCM
    const authTag = cipher.getAuthTag();

    // Format: salt:iv:authTag:encryptedData
    return [
      salt.toString("hex"),
      iv.toString("hex"),
      authTag.toString("hex"),
      encrypted,
    ].join(":");
  }

  public decrypt(encryptedData: string, secrets: string[]): string {
    const parts = encryptedData.split(":");

    if (parts.length !== 4) {
      throw new Error("Invalid encrypted data format");
    }

    const salt = Buffer.from(parts[0], "hex");
    const iv = Buffer.from(parts[1], "hex");
    const authTag = Buffer.from(parts[2], "hex");
    const encrypted = parts[3];

    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      this.getEncryptionKey(secrets, salt),
      iv
    );

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }

  public hash(data: string): string {
    // Use the secret as salt and PBKDF2 for rainbow table resistance
    const salt = Buffer.from(this.secret, "utf8");
    const derivedKey = this.deriveKey(data, salt, 32);
    return derivedKey.toString("hex");
  }
}
