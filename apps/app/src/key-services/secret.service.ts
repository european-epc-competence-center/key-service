import { Injectable } from "@nestjs/common";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { logError, logWarn } from "../utils/log/logger";
import { ConfigurationException } from "../types/custom-exceptions";

@Injectable()
export class SecretService {
  private readonly secret: string;
  private readonly iterations: number; // PBKDF2 iterations (OWASP recommended minimum)

  constructor() {
    // Configure iterations from environment variable with default of 100000
    this.iterations = parseInt(process.env.PBKDF2_ITERATIONS || '100000', 10);

    if (this.iterations < 100000) {
      logWarn("PBKDF2_ITERATIONS is less than 100000, which is not recommended");
    }
    
    const keyPath = process.env.SIGNING_KEY_PATH || "/run/secrets/signing-key";
    try {
      this.secret = fs.readFileSync(path.resolve(keyPath), "utf8").trim();
      if (!this.secret || this.secret.length < 32) {
        throw new ConfigurationException(
          "Signing key must be at least 32 characters long"
        );
      }
    } catch (err) {
      logError(`Failed to read signing key from ${keyPath}: ${err}`);
      if (process.env.NODE_ENV === "production") {
        throw new ConfigurationException(
          "Cannot start service without proper signing key in production"
        );
      }
      // Only allow fallback in development
      this.secret =
        "development-only-dummy-secret-not-for-production-use-minimum-length";
    }
  }

  private deriveKey(
    password: string,
    salt: Buffer,
    length: number = 32
  ): Buffer {
    // Use PBKDF2 with SHA-256, which is FIPS compliant and widely supported
    return crypto.pbkdf2Sync(password, salt, this.iterations, length, "sha256");
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
