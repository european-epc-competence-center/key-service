import { Injectable } from "@nestjs/common";
import * as crypto from "crypto";
import { payloadEncryptionConfig } from "../config/payload-encryption.config";
import { logInfo } from "../utils/log/logger";

/**
 * PayloadEncryptionService
 * 
 * Simple AES-256-GCM encryption for request and response payloads.
 * Uses a shared secret (256-bit key) for symmetric encryption.
 * 
 * Algorithm: AES-256-GCM (Galois/Counter Mode)
 * - Provides confidentiality and authenticity
 * - Simple to implement across all platforms
 * - No key derivation - direct use of 256-bit secret
 * - Fast and secure
 * 
 * Encrypted format: base64(iv:authTag:ciphertext)
 * - iv: 12 bytes (96 bits) initialization vector
 * - authTag: 16 bytes (128 bits) authentication tag
 * - ciphertext: encrypted data
 * 
 * Compatible with standard AES-GCM in:
 * - Java (javax.crypto.Cipher with "AES/GCM/NoPadding")
 * - Spring Boot (spring-security-crypto)
 * - Python (cryptography library)
 * - Go (crypto/cipher)
 * - .NET (System.Security.Cryptography.AesGcm)
 */
@Injectable()
export class PayloadEncryptionService {
  private readonly secret: Buffer | undefined;
  private readonly enabled: boolean;

  constructor() {
    this.enabled = payloadEncryptionConfig.enabled;
    this.secret = payloadEncryptionConfig.secret;

    if (this.enabled && !this.secret) {
      throw new Error(
        "PayloadEncryptionService enabled but no inter-service shared secret configured"
      );
    }

    if (this.enabled) {
      logInfo("Inter-service request decryption (AES-256-GCM) is enabled");
    }
  }

  /**
   * Check if payload encryption is enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Encrypt data using AES-256-GCM
   * Used internally for testing and by clients for encrypting requests
   * 
   * @param data - String data to encrypt (typically JSON.stringify(payload))
   * @returns Base64-encoded encrypted data: base64(iv:authTag:ciphertext)
   * 
   * @example
   * ```typescript
   * const encrypted = service.encrypt(JSON.stringify({ foo: 'bar' }));
   * ```
   */
  encrypt(data: string): string {
    if (!this.enabled || !this.secret) {
      throw new Error("Inter-service encryption is not enabled or configured");
    }

    // Generate random IV (12 bytes is optimal for GCM)
    const iv = crypto.randomBytes(12);

    // Create cipher with the 256-bit key
    const cipher = crypto.createCipheriv("aes-256-gcm", this.secret, iv);

    // Encrypt data
    let ciphertext = cipher.update(data, "utf8", "hex");
    ciphertext += cipher.final("hex");

    // Get authentication tag
    const authTag = cipher.getAuthTag();

    // Combine: iv:authTag:ciphertext
    const combined = [
      iv.toString("hex"),
      authTag.toString("hex"),
      ciphertext,
    ].join(":");

    // Return as base64
    return Buffer.from(combined, "utf8").toString("base64");
  }

  /**
   * Decrypt encrypted data
   * Used by the interceptor to decrypt incoming requests
   * 
   * @param encryptedData - Base64-encoded encrypted data from encrypt()
   * @returns Decrypted string
   * 
   * @throws Error if data format is invalid or authentication fails
   * 
   * @example
   * ```typescript
   * const decrypted = service.decrypt(encryptedData);
   * const payload = JSON.parse(decrypted);
   * ```
   */
  decrypt(encryptedData: string): string {
    if (!this.enabled || !this.secret) {
      throw new Error("Inter-service encryption is not enabled or configured");
    }

    // Decode base64
    const combined = Buffer.from(encryptedData, "base64").toString("utf8");

    // Split into parts
    const parts = combined.split(":");
    if (parts.length !== 3) {
      throw new Error(
        "Invalid encrypted data format. Expected 3 parts (iv:authTag:ciphertext)"
      );
    }

    const iv = Buffer.from(parts[0], "hex");
    const authTag = Buffer.from(parts[1], "hex");
    const ciphertext = parts[2];

    // Validate sizes
    if (iv.length !== 12) {
      throw new Error(`Invalid IV size: expected 12 bytes, got ${iv.length}`);
    }
    if (authTag.length !== 16) {
      throw new Error(`Invalid auth tag size: expected 16 bytes, got ${authTag.length}`);
    }

    // Create decipher
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.secret, iv);
    decipher.setAuthTag(authTag);

    // Decrypt data
    let decrypted = decipher.update(ciphertext, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }

  /**
   * Encrypt a JSON object
   * Convenience method that handles JSON.stringify internally
   * 
   * @param payload - Any JSON-serializable object
   * @returns Base64-encoded encrypted data
   */
  encryptJson(payload: any): string {
    return this.encrypt(JSON.stringify(payload));
  }

  /**
   * Decrypt to a JSON object
   * Convenience method that handles JSON.parse internally
   * 
   * @param encryptedData - Base64-encoded encrypted data
   * @returns Parsed JSON object
   */
  decryptJson<T = any>(encryptedData: string): T {
    const decrypted = this.decrypt(encryptedData);
    return JSON.parse(decrypted) as T;
  }
}

