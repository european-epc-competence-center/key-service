import { Injectable } from "@nestjs/common";
import * as jose from "jose";
import { SignatureType } from "../types/key-types.enum";
import { KeyType } from "../types/key-format.enum";
import { KeyException } from "../types/custom-exceptions";
import {
  IDENTIFIER_PATTERN,
  VALIDATION_CONSTANTS,
} from "../types/request.dto";

/**
 * Passphrase-encrypted key export (RFC 7516 compact JWE).
 *
 * The stored key is already decrypted with the caller's secrets before this
 * runs. The JWE is encrypted with the passphrase alone, so another deployment
 * can import it without this service's vault secret.
 *
 * Protected header:
 * - alg: PBES2-HS512+A256KW (RFC 7518). jose only runs PBES2 when the caller
 *   allows that alg, and its default iteration count is 2048. The count is
 *   set here to the OWASP 2023 PBKDF2-HMAC-SHA512 figure and is also the
 *   decrypt ceiling, so a crafted header cannot force more work.
 * - enc: A256GCM
 * - cty: application/eecc-key-export+json
 *
 * Plaintext is a versioned JSON document with the multibase key material.
 */
export const KEY_EXPORT_VERSION = 1;
export const KEY_EXPORT_ALG = "PBES2-HS512+A256KW";
export const KEY_EXPORT_ENC = "A256GCM";
export const KEY_EXPORT_CONTENT_TYPE = "application/eecc-key-export+json";
export const KEY_EXPORT_P2C = 210_000;
const MAX_EXPORT_PLAINTEXT_BYTES = 65_536;

export interface KeyExportDocument {
  version: typeof KEY_EXPORT_VERSION;
  id: string;
  signatureType: SignatureType;
  keyType: KeyType;
  publicKey: string;
  privateKey: string;
}

@Injectable()
export class KeyExportService {
  async encrypt(document: KeyExportDocument, passphrase: string): Promise<string> {
    this.assertPassphrase(passphrase);
    const plaintext = new TextEncoder().encode(JSON.stringify(document));
    return await new jose.CompactEncrypt(plaintext)
      .setProtectedHeader({
        alg: KEY_EXPORT_ALG,
        enc: KEY_EXPORT_ENC,
        cty: KEY_EXPORT_CONTENT_TYPE,
      })
      .setKeyManagementParameters({ p2c: KEY_EXPORT_P2C })
      .encrypt(new TextEncoder().encode(passphrase));
  }

  async decrypt(exportedKey: string, passphrase: string): Promise<KeyExportDocument> {
    this.assertPassphrase(passphrase);
    let plaintext: Uint8Array;
    try {
      const header = jose.decodeProtectedHeader(exportedKey);
      if (!this.isSupportedHeader(header)) {
        throw new KeyException("Unsupported exported key format");
      }
      const decrypted = await jose.compactDecrypt(
        exportedKey,
        new TextEncoder().encode(passphrase),
        {
          keyManagementAlgorithms: [KEY_EXPORT_ALG],
          contentEncryptionAlgorithms: [KEY_EXPORT_ENC],
          maxPBES2Count: KEY_EXPORT_P2C,
        }
      );
      plaintext = decrypted.plaintext;
    } catch (error) {
      if (error instanceof KeyException) {
        throw error;
      }
      throw new KeyException("Failed to decrypt exported key");
    }
    return this.parseDocument(plaintext);
  }

  private assertPassphrase(passphrase: string): void {
    if (
      typeof passphrase !== "string" ||
      passphrase.length < VALIDATION_CONSTANTS.MIN_PASSPHRASE_LENGTH ||
      passphrase.length > VALIDATION_CONSTANTS.MAX_PASSPHRASE_LENGTH
    ) {
      throw new KeyException(
        `Passphrase must be between ${VALIDATION_CONSTANTS.MIN_PASSPHRASE_LENGTH} and ${VALIDATION_CONSTANTS.MAX_PASSPHRASE_LENGTH} characters`
      );
    }
  }

  private isSupportedHeader(header: jose.ProtectedHeaderParameters): boolean {
    return (
      header.alg === KEY_EXPORT_ALG &&
      header.enc === KEY_EXPORT_ENC &&
      header.cty === KEY_EXPORT_CONTENT_TYPE &&
      header.p2c === KEY_EXPORT_P2C &&
      header.zip === undefined &&
      header.crit === undefined
    );
  }

  private parseDocument(plaintext: Uint8Array): KeyExportDocument {
    if (plaintext.byteLength > MAX_EXPORT_PLAINTEXT_BYTES) {
      throw new KeyException("Invalid exported key");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(plaintext));
    } catch {
      throw new KeyException("Invalid exported key");
    }
    if (!parsed || typeof parsed !== "object") {
      throw new KeyException("Invalid exported key");
    }
    const document = parsed as Record<string, unknown>;
    if (
      document.version !== KEY_EXPORT_VERSION ||
      !this.isIdentifier(document.id) ||
      !this.isSignatureType(document.signatureType) ||
      !this.isKeyType(document.keyType) ||
      !this.isKeyMaterial(document.publicKey) ||
      !this.isKeyMaterial(document.privateKey)
    ) {
      throw new KeyException("Invalid exported key");
    }
    return {
      version: KEY_EXPORT_VERSION,
      id: document.id,
      signatureType: document.signatureType,
      keyType: document.keyType,
      publicKey: document.publicKey,
      privateKey: document.privateKey,
    };
  }

  private isIdentifier(value: unknown): value is string {
    return (
      typeof value === "string" &&
      value.length > 0 &&
      value.length <= VALIDATION_CONSTANTS.MAX_IDENTIFIER_LENGTH &&
      IDENTIFIER_PATTERN.test(value)
    );
  }

  private isKeyMaterial(value: unknown): value is string {
    return typeof value === "string" && value.length > 0;
  }

  private isSignatureType(value: unknown): value is SignatureType {
    return Object.values(SignatureType).includes(value as SignatureType);
  }

  private isKeyType(value: unknown): value is KeyType {
    return Object.values(KeyType).includes(value as KeyType);
  }
}
