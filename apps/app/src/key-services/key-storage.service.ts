import { Injectable, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { EncryptedKey } from "./entities/encrypted-key.entity";
import { SignatureType } from "../types/key-types.enum";
import { SecretService } from "./secret.service";
import { FailedAttemptsCacheService } from "./failed-attempts-cache.service";
import { KeyType, KeyPair, RawKeypair } from "../types";
import { logError } from "../utils/log/logger";
import {
  KeyException,
  TooManyFailedAttemptsException,
} from "../types/custom-exceptions";
import { failedAttemptsCacheConfig } from "../config/failed-attempts.config";
import { PayloadEncryptionService } from "./payload-encryption.service";

@Injectable()
export class KeyStorageService {
  constructor(
    @InjectRepository(EncryptedKey)
    private readonly encryptedKeyRepository: Repository<EncryptedKey>,
    private readonly secretService: SecretService,
    private readonly failedAttemptsCache: FailedAttemptsCacheService,
    private readonly payloadEncryptionService: PayloadEncryptionService
  ) {}

  async storeKey(
    identifier: string,
    signatureType: SignatureType,
    keyType: KeyType,
    privateKey: any,
    publicKey: any,
    secrets: string[]
  ): Promise<EncryptedKey> {
    // Encrypt the keys using the secret service
    const encryptedPrivateKey = this.secretService.encrypt(
      JSON.stringify(privateKey),
      secrets
    );

    const encryptedPublicKey = this.secretService.encrypt(
      JSON.stringify(publicKey),
      secrets
    );

    const hashedIdentifier = this.secretService.hash(identifier);

    // Check if key already exists
    const existingKey = await this.encryptedKeyRepository.findOne({
      where: { identifier: hashedIdentifier, keyType },
    });

    if (existingKey) {
      throw new Error(`Key with identifier ${identifier} already exists`);
    } else {
      // Create new key
      const encryptedKey = this.encryptedKeyRepository.create({
        identifier: hashedIdentifier,
        signatureType,
        keyType,
        encryptedPrivateKey,
        encryptedPublicKey,
      });
      return await this.encryptedKeyRepository.save(encryptedKey);
    }
  }

  async retrieveKey(
    identifier: string,
    secrets: string[]
  ): Promise<RawKeypair> {
    const hashedIdentifier = this.secretService.hash(identifier);

    // Check if this identifier is currently blocked due to too many failed attempts
    if (this.failedAttemptsCache.isBlocked(hashedIdentifier)) {
      throw new TooManyFailedAttemptsException(
        `Too many failed decryption attempts for identifier: ${identifier}`,
        failedAttemptsCacheConfig.cooldownPeriodSeconds
      );
    }

    const encryptedKey = await this.encryptedKeyRepository.findOne({
      where: { identifier: hashedIdentifier },
    });

    if (!encryptedKey) {
      throw new NotFoundException(
        `Key with identifier ${identifier} not found`
      );
    }

    try {
      // Decrypt the keys using the secret service
      const decryptedPrivateKey = this.secretService.decrypt(
        encryptedKey.encryptedPrivateKey,
        secrets
      );

      const decryptedPublicKey = this.secretService.decrypt(
        encryptedKey.encryptedPublicKey,
        secrets
      );

      return {
        id: identifier,
        keyType: encryptedKey.keyType as KeyType,
        signatureType: encryptedKey.signatureType as SignatureType,
        controller: identifier.split("#")[0],
        privateKey: JSON.parse(decryptedPrivateKey),
        publicKey: JSON.parse(decryptedPublicKey),
      };
    } catch (error) {
      // Record this failed decryption attempt
      this.failedAttemptsCache.recordFailedAttempt(hashedIdentifier);

      // Check if this was the attempt that triggered the block
      if (this.failedAttemptsCache.isBlocked(hashedIdentifier)) {
        throw new TooManyFailedAttemptsException(
          `Too many failed decryption attempts for identifier: ${identifier}`,
          failedAttemptsCacheConfig.cooldownPeriodSeconds
        );
      }

      throw new KeyException(
        `Failed to decrypt key for identifier: ${identifier}`
      );
    }
  }

  async deleteKey(identifier: string, secrets: string[]): Promise<void> {
    const keyPair = await this.retrieveKey(identifier, secrets);
    if (keyPair.id !== identifier) {
      throw new Error("Key identifier does not match the stored identifier");
    }
    const hashedIdentifier = this.secretService.hash(identifier);
    await this.encryptedKeyRepository.delete({ identifier: hashedIdentifier });
  }

  async exportKey(identifier: string, secrets: string[], password: string): Promise<string> {
    const keyPair = await this.retrieveKey(identifier, secrets);
    return await this.payloadEncryptionService.encrypt(JSON.stringify(keyPair), password);
  }
}
