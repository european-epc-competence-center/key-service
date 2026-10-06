import { Injectable } from "@nestjs/common";
import { SignatureType } from "../types/key-types.enum";
import {
  KeyPair,
  ECJsonWebKey,
  RSAJsonWebKey,
} from "../types/keypair.types";

// @ts-ignore
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
// @ts-ignore
import * as EcdsaMultikey from "@digitalbazaar/ecdsa-multikey";
// @ts-ignore
import * as RsaMultikey from "@eecc/rsa-multikey";
import { VerificationMethod } from "../types/verification-method.types";
import { KeyStorageService } from "./key-storage.service";
import { KeyExportService, KEY_EXPORT_VERSION } from "./key-export.service";
import { KeyType } from "../types";
import { UnsupportedException } from "../types/custom-exceptions";

@Injectable()
export class KeyService {
  constructor(
    private readonly keyStorageService: KeyStorageService,
    private readonly keyExportService: KeyExportService
  ) {}

  async generateKeyPair(
    keyType: SignatureType,
    keyFormat: KeyType,
    identifier: string,
    secrets: string[]
  ): Promise<VerificationMethod> {
    if (!secrets || secrets.length === 0) {
      throw new Error("At least one secret must be provided");
    }
    if (keyType === SignatureType.ED25519_2020) {
      return await this.generateEd25519Multikey(
        identifier,
        keyFormat,
        secrets
      );
    }
    if (keyType === SignatureType.ES256) {
      return await this.generateEcdsaMultikey(
        identifier,
        keyFormat,
        secrets
      );
    }
    if (keyType === SignatureType.PS256) {
      return await this.generateRsaMultikey(
        identifier,
        keyFormat,
        secrets
      );
    }
    throw new UnsupportedException(`Unsupported key type: ${keyType}`);
  }

  async getKeyPair(
    identifier: string,
    secrets: string[],
    publicIdentifier: string = identifier
  ): Promise<KeyPair> {
    if (!secrets || secrets.length === 0) {
      throw new Error("At least one secret must be provided");
    }
    const storedKey = await this.keyStorageService.retrieveKey(
      identifier,
      secrets,
      publicIdentifier
    );
    if (
      storedKey.signatureType === SignatureType.ED25519_2020
    ) {
      const ed25519Key = await Ed25519Multikey.from({
        type: 'Multikey',
        id: storedKey.id,
        controller: storedKey.controller,
        publicKeyMultibase: storedKey.publicKey,
        secretKeyMultibase: storedKey.privateKey,
      });

      return {...storedKey, signer: ed25519Key.signer, verifier: ed25519Key.verifier};
    }
    if (
      storedKey.signatureType === SignatureType.ES256
    ) {
      const ecdsaKey = await EcdsaMultikey.from({
        type: 'Multikey',
        id: storedKey.id,
        controller: storedKey.controller,
        publicKeyMultibase: storedKey.publicKey,
        secretKeyMultibase: storedKey.privateKey,
      });

      return {...storedKey, signer: ecdsaKey.signer, verifier: ecdsaKey.verifier};
    }
    if (
      storedKey.signatureType === SignatureType.PS256
    ) {
      const rsaKey = await RsaMultikey.from({
        type: 'Multikey',
        id: storedKey.id,
        controller: storedKey.controller,
        publicKeyMultibase: storedKey.publicKey,
        secretKeyMultibase: storedKey.privateKey,
      }) as any;

      return {...storedKey, signer: rsaKey.signer, verifier: rsaKey.verifier};
    }
    throw new UnsupportedException(
      `Unsupported signature type ${storedKey.signatureType} for key type ${storedKey.keyType}`
    );
  }

  async generateEd25519Multikey(
    identifier: string,
    keyFormat: KeyType,
    secrets: string[]
  ): Promise<VerificationMethod> {
    const keyPair = await Ed25519Multikey.generate({
      controller: identifier.split("#")[0],
      id: identifier,
    });
    if (!keyPair.id.split("#")[1]) {
      keyPair.id = `${identifier}#${keyPair.publicKeyMultibase}`;
    }
    await this.keyStorageService.storeKey(
      keyPair.id,
      SignatureType.ED25519_2020,
      keyFormat,
      keyPair.secretKeyMultibase,
      keyPair.publicKeyMultibase,
      secrets
    );
    return await this.toVerificationMethod(
      keyPair.id,
      SignatureType.ED25519_2020,
      keyFormat,
      keyPair.publicKeyMultibase,
      keyPair.secretKeyMultibase
    );
  }

  async generateEcdsaMultikey(
    identifier: string,
    keyFormat: KeyType,
    secrets: string[]
  ): Promise<VerificationMethod> {
    const keyPair = await EcdsaMultikey.generate({
      curve: 'P-256',
      controller: identifier.split("#")[0],
      id: identifier,
    });
    if (!keyPair.id.split("#")[1]) {
      keyPair.id = `${identifier}#${keyPair.publicKeyMultibase}`;
    }
    await this.keyStorageService.storeKey(
      keyPair.id,
      SignatureType.ES256,
      keyFormat,
      keyPair.secretKeyMultibase,
      keyPair.publicKeyMultibase,
      secrets
    );
    return await this.toVerificationMethod(
      keyPair.id,
      SignatureType.ES256,
      keyFormat,
      keyPair.publicKeyMultibase,
      keyPair.secretKeyMultibase
    );
  }

  async generateRsaMultikey(
    identifier: string,
    keyFormat: KeyType,
    secrets: string[]
  ): Promise<VerificationMethod> {
    const keyPair = await RsaMultikey.generate({
      controller: identifier.split("#")[0],
      id: identifier,
    }) as any;
    if (!keyPair.id.split("#")[1]) {
      keyPair.id = `${identifier}#${keyPair.publicKeyMultibase}`;
    }
    await this.keyStorageService.storeKey(
      keyPair.id,
      SignatureType.PS256,
      keyFormat,
      keyPair.secretKeyMultibase,
      keyPair.publicKeyMultibase,
      secrets
    );
    return await this.toVerificationMethod(
      keyPair.id,
      SignatureType.PS256,
      keyFormat,
      keyPair.publicKeyMultibase,
      keyPair.secretKeyMultibase
    );
  }

  /**
   * Delete a key pair from the key storage service when owernship can be proven
   * @param identifier 
   * @param secrets 
   * @returns 
   */
  async deleteKey(identifier: string, secrets: string[]): Promise<void> {
    return await this.keyStorageService.deleteKey(identifier, secrets);
  }

  /**
   * Decrypt a stored key with `secrets` and return it as a passphrase-encrypted
   * compact JWE. The original key stays in storage.
   */
  async exportKey(
    identifier: string,
    secrets: string[],
    passphrase: string
  ): Promise<string> {
    this.assertSecrets(secrets);
    const storedKey = await this.keyStorageService.retrieveKey(
      identifier,
      secrets
    );
    this.assertMultibaseKey(storedKey);
    return await this.keyExportService.encrypt(
      {
        version: KEY_EXPORT_VERSION,
        id: identifier,
        signatureType: storedKey.signatureType,
        keyType: storedKey.keyType,
        publicKey: storedKey.publicKey,
        privateKey: storedKey.privateKey,
      },
      passphrase
    );
  }

  /**
   * Decrypt a passphrase-encrypted export and store it under `secrets`.
   * `identifier` overrides the id carried inside the export.
   * The returned verification method is built from the stored row.
   */
  async importKey(
    exportedKey: string,
    passphrase: string,
    secrets: string[],
    identifier?: string
  ): Promise<VerificationMethod> {
    this.assertSecrets(secrets);
    const document = await this.keyExportService.decrypt(
      exportedKey,
      passphrase
    );
    const id = identifier ?? document.id;
    await this.keyStorageService.storeKey(
      id,
      document.signatureType,
      document.keyType,
      document.privateKey,
      document.publicKey,
      secrets
    );
    const storedKey = await this.keyStorageService.retrieveKey(id, secrets);
    this.assertMultibaseKey(storedKey);
    return await this.toVerificationMethod(
      storedKey.id,
      storedKey.signatureType,
      storedKey.keyType,
      storedKey.publicKey,
      storedKey.privateKey
    );
  }

  private assertSecrets(secrets: string[]): void {
    if (!secrets || secrets.length === 0) {
      throw new Error("At least one secret must be provided");
    }
  }

  private assertMultibaseKey<
    T extends { publicKey: unknown; privateKey: unknown; signatureType: SignatureType }
  >(
    storedKey: T
  ): asserts storedKey is T & { publicKey: string; privateKey: string } {
    if (
      typeof storedKey.publicKey !== "string" ||
      typeof storedKey.privateKey !== "string"
    ) {
      throw new UnsupportedException(
        `Unsupported key material for signature type ${storedKey.signatureType}`
      );
    }
  }

  /**
   * Public verification method for a stored multibase key.
   * Generate and import both return this shape. `JsonWebKey` is converted
   * from the multibase material; `Multikey` copies the public multibase.
   */
  private async toVerificationMethod(
    id: string,
    signatureType: SignatureType,
    keyFormat: KeyType,
    publicKeyMultibase: string,
    secretKeyMultibase: string
  ): Promise<VerificationMethod> {
    const controller = id.split("#")[0];
    if (keyFormat === KeyType.MULTIKEY) {
      return {
        id,
        type: keyFormat,
        controller,
        publicKeyMultibase,
      };
    }
    const multikey = {
      type: "Multikey",
      id,
      controller,
      publicKeyMultibase,
      secretKeyMultibase,
    };
    if (signatureType === SignatureType.ED25519_2020) {
      const keyPair = await Ed25519Multikey.from(multikey);
      return {
        id,
        type: keyFormat,
        controller,
        publicKeyJwk: (await Ed25519Multikey.toJwk({
          keyPair,
          secretKey: false,
        })) as ECJsonWebKey,
      };
    }
    if (signatureType === SignatureType.ES256) {
      const keyPair = await EcdsaMultikey.from(multikey);
      return {
        id,
        type: keyFormat,
        controller,
        publicKeyJwk: (await EcdsaMultikey.toJwk({
          keyPair,
          secretKey: false,
        })) as ECJsonWebKey,
      };
    }
    if (signatureType === SignatureType.PS256) {
      const keyPair = (await RsaMultikey.from(multikey)) as any;
      return {
        id,
        type: keyFormat,
        controller,
        publicKeyJwk: (await RsaMultikey.toJwk({
          keyPair,
          secretKey: false,
        })) as RSAJsonWebKey,
      };
    }
    throw new UnsupportedException(
      `Unsupported signature type ${signatureType}`
    );
  }
}
