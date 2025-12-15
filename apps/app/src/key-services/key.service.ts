import { Injectable } from "@nestjs/common";
import { SignatureType } from "../types/key-types.enum";
import {
  KeyPair,
  RawKeypair,
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
import { KeyType } from "../types";
import { UnsupportedException } from "../types/custom-exceptions";

@Injectable()
export class KeyService {
  constructor(private readonly keyStorageService: KeyStorageService) {}

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

  async getKeyPair(identifier: string, secrets: string[]): Promise<KeyPair> {
    if (!secrets || secrets.length === 0) {
      throw new Error("At least one secret must be provided");
    }
    const storedKey = await this.keyStorageService.retrieveKey(
      identifier,
      secrets
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
    if (keyFormat === KeyType.MULTIKEY) {
      return {
        id: keyPair.id,
        type: keyFormat,
        controller: keyPair.controller,
        publicKeyMultibase: keyPair.publicKeyMultibase,
      };
    }
    return {
      id: keyPair.id,
      type: keyFormat,
      controller: keyPair.controller,
      publicKeyJwk: await Ed25519Multikey.toJwk({keyPair: keyPair, secretKey: false}) as ECJsonWebKey,
    };
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
    if (keyFormat === KeyType.MULTIKEY) {
      return {
        id: keyPair.id,
        type: keyFormat,
        controller: keyPair.controller,
        publicKeyMultibase: keyPair.publicKeyMultibase,
      };
    }
    return {
      id: keyPair.id,
      type: keyFormat.toString(),
      controller: keyPair.controller,
      publicKeyJwk: await EcdsaMultikey.toJwk({keyPair: keyPair, secretKey: false}) as ECJsonWebKey,
    };
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
    if (keyFormat === KeyType.MULTIKEY) {
      return {
        id: keyPair.id,
        type: keyFormat,
        controller: keyPair.controller,
        publicKeyMultibase: keyPair.publicKeyMultibase,
      };
    }
    return {
      id: keyPair.id,
      type: keyFormat,
      controller: keyPair.controller,
      publicKeyJwk: await RsaMultikey.toJwk({keyPair: keyPair, secretKey: false}) as RSAJsonWebKey,
    };
  }
}
