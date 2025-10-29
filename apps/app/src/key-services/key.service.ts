import { Injectable } from "@nestjs/common";
import { SignatureType } from "../types/key-types.enum";
import {
  KeyPair,
  RawKeypair,
  JsonWebKey,
  RSAJsonWebKey,
  RSAPrivateJsonWebKey,
} from "../types/keypair.types";

// @ts-ignore
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { VerificationMethod } from "../types/verification-method.types";
import { KeyStorageService } from "./key-storage.service";
import { KeyType } from "../types";
import * as crypto from "crypto";
import { UnsupportedException } from "../types/custom-exceptions";
import * as jose from "jose";

@Injectable()
export class KeyService {
  constructor(private readonly keyStorageService: KeyStorageService) {}

  async getPublicKey(identifier: string, secrets: string[]): Promise<any> {
    return (await this.getKeyPair(identifier, secrets)).publicKey;
  }

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
      const ed25519KeyPair = await this.generateEd25519VerificationKey2020(
        identifier,
        keyFormat,
        secrets
      );
      return {
        id: ed25519KeyPair.id,
        type: ed25519KeyPair.type,
        controller: ed25519KeyPair.controller,
        publicKeyMultibase: ed25519KeyPair.publicKeyMultibase,
      };
    }
    if (keyType === SignatureType.ES256) {
      const es256KeyPair = await this.generateES256JsonWebKey(
        identifier,
        secrets
      );
      return {
        id: es256KeyPair.id,
        type: KeyType.JWK,
        controller: identifier.split("#")[0],
        publicKeyJwk: es256KeyPair.publicKeyJwk,
      };
    }
    if (keyType === SignatureType.PS256) {
      const ps256KeyPair = await this.generatePS256JsonWebKey(
        identifier,
        secrets
      );
      return ps256KeyPair;
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
      storedKey.signatureType === SignatureType.ED25519_2020 &&
      storedKey.keyType === KeyType.VERIFICATION_KEY_2020
    ) {
      const ed25519Key = new Ed25519VerificationKey2020({
        id: storedKey.id,
        controller: storedKey.controller,
        publicKeyMultibase: storedKey.publicKey,
        privateKeyMultibase: storedKey.privateKey,
      });

      return {
        privateKey: storedKey.privateKey,
        publicKey: storedKey.publicKey,
        keyType: storedKey.keyType,
        signatureType: storedKey.signatureType,
        id: storedKey.id,
        signer: () => ed25519Key.signer(),
      };
    }
    if (
      storedKey.signatureType === SignatureType.ES256 &&
      storedKey.keyType === KeyType.JWK
    ) {
      return await this.getES256JsonWebKey(storedKey);
    }
    if (
      storedKey.signatureType === SignatureType.PS256 &&
      (storedKey.keyType === KeyType.JWK ||
        storedKey.keyType === KeyType.JWK_2020)
    ) {
      return await this.getPS256JsonWebKey(storedKey);
    }
    throw new UnsupportedException(
      `Unsupported signature type ${storedKey.signatureType} for key type ${storedKey.keyType}`
    );
  }

  async generateEd25519VerificationKey2020(
    identifier: string,
    keyFormat: KeyType,
    secrets: string[]
  ): Promise<VerificationMethod> {
    const keyPair = await Ed25519VerificationKey2020.generate({
      controller: identifier.split("#")[0],
      id: identifier,
    });
    if (!keyPair.id.split("#")[1]) {
      keyPair.id = `${identifier}#${keyPair.fingerprint()}`;
    }
    await this.keyStorageService.storeKey(
      keyPair.id,
      SignatureType.ED25519_2020,
      keyFormat,
      keyPair.privateKeyMultibase,
      keyPair.publicKeyMultibase,
      secrets
    );
    return {
      id: keyPair.id,
      type: keyPair.type,
      controller: keyPair.controller,
      publicKeyMultibase: keyPair.publicKeyMultibase,
    };
  }

  async generateES256JsonWebKey(
    identifier: string,
    secrets: string[]
  ): Promise<VerificationMethod> {
    // Use JOSE library for FIPS 186-4 compliant ES256 key generation
    // This ensures proper curve validation and key generation within valid range
    const keyPair = await jose.generateKeyPair("ES256", { extractable: true });

    // Export keys to JWK format
    const privateKeyJwkRaw = await jose.exportJWK(keyPair.privateKey);
    const publicKeyJwkRaw = await jose.exportJWK(keyPair.publicKey);

    // Generate kid from identifier or use a hash of the public key
    const kid =
      identifier.split("#")[1] ||
      crypto.randomBytes(16).toString("base64url");

    // Construct properly typed JWKs with required fields
    const publicKeyJwk: JsonWebKey = {
      kty: publicKeyJwkRaw.kty!,
      crv: publicKeyJwkRaw.crv!,
      x: publicKeyJwkRaw.x!,
      y: publicKeyJwkRaw.y!,
      kid,
    };

    const privateKeyJwk: JsonWebKey = {
      ...publicKeyJwk,
      d: privateKeyJwkRaw.d!,
    };

    const keyId =
      identifier.split("#").length > 1 ? identifier : `${identifier}#${kid}`;

    await this.keyStorageService.storeKey(
      keyId,
      SignatureType.ES256,
      KeyType.JWK,
      privateKeyJwk,
      publicKeyJwk,
      secrets
    );

    return {
      id: keyId,
      type: KeyType.JWK,
      controller: identifier.split("#")[0],
      publicKeyJwk,
    };
  }

  async generatePS256JsonWebKey(
    identifier: string,
    secrets: string[]
  ): Promise<VerificationMethod> {
    // Generate RSA key pair using Node.js crypto - generate as key objects directly
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 4096,
    });

    // Export public key to get modulus and exponent
    const publicKeyJwk = publicKey.export({
      format: "jwk",
    }) as RSAJsonWebKey;

    // Export private key to get all RSA parameters
    const privateKeyJwk = privateKey.export({
      format: "jwk",
    }) as RSAPrivateJsonWebKey;

    const kid =
      identifier.split("#")[1] || crypto.randomBytes(16).toString("base64url");

    // Add required JWK parameters
    publicKeyJwk.kid = kid;
    publicKeyJwk.kty = "RSA";
    privateKeyJwk.kid = kid;
    privateKeyJwk.kty = "RSA";

    const keyId =
      identifier.split("#").length > 1 ? identifier : `${identifier}#${kid}`;

    await this.keyStorageService.storeKey(
      keyId,
      SignatureType.PS256,
      KeyType.JWK_2020,
      privateKeyJwk,
      publicKeyJwk,
      secrets
    );

    return {
      id: keyId,
      type: KeyType.JWK_2020,
      controller: identifier.split("#")[0],
      publicKeyJwk,
    };
  }

  async getES256JsonWebKey(storedKey: RawKeypair): Promise<KeyPair> {
    return {
      privateKey: storedKey.privateKey,
      publicKey: storedKey.publicKey,
      keyType: storedKey.keyType,
      signatureType: storedKey.signatureType,
      id: storedKey.id,
      signer: () =>
        Promise.resolve({
          sign: async (options: { data: string }): Promise<Uint8Array> => {
            // Use jose library for ES256 signing to get raw signature bytes
            const privateKeyJwk = storedKey.privateKey as JsonWebKey;

            // Import the private key using jose
            const privateKey = await jose.importJWK({
              ...privateKeyJwk,
              alg: "ES256",
            } as jose.JWK);

            // The data is already the JWT signing input (header.payload)
            // For proper JWT signing, we need to split and use the payload only
            const [headerPart, payloadPart] = options.data.split(".");

            // Decode the header to get the algorithm and other claims
            const headerBytes = jose.base64url.decode(headerPart);
            const headerObj = JSON.parse(new TextDecoder().decode(headerBytes));

            // Decode the payload
            const payloadBytes = jose.base64url.decode(payloadPart);

            // Create a JWS with the decoded payload and header
            const jws = await new jose.FlattenedSign(payloadBytes)
              .setProtectedHeader(headerObj)
              .sign(privateKey);

            // Return the raw signature bytes
            return jose.base64url.decode(jws.signature);
          },
        }),
    };
  }

  async getPS256JsonWebKey(storedKey: RawKeypair): Promise<KeyPair> {
    return {
      privateKey: storedKey.privateKey,
      publicKey: storedKey.publicKey,
      keyType: storedKey.keyType,
      signatureType: storedKey.signatureType,
      id: storedKey.id,
      signer: () =>
        Promise.resolve({
          sign: async (options: { data: string }): Promise<Uint8Array> => {
            // Use jose library for PS256 signing to get raw signature bytes
            const privateKeyJwk = storedKey.privateKey as RSAPrivateJsonWebKey;

            // Import the private key using jose
            const privateKey = await jose.importJWK({
              ...privateKeyJwk,
              alg: "PS256",
            } as jose.JWK);

            // The data is already the JWT signing input (header.payload)
            // For proper JWT signing, we need to split and use the payload only
            const [headerPart, payloadPart] = options.data.split(".");

            // Decode the header to get the algorithm and other claims
            const headerBytes = jose.base64url.decode(headerPart);
            const headerObj = JSON.parse(new TextDecoder().decode(headerBytes));

            // Decode the payload
            const payloadBytes = jose.base64url.decode(payloadPart);

            // Create a JWS with the decoded payload and header
            const jws = await new jose.FlattenedSign(payloadBytes)
              .setProtectedHeader(headerObj)
              .sign(privateKey);

            // Return the raw signature bytes
            return jose.base64url.decode(jws.signature);
          },
        }),
    };
  }
}
