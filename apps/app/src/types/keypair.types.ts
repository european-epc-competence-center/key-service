/**
 * KeyPair types for cryptographic key management
 */

import { KeyType } from "./key-format.enum";
import { SignatureType } from "./key-types.enum";

// JWK (JSON Web Key) types
export interface JsonWebKey {
  kty: string;
  kid?: string;
  [key: string]: any;
}

export interface ECJsonWebKey extends JsonWebKey {
  kty: "EC";
  crv: string;
  x: string;
  y: string;
}

export interface ECPrivateJsonWebKey extends ECJsonWebKey {
  d: string;
}

export interface RSAJsonWebKey extends JsonWebKey {
  kty: "RSA";
  n: string;
  e: string;
  x5c?: string[];
}

export interface RSAPrivateJsonWebKey extends RSAJsonWebKey {
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
}

// Ed25519 specific types
export interface Ed25519KeyPair {
  id: string;
  controller: string;
  publicKeyMultibase: string;
  privateKeyMultibase: string;
  signer(): Promise<{
    sign: (options: { data: string }) => Promise<Uint8Array>;
  }>;
}

// ES256 signature result
export interface ES256Signature {
  r: string;
  s: string;
}

// ES256 KeyPair interface - updated to match the consistent signer pattern
// All key pair types now use the same signer function signature:
// signer(): Promise<{ sign: (options: { data: string }) => Promise<Uint8Array> }>
export interface ES256KeyPair {
  privateKeyJwk: ECPrivateJsonWebKey;
  publicKeyJwk: ECJsonWebKey;
  signer(): Promise<{
    sign: (options: { data: string }) => Promise<Uint8Array>;
  }>;
}

// Raw KeyPair interface without signer - contains just the key data
export interface RawKeypair {
  /**
   * Public key in the appropriate format for the key type
   */
  publicKey: string | JsonWebKey;

  /**
   * Private key in the appropriate format for the key type
   */
  privateKey: string | JsonWebKey;

  /**
   * key identifier
   */
  id: string;

  /**
   * controller (DID)
   */
  controller?: string;

  /**
   * key type
   */
  keyType: KeyType;

  /**
   * Signature type
   */
  signatureType: SignatureType;
}

// Main KeyPair interface that extends RawKeypair and adds signer functionality
export interface KeyPair extends RawKeypair {
  /**
   * Function to sign data
   */
  signer(): Promise<{
    sign: (options: { data: string | Uint8Array }) => Promise<Uint8Array>;
  }>;
  
  /**
   * Optional function to verify signatures (for data integrity proofs)
   */
  verifier?(): Promise<{
    verify: (options: { data: Uint8Array; signature: Uint8Array }) => Promise<boolean>;
  }>;
}

// Type guards
export function isEd25519KeyPair(keyPair: any): keyPair is Ed25519KeyPair {
  return (
    keyPair &&
    typeof keyPair === "object" &&
    typeof keyPair.publicKeyMultibase === "string" &&
    typeof keyPair.privateKeyMultibase === "string" &&
    typeof keyPair.signer === "function"
  );
}

export function isES256KeyPair(keyPair: any): keyPair is ES256KeyPair {
  return (
    keyPair &&
    typeof keyPair === "object" &&
    keyPair.privateKeyJwk &&
    keyPair.publicKeyJwk &&
    typeof keyPair.signer === "function"
  );
}

export function isKeyPair(obj: any): obj is KeyPair {
  return (
    obj &&
    typeof obj === "object" &&
    typeof obj.signer === "function" &&
    obj.publicKey !== undefined &&
    obj.privateKey !== undefined
  );
}
