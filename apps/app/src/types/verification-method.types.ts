/**
 * Verification Method types for DID Documents
 *
 * A verification method is a set of parameters that can be used together with
 * a process to independently verify a proof.
 */

import { JsonWebKey } from "./keypair.types";

/**
 * Verification Method within a DID Document
 *
 * A verification method is a set of parameters that can be used together with
 * a process to independently verify a proof.
 */
export interface VerificationMethod {
  /**
   * The verification method identifier
   * Required property
   */
  id: string;

  /**
   * The type of verification method
   * Required property
   */
  type: string;

  /**
   * The DID that controls this verification method
   * Required property
   */
  controller: string;

  /**
   * The public key in multibase format
   * Used for Ed25519VerificationKey2020, EcdsaSecp256k1VerificationKey2019, etc.
   */
  publicKeyMultibase?: string;

  /**
   * The public key in JWK format
   * Used for JsonWebKey2020
   */
  publicKeyJwk?: JsonWebKey;

  /**
   * The public key in PEM format
   * Used for some verification method types
   */
  publicKeyPem?: string;

  /**
   * The blockchain account address
   * Used for blockchain-based verification methods
   */
  blockchainAccountId?: string;

  /**
   * The ethereum address
   * Used for Ethereum-based verification methods
   */
  ethereumAddress?: string;
}
