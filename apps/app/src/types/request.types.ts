import {
  VerifiableCredential,
  VerifiablePresentation,
} from "./verifiable-credential.types";
import { VerificationMethod } from "./verification-method.types";
import { SignatureType } from "./key-types.enum";
import { KeyType } from "./key-format.enum";

/**
 * Request body type for signing operations
 */
export interface ServiceRequestBody {
  /**
   * The verifiable credential to be signed
   */
  verifiable: VerifiableCredential | VerifiablePresentation;

  /**
   * Secrets of the users for the key pair generation
   */
  secrets: string[];

  /**
   * Identifier for the signing key
   */
  identifier: string;

  /**
   * Type of signing key to use
   */
  signatureType: SignatureType;

  /**
   * Format of the key to use
   */
  keyType: KeyType;
}

/**
 * Request body type for key generation operations
 * Inherits from ServiceRequestBody but excludes the credential field
 */
export interface GenerateRequestBody
  extends Omit<ServiceRequestBody, "verifiable"> {}

/**
 * Request body type for signing operations with existing keys
 * Inherits from ServiceRequestBody but excludes signatureType and keyType fields
 */
export interface SignRequestBody
  extends Omit<ServiceRequestBody, "signatureType" | "keyType"> {}

/**
 * `POST /generate` and `POST /import` response. `signatureType` and `keyType`
 * are the values stored with the key, beside the public verification method.
 */
export interface KeyResponse {
  verificationMethod: VerificationMethod;
  signatureType: SignatureType;
  keyType: KeyType;
}
