/**
 * Verifiable Credential types following VC Data Model 2.0 specification
 * https://www.w3.org/TR/vc-data-model-2.0/
 */

// Base types for common properties
export type URI = string;
export type DateTime = string; // ISO 8601 format
export type LanguageTag = string; // RFC 5646 format

// Context types
export type Context = URI | ContextObject | (URI | ContextObject)[];
export interface ContextObject {
  [key: string]: any;
}

// Credential Subject types
export interface CredentialSubject {
  id?: URI;
  [key: string]: any;
}

// Issuer types
export type Issuer = URI | IssuerObject;
export interface IssuerObject {
  id: URI;
  name?: string;
  image?: URI;
  url?: URI;
  [key: string]: any;
}

// Proof types
export interface Proof {
  type: string;
  created?: DateTime;
  verificationMethod?: URI;
  proofPurpose?: string;
  proofValue?: string;
  jws?: string;
  [key: string]: any;
}

// Evidence types
export interface Evidence {
  id?: URI;
  type: string | string[];
  verifier?: URI;
  evidenceDocument?: URI;
  subjectPresence?: "Physical" | "Digital";
  documentPresence?: "Physical" | "Digital";
  [key: string]: any;
}

// RefreshService types
export interface RefreshService {
  id: URI;
  type: string;
  [key: string]: any;
}

// TermsOfUse types
export interface TermsOfUse {
  type: string;
  id?: URI;
  profile?: URI;
  prohibition?: any[];
  permission?: any[];
  obligation?: any[];
  [key: string]: any;
}

// CredentialStatus types
export interface CredentialStatus {
  id: URI;
  type: string;
  [key: string]: any;
}

// DataIntegrityProof types
export interface DataIntegrityProof extends Proof {
  type: "DataIntegrityProof";
  cryptosuite: string;
  created: DateTime;
  verificationMethod: URI;
  proofPurpose: string;
  proofValue: string;
}

// JWT Proof types
export interface JwtProof extends Proof {
  type: "JwtProof2020";
  jwt: string;
}

// SD-JWT Proof types
export interface SdJwtProof extends Proof {
  type: "SdJwtProof";
  sd_jwt: string;
  disclosures?: string[];
}

// Main Verifiable Credential interface
export interface VerifiableCredential {
  // Required properties
  "@context": Context;
  type: string | string[];
  issuer: Issuer;
  credentialSubject: CredentialSubject | CredentialSubject[];

  // Optional properties
  id?: URI;
  issuanceDate?: DateTime;
  expirationDate?: DateTime;
  validFrom?: DateTime;
  validUntil?: DateTime;
  credentialStatus?: CredentialStatus;
  credentialSchema?:
    | {
        id: URI;
        type: string;
      }
    | {
        id: URI;
        type: string;
      }[];
  evidence?: Evidence | Evidence[];
  termsOfUse?: TermsOfUse | TermsOfUse[];
  refreshService?: RefreshService | RefreshService[];

  // Proof properties (one of these must be present)
  proof?: Proof | Proof[];
  jwt?: string;
  sd_jwt?: string;
  disclosures?: string[];
}

// Verifiable Presentation types
export interface VerifiablePresentation {
  "@context": Context;
  type: string | string[];
  verifiableCredential: VerifiableCredential | VerifiableCredential[];

  id?: URI;
  holder?: URI;
  verifier?: URI | URI[];
  issuanceDate?: DateTime;
  expirationDate?: DateTime;
  validFrom?: DateTime;
  validUntil?: DateTime;

  proof?: Proof | Proof[];
  jwt?: string;
  sd_jwt?: string;
  disclosures?: string[];
}

// Utility types for working with VCs
export type CredentialType = "VerifiableCredential" | string;
export type PresentationType = "VerifiablePresentation" | string;

// Type guards
export function isVerifiableCredential(obj: any): obj is VerifiableCredential {
  return (
    obj &&
    typeof obj === "object" &&
    obj["@context"] &&
    obj.type &&
    obj.issuer &&
    obj.credentialSubject &&
    (obj.proof || obj.jwt || obj.sd_jwt)
  );
}

export function isVerifiablePresentation(
  obj: any
): obj is VerifiablePresentation {
  return (
    obj &&
    typeof obj === "object" &&
    obj["@context"] &&
    obj.type &&
    obj.verifiableCredential
  );
}

// Common credential types
export const COMMON_CREDENTIAL_TYPES = {
  VERIFIABLE_CREDENTIAL: "VerifiableCredential",
} as const;

// Common proof types
export const COMMON_PROOF_TYPES = {
  DATA_INTEGRITY: "DataIntegrityProof",
  JWT: "JwtProof2020",
  SD_JWT: "SdJwtProof",
  ED25519_SIGNATURE_2020: "Ed25519Signature2020",
  ECDSA_SECP256K1_SIGNATURE_2019: "EcdsaSecp256k1Signature2019",
  RSA_SIGNATURE_2018: "RsaSignature2018",
} as const;
