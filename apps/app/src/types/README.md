# Verifiable Credential Types

This directory contains TypeScript type definitions for Verifiable Credentials following the [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) specification.

## Overview

The Verifiable Credential (VC) types provide comprehensive TypeScript interfaces for working with verifiable credentials and presentations. These types ensure type safety and compliance with the VC Data Model 2.0 specification.

## Files

- `verifiable-credential.types.ts` - Main type definitions
- `verifiable-credential.types.spec.ts` - Tests for the type definitions
- `../utils/vc-examples.ts` - Utility functions for creating and validating VCs

## Core Types

### VerifiableCredential

The main interface for verifiable credentials:

```typescript
interface VerifiableCredential {
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
  credentialSchema?: CredentialSchema | CredentialSchema[];
  evidence?: Evidence | Evidence[];
  termsOfUse?: TermsOfUse | TermsOfUse[];
  refreshService?: RefreshService | RefreshService[];

  // Proof properties (one must be present)
  proof?: Proof | Proof[];
  jwt?: string;
  sd_jwt?: string;
  disclosures?: string[];
}
```

### VerifiablePresentation

Interface for verifiable presentations:

```typescript
interface VerifiablePresentation {
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
```

## Utility Functions

### Creating VCs

```typescript
import {
  createBasicVC,
  createUniversityDegreeVC,
  createIssuer,
} from "../utils/vc-examples";

// Create a basic VC
const issuer = createIssuer("did:example:university", "Example University");
const subject = { id: "did:example:student", name: "John Doe" };
const vc = createBasicVC(issuer, subject);

// Create a university degree VC
const degreeVC = createUniversityDegreeVC(
  issuer,
  "student123",
  "Bachelor of Science in Computer Science",
  "Example University",
  "2023-05-15"
);
```

### Validating VCs

```typescript
import { validateVC, isVerifiableCredential } from "../utils/vc-examples";

// Validate a VC
const result = validateVC(vc);
if (result.isValid) {
  console.log("VC is valid");
} else {
  console.log("VC validation errors:", result.errors);
}

// Type guard
if (isVerifiableCredential(obj)) {
  // obj is now typed as VerifiableCredential
}
```

## Common Constants

### Credential Types

```typescript
import { COMMON_CREDENTIAL_TYPES } from "./verifiable-credential.types";

COMMON_CREDENTIAL_TYPES.VERIFIABLE_CREDENTIAL; // 'VerifiableCredential'
COMMON_CREDENTIAL_TYPES.UNIVERSITY_DEGREE; // 'UniversityDegreeCredential'
COMMON_CREDENTIAL_TYPES.DRIVERS_LICENSE; // 'DriversLicenseCredential'
COMMON_CREDENTIAL_TYPES.IDENTITY_CARD; // 'IdentityCardCredential'
COMMON_CREDENTIAL_TYPES.EMPLOYMENT_CREDENTIAL; // 'EmploymentCredential'
COMMON_CREDENTIAL_TYPES.MEMBERSHIP_CREDENTIAL; // 'MembershipCredential'
COMMON_CREDENTIAL_TYPES.ACHIEVEMENT_CREDENTIAL; // 'AchievementCredential'
COMMON_CREDENTIAL_TYPES.CERTIFICATE; // 'CertificateCredential'
```

### Proof Types

```typescript
import { COMMON_PROOF_TYPES } from "./verifiable-credential.types";

COMMON_PROOF_TYPES.DATA_INTEGRITY; // 'DataIntegrityProof'
COMMON_PROOF_TYPES.JWT; // 'JwtProof2020'
COMMON_PROOF_TYPES.SD_JWT; // 'SdJwtProof'
COMMON_PROOF_TYPES.ED25519_SIGNATURE_2020; // 'Ed25519Signature2020'
COMMON_PROOF_TYPES.ECDSA_SECP256K1_SIGNATURE_2019; // 'EcdsaSecp256k1Signature2019'
COMMON_PROOF_TYPES.RSA_SIGNATURE_2018; // 'RsaSignature2018'
```

## Example Usage

### Complete VC Creation Example

```typescript
import {
  VerifiableCredential,
  COMMON_CREDENTIAL_TYPES,
  COMMON_PROOF_TYPES,
} from "./verifiable-credential.types";
import { createIssuer } from "../utils/vc-examples";

// Create a complete VC
const vc: VerifiableCredential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  type: [
    COMMON_CREDENTIAL_TYPES.VERIFIABLE_CREDENTIAL,
    "UniversityDegreeCredential",
  ],
  issuer: createIssuer("did:example:university", "Example University"),
  credentialSubject: {
    id: "did:example:student123",
    name: "Alice Johnson",
    degree: {
      type: "BachelorDegree",
      name: "Bachelor of Science in Computer Science",
      university: "Example University",
    },
    graduationDate: "2023-05-15",
  },
  issuanceDate: "2023-05-15T10:00:00Z",
  proof: {
    type: COMMON_PROOF_TYPES.DATA_INTEGRITY,
    cryptosuite: "ed25519-2022",
    created: "2023-05-15T10:00:00Z",
    verificationMethod: "did:example:university#key-1",
    proofPurpose: "assertionMethod",
    proofValue: "zQ3shar2yKJh6mHdKVcg95a6bJDFKPs8VjrhPuKV6o4BkqR1",
  },
};
```

### JWT VC Example

```typescript
const jwtVC: VerifiableCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  type: [COMMON_CREDENTIAL_TYPES.VERIFIABLE_CREDENTIAL],
  issuer: "did:example:issuer",
  credentialSubject: {
    id: "did:example:subject",
    name: "John Doe",
  },
  issuanceDate: "2023-01-01T00:00:00Z",
  jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
};
```

## Integration with Signing Services

The types are integrated with the signing services in the application:

```typescript
import { DataIntegritySigningService } from "../signing-services/data-integrity-signing.service";
import { VerifiableCredential } from "./verifiable-credential.types";

// The signing service now uses proper types
const signedVC = await dataIntegritySigningService.sign(
  vc, // VerifiableCredential
  "did:example:issuer#key-1",
  "secret"
);
```

## Testing

Run the tests to verify the types work correctly:

```bash
npm run test:unit
```

The tests cover:

- Type guards for validation
- VC creation utilities
- Validation functions
- Example usage patterns

## Compliance

These types are designed to be fully compliant with:

- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Verifiable Credentials Data Model 1.1](https://www.w3.org/TR/vc-data-model/) (backward compatibility)
- Common VC implementations and libraries

## Contributing

When adding new credential types or proof types:

1. Add them to the appropriate constants in `verifiable-credential.types.ts`
2. Create utility functions in `vc-examples.ts` if needed
3. Add tests in `verifiable-credential.types.spec.ts`
4. Update this README with examples
