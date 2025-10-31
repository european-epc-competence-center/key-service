# Data Integrity Signatures

## Overview

The Key Service supports W3C Data Integrity proofs for Verifiable Credentials and Verifiable Presentations using multiple signature algorithms.

## Supported Signature Algorithms

### Ed25519Signature2020
- **Algorithm**: EdDSA with Ed25519 curve
- **Library**: `@digitalbazaar/ed25519-signature-2020`
- **Proof Type**: `Ed25519Signature2020`
- **Key Type**: `Ed25519VerificationKey2020`
- **Context**: `https://w3id.org/security/suites/ed25519-2020/v1`

### ES256Signature2020 (EcdsaSecp256r1Signature2019)
- **Algorithm**: ECDSA with P-256 curve (ES256)
- **Implementation**: Custom suite extending `LinkedDataSignature` from `jsonld-signatures`
- **Proof Type**: `EcdsaSecp256r1Signature2019`
- **Key Type**: `JsonWebKey2020` with EC P-256
- **Context**: `https://w3id.org/security/suites/jws-2020/v1`
- **Location**: `apps/app/src/signing-services/ES256Signature2020.ts`

## Implementation Details

### ES256Signature2020 Custom Suite

The ES256Signature2020 suite is a custom implementation following the Digital Bazaar signature suite pattern:

```typescript
export class ES256Signature2020 extends LinkedDataSignature {
  // Extends jsonld-signatures LinkedDataSignature base class
  // Implements sign() and verifySignature() methods
  // Uses base58btc multibase encoding for proof values
}
```

#### Key Features:
1. **Multibase Encoding**: Proof values use base58btc encoding with `z` prefix
2. **JOSE Integration**: Utilizes `jose` library for ES256 signing and verification
3. **Dual-mode Signing**: Supports both JWT (string) and Data Integrity (Uint8Array) data formats
4. **Verification Method**: Automatically handles key metadata and verification method resolution

### Service Integration

The `DataIntegritySigningService` handles both Ed25519 and ES256 signatures:

```typescript
// Signature type detection
if (keyPair.signatureType === SignatureType.ED25519_2020) {
  suite = new Ed25519Signature2020({ key: keyPair });
} else if (keyPair.signatureType === SignatureType.ES256) {
  // ES256 requires explicit signer/verifier initialization
  const signer = await keyPair.signer();
  const verifier = await keyPair.verifier();
  suite = new ES256Signature2020({ signer, verifier });
}
```

### Signer/Verifier Architecture

#### KeyService Integration
The `KeyService` provides signer and verifier functions for ES256 keys:

- **Signer**: Returns object with `sign()` method that accepts `Uint8Array` or `string`
- **Verifier**: Returns object with `verify()` method for signature validation
- **Dual Mode**: Handles both JWT signing (string input) and Data Integrity signing (Uint8Array input)

#### Key Format
ES256 keys use JWK format:
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "...",
  "y": "...",
  "d": "..." // private key only
}
```

## Usage

### Signing a Verifiable Credential

```typescript
const signedVC = await dataIntegritySigningService.signVC(
  credential,
  verificationMethod, // e.g., "did:web:example.com#key-1"
  secrets
);
```

The service automatically selects the appropriate signature suite based on the key type associated with the `verificationMethod`.

### Signing a Verifiable Presentation

```typescript
const signedVP = await dataIntegritySigningService.signVP(
  presentation,
  verificationMethod,
  secrets,
  challenge, // required for VPs
  domain     // optional
);
```

## Proof Structure

### ES256 Data Integrity Proof Example

```json
{
  "type": "EcdsaSecp256r1Signature2019",
  "created": "2024-01-01T00:00:00Z",
  "verificationMethod": "did:web:example.com#key-1",
  "proofPurpose": "assertionMethod",
  "proofValue": "z..." // base58btc encoded signature
}
```

## Testing

Tests are located in `data-integrity-signing.service.spec.ts`:
- ES256 VC V1 and V2 signing tests
- ES256 VP signing with challenge/domain
- Tests verify proof structure, signature format, and credential integrity

**Note**: ES256 tests pass in isolation but may have test ordering issues when run together. This is a test infrastructure issue, not an implementation problem.

## Security Considerations

1. **Private Key Protection**: Private keys never leave the key service, stored encrypted
2. **Signature Verification**: Verifiers can validate signatures using only public keys
3. **Proof Purpose**: Proofs include purpose (e.g., `assertionMethod`, `authentication`)
4. **Canonicalization**: Uses JSON-LD canonicalization (URDNA2015) before signing

## References

- [W3C Data Integrity Specification](https://w3c.github.io/vc-data-integrity/)
- [jsonld-signatures Library](https://github.com/digitalbazaar/jsonld-signatures)
- [ECDSA Secp256r1 Signature 2019](https://w3c-ccg.github.io/lds-ecdsa-secp256r1-2019/)
- [JSON Web Signature 2020](https://w3c-ccg.github.io/lds-jws2020/)

