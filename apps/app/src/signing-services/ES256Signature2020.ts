/*!
 * Copyright (c) 2024 Christian Fries. All rights reserved.
 * Based on Ed25519Signature2020 implementation pattern from Digital Bazaar
 */
// @ts-ignore
import * as base58btc from 'base58-universal';
// @ts-ignore
import jsigs from 'jsonld-signatures';
const { suites: { LinkedDataSignature } } = jsigs;

// Use the security context v2 which supports JsonWebKey2020
const SUITE_CONTEXT_URL = 'https://w3id.org/security/suites/jws-2020/v1';

// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER = 'z';

/**
 * ES256Signature2020 suite for creating and verifying Data Integrity Proofs
 * using ECDSA with P-256 curve (ES256 algorithm)
 */
export class ES256Signature2020 extends LinkedDataSignature {
  public signer: any;
  public verifier: any;
  public key: any;
  public requiredKeyType: string;

  /**
   * @param {object} options - Options hashmap.
   *
   * Either a `key` OR at least one of `signer`/`verifier` is required:
   *
   * @param {object} [options.key] - An optional key object (containing an
   *   `id` property, and either `signer` or `verifier`, depending on the
   *   intended operation. Useful for when the application is managing keys
   *   itself (when using a KMS, you never have access to the private key,
   *   and so should use the `signer` param instead).
   * @param {Function} [options.signer] - Signer function that returns an
   *   object with an async sign() method. This is useful when interfacing
   *   with a KMS (since you don't get access to the private key and its
   *   `signer()`, the KMS client gives you only the signer function to use).
   * @param {Function} [options.verifier] - Verifier function that returns
   *   an object with an async `verify()` method. Useful when working with a
   *   KMS-provided verifier function.
   *
   * Advanced optional parameters and overrides:
   *
   * @param {object} [options.proof] - A JSON-LD document with options to use
   *   for the `proof` node (e.g. any other custom fields can be provided here
   *   using a context different from security-v2).
   * @param {string|Date} [options.date] - Signing date to use if not passed.
   * @param {boolean} [options.useNativeCanonize] - Whether to use a native
   *   canonize algorithm.
   * @param {object} [options.canonizeOptions] - Options to pass to
   *   canonize algorithm.
   */
  constructor({
    key, signer, verifier, proof, date, useNativeCanonize, canonizeOptions
  }: any = {}) {
    // If key is provided but doesn't have signer/verifier methods,
    // extract them before calling super
    if (key && typeof key.signer === 'function' && !signer) {
      // Key has signer/verifier methods - they will be called by super
    }
    
    super({
      type: 'EcdsaSecp256r1Signature2019',
      contextUrl: SUITE_CONTEXT_URL,
      key, signer, verifier, proof, date, useNativeCanonize,
      canonizeOptions
    });
    
    // Initialize properties from super's processing
    this.key = key;
    // signer and verifier are set by super's _processSignatureParams
    
    // ES256 uses JsonWebKey2020 key type
    this.requiredKeyType = 'JsonWebKey2020';
  }

  /**
   * Adds a signature (proofValue) field to the proof object. Called by
   * LinkedDataSignature.createProof().
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.verifyData - Data to be signed (extracted
   *   from document, according to the suite's spec).
   * @param {object} options.proof - Proof object (containing the proofPurpose,
   *   verificationMethod, etc).
   *
   * @returns {Promise<object>} Resolves with the proof containing the signature
   *   value.
   */
  async sign({ verifyData, proof }: any): Promise<any> {
    if (!(this.signer && typeof this.signer.sign === 'function')) {
      throw new Error('A signer API has not been specified.');
    }

    const signatureBytes = await this.signer.sign({ data: verifyData });
    proof.proofValue =
      MULTIBASE_BASE58BTC_HEADER + base58btc.encode(signatureBytes);

    return proof;
  }

  /**
   * Verifies the proof signature against the given data.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.verifyData - Canonicalized hashed data.
   * @param {object} options.verificationMethod - Key object.
   * @param {object} options.proof - The proof to be verified.
   *
   * @returns {Promise<boolean>} Resolves with the verification result.
   */
  async verifySignature({ verifyData, verificationMethod, proof }: any): Promise<boolean> {
    const { proofValue } = proof;
    if (!(proofValue && typeof proofValue === 'string')) {
      throw new TypeError(
        'The proof does not include a valid "proofValue" property.');
    }
    if (proofValue[0] !== MULTIBASE_BASE58BTC_HEADER) {
      throw new Error('Only base58btc multibase encoding is supported.');
    }
    const signatureBytes = base58btc.decode(proofValue.substr(1));

    let { verifier } = this;
    if (!verifier) {
      // For ES256, we need to create a verifier from the verification method
      // This will be handled by the key infrastructure
      throw new Error('Verifier must be provided for ES256 verification.');
    }
    return verifier.verify({ data: verifyData, signature: signatureBytes });
  }

  async assertVerificationMethod({ verificationMethod }: any): Promise<void> {
    // ES256 uses JsonWebKey2020 key type
    if (verificationMethod.type !== 'JsonWebKey2020' && 
        verificationMethod.type !== 'JsonWebKey') {
      throw new Error(`Unsupported key type "${verificationMethod.type}".`);
    }

    // Ensure the key has a publicKeyJwk
    if (!verificationMethod.publicKeyJwk) {
      throw new TypeError(
        'The verification method must contain a "publicKeyJwk" property.');
    }

    // Verify it's an EC key with P-256 curve
    const jwk = verificationMethod.publicKeyJwk;
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
      throw new Error('The key must be an EC key with P-256 curve for ES256.');
    }

    if (!_includesContext({ document: verificationMethod, contextUrl: SUITE_CONTEXT_URL })) {
      // For DID Documents, since keys do not have their own contexts,
      // the suite context is usually provided by the documentLoader logic
      // We can be lenient here as long as the key type is correct
    }

    // ensure verification method has not been revoked
    if (verificationMethod.revoked !== undefined) {
      throw new Error('The verification method has been revoked.');
    }
  }

  async getVerificationMethod({ proof, documentLoader }: any): Promise<any> {
    // Check if we have key ID stored (from DataIntegritySigningService)
    const keyId = (this as any).keyId;
    const keyController = (this as any).keyController;
    const keyPublicKey = (this as any).keyPublicKey;
    
    if (keyId && keyController && keyPublicKey) {
      // This happens during sign() operations when we stored the key metadata
      return {
        id: keyId,
        type: 'JsonWebKey2020',
        controller: keyController,
        publicKeyJwk: keyPublicKey
      };
    }
    
    if (this.key) {
      // This happens most often during sign() operations. For verify(),
      // the expectation is that the verification method will be fetched
      // by the documentLoader (below), not provided as a `key` parameter.
      return {
        id: this.key.id,
        type: 'JsonWebKey2020',
        controller: this.key.controller,
        publicKeyJwk: this.key.publicKey
      };
    }

    let { verificationMethod } = proof;

    if (typeof verificationMethod === 'object') {
      verificationMethod = verificationMethod.id;
    }

    if (!verificationMethod) {
      throw new Error('No "verificationMethod" found in proof.');
    }

    const { document } = await documentLoader(verificationMethod);

    const vmDoc = typeof document === 'string' ?
      JSON.parse(document) : document;

    await this.assertVerificationMethod({ verificationMethod: vmDoc });

    return vmDoc;
  }

  async matchProof({ proof, document, purpose, documentLoader }: any): Promise<boolean> {
    if (!await super.matchProof({ proof, document, purpose, documentLoader })) {
      return false;
    }
    if (!this.key) {
      // no key specified, so assume this suite matches and it can be retrieved
      return true;
    }

    const { verificationMethod } = proof;

    // only match if the key specified matches the one in the proof
    if (typeof verificationMethod === 'object') {
      return verificationMethod.id === this.key.id;
    }
    return verificationMethod === this.key.id;
  }
}

/**
 * Tests whether a provided JSON-LD document includes a context url in its
 * `@context` property.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.document - A JSON-LD document.
 * @param {string} options.contextUrl - A context url.
 *
 * @returns {boolean} Returns true if document includes context.
 */
function _includesContext({ document, contextUrl }: any): boolean {
  const context = document['@context'];
  return context === contextUrl ||
    (Array.isArray(context) && context.includes(contextUrl));
}

