import { Injectable } from "@nestjs/common";
import { KeyService } from "../key-services/key.service";
import { DocumentLoaderService } from "../utils/document-loader.service";
import {
  VerifiableCredential,
  Issuer,
  VerifiablePresentation,
} from "../types/verifiable-credential.types";
// @ts-ignore
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
// @ts-ignore
import {cryptosuite as eddsaRdfc2022CryptoSuite} from "@digitalbazaar/eddsa-rdfc-2022-cryptosuite";
// @ts-ignore
import {cryptosuite as ecdsaRdfc2019CryptoSuite} from "@digitalbazaar/ecdsa-rdfc-2019-cryptosuite";
// @ts-ignore
import { issue, signPresentation as vcSignPresentation } from "@digitalbazaar/vc";

import { formatSigningError, logSigningError } from "../utils/format-signing-error";
import { SignatureType } from "../types/key-types.enum";
import {
  ValidationException,
  SigningException,
  UnsupportedException,
} from "../types/custom-exceptions";
// @ts-ignore
import {cryptosuite as rsaRdfc2025CryptoSuite} from "@eecc/rsa-rdfc-2025-cryptosuite";

@Injectable()
export class DataIntegritySigningService {
  constructor(
    private readonly keyService: KeyService,
    private readonly documentLoaderService: DocumentLoaderService
  ) {}

  /**
   * Sign a verifiable credential using Data Integrity proof
   * @param credential - The verifiable credential to sign
   * @param verificationMethod - The verification method identifier
   * @param secrets - Array of secrets for key derivation
   * @returns Signed verifiable credential with proof
   */
  async signCredential(
    credential: VerifiableCredential,
    verificationMethod: string,
    secrets: string[],
  ): Promise<VerifiableCredential> {

    const keyPair = await this.keyService.getKeyPair(
      verificationMethod,
      secrets
    );

    let suite;
    if (keyPair.signatureType === SignatureType.ED25519_2020) {
      suite = new DataIntegrityProof({
        signer: keyPair.signer(), cryptosuite: eddsaRdfc2022CryptoSuite
      });
    } else if (keyPair.signatureType === SignatureType.ES256) {
      suite = new DataIntegrityProof({
        signer: keyPair.signer(), cryptosuite: ecdsaRdfc2019CryptoSuite
      });
    } else if (keyPair.signatureType === SignatureType.PS256) {
      suite = new DataIntegrityProof({
        signer: keyPair.signer(), cryptosuite: rsaRdfc2025CryptoSuite
      });
    } else {
      throw new UnsupportedException(
        `Signature type ${keyPair.signatureType} is not supported for data integrity proof`
      );
    }

    if (!credential.issuer || typeof credential.issuer === "string") {
      credential.issuer = keyPair.id?.split("#")[0] as Issuer;
    } else {
      credential.issuer.id = keyPair.id?.split("#")[0] as string;
    }

    const documentLoader = await DocumentLoaderService.getDocumentLoader();
    try {
      return await issue({ credential, suite, documentLoader });
    } catch (error: unknown) {
      logSigningError(error);
      throw new SigningException(formatSigningError(error));
    }
  }

  /**
   * Sign a verifiable presentation using Data Integrity proof
   * @param presentation - The verifiable presentation to sign
   * @param verificationMethod - The verification method identifier
   * @param secrets - Array of secrets for key derivation
   * @param challenge - Challenge for the proof (e.g. OpenID4VCI `c_nonce` for `di_vp` when the issuer uses a Nonce Endpoint)
   * @param domain - Optional domain for the proof; required for OpenID4VCI `di_vp` (Credential Issuer Identifier), enforced at `AppService.signProofOfPossession`
   * @param validUntil - ISO 8601 date-time; overwrites `presentation.validUntil` when set
   * @returns Signed verifiable presentation with proof
   */
  async signPresentation(
    presentation: VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    challenge: string = "",
    domain?: string,
    validUntil?: string,
  ): Promise<VerifiablePresentation> {

    const keyPair = await this.keyService.getKeyPair(
      verificationMethod,
      secrets
    );
    
    let suite;
    if (keyPair.signatureType === SignatureType.ED25519_2020) {
      suite = new DataIntegrityProof({
        signer: keyPair.signer(), cryptosuite: eddsaRdfc2022CryptoSuite
      });
    } else if (keyPair.signatureType === SignatureType.ES256) {
      suite = new DataIntegrityProof({
        signer: keyPair.signer(), cryptosuite: ecdsaRdfc2019CryptoSuite
      });
    } else if (keyPair.signatureType === SignatureType.PS256) {
      suite = new DataIntegrityProof({
        signer: keyPair.signer(), cryptosuite: rsaRdfc2025CryptoSuite
      });
    } else {
      throw new UnsupportedException(
        `Signature type ${keyPair.signatureType} is not supported for data integrity proof`
      );
    }

    if (!presentation.holder) {
      presentation.holder = keyPair.id?.split("#")[0] as string;
    }

    // Request-level `validUntil` overwrites whatever is on the presentation object
    if (validUntil) {
      presentation.validUntil = validUntil;
    }

    const documentLoader = await DocumentLoaderService.getDocumentLoader();
    try {
        return await vcSignPresentation({ presentation, suite, documentLoader, challenge, domain });
    } catch (error: unknown) {
      logSigningError(error);
      throw new SigningException(formatSigningError(error));
    }
  }
}



