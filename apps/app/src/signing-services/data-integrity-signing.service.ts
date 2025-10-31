import { Injectable } from "@nestjs/common";
import { KeyService } from "../key-services/key.service";
import { DocumentLoaderService } from "../utils/document-loader.service";
import {
  VerifiableCredential,
  DataIntegrityProof,
  Issuer,
  VerifiablePresentation,
} from "../types/verifiable-credential.types";
// @ts-ignore
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";
// @ts-ignore
import { issue, signPresentation } from "@digitalbazaar/vc";

import { logDebug, logError } from "../utils/log/logger";
import { SignatureType } from "../types/key-types.enum";
import {
  ValidationException,
  SigningException,
  UnsupportedException,
} from "../types/custom-exceptions";
import { ES256Signature2020 } from "./ES256Signature2020";

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
  async signVC(
    credential: VerifiableCredential,
    verificationMethod: string,
    secrets: string[]
  ): Promise<VerifiableCredential> {

    const keyPair = await this.keyService.getKeyPair(
      verificationMethod,
      secrets
    );

    let suite;
    if (keyPair.signatureType === SignatureType.ED25519_2020) {
      suite = new Ed25519Signature2020({
        key: keyPair,
      });
    } else if (keyPair.signatureType === SignatureType.ES256) {
      // For ES256, we need to call the signer/verifier methods and pass the results
      // directly to the suite, along with a key object for metadata
      const signer = await keyPair.signer();
      const verifier = keyPair.verifier ? await keyPair.verifier() : undefined;
      
      suite = new ES256Signature2020({
        signer,
        verifier,
        // Pass key metadata (without signer/verifier methods)
        // This will be used by getVerificationMethod
      });
      
      // Store key reference on the suite for later use
      (suite as any).keyId = keyPair.id;
      (suite as any).keyController = keyPair.controller;
      (suite as any).keyPublicKey = keyPair.publicKey;
      // Set verification method on the suite
      (suite as any).verificationMethod = keyPair.id;
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
    } catch (error: any) {
      if (error.details) {
        logError("Error details:\n" + JSON.stringify(error.details, null, 2));
        throw new SigningException(
          `Failed to sign: ${error.details.message} - ${error.details}`
        );
      }
      throw new SigningException(`Failed to sign: ${error.message}`);
    }
  }

  /**
   * Sign a verifiable presentation using Data Integrity proof
   * @param presentation - The verifiable presentation to sign
   * @param verificationMethod - The verification method identifier
   * @param secrets - Array of secrets for key derivation
   * @param challenge - Challenge string for the proof
   * @param domain - Optional domain for the proof
   * @returns Signed verifiable presentation with proof
   */
  async signVP(
    presentation: VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    challenge: string = "",
    domain?: string
  ): Promise<VerifiablePresentation> {

    const keyPair = await this.keyService.getKeyPair(
      verificationMethod,
      secrets
    );
    
    let suite;
    if (keyPair.signatureType === SignatureType.ED25519_2020) {
      suite = new Ed25519Signature2020({
        key: keyPair,
      });
    } else if (keyPair.signatureType === SignatureType.ES256) {
      // For ES256, we need to call the signer/verifier methods and pass the results
      // directly to the suite, along with a key object for metadata
      const signer = await keyPair.signer();
      const verifier = keyPair.verifier ? await keyPair.verifier() : undefined;
      
      suite = new ES256Signature2020({
        signer,
        verifier,
        // Pass key metadata (without signer/verifier methods)
        // This will be used by getVerificationMethod
      });
      
      // Store key reference on the suite for later use
      (suite as any).keyId = keyPair.id;
      (suite as any).keyController = keyPair.controller;
      (suite as any).keyPublicKey = keyPair.publicKey;
      // Set verification method on the suite
      (suite as any).verificationMethod = keyPair.id;
    } else {
      throw new UnsupportedException(
        `Signature type ${keyPair.signatureType} is not supported for data integrity proof`
      );
    }

    if (!presentation.holder) {
      presentation.holder = keyPair.id?.split("#")[0] as string;
    }

    const documentLoader = await DocumentLoaderService.getDocumentLoader();
    try {
        return await signPresentation({ presentation, suite, documentLoader, challenge, domain });
    } catch (error: any) {
      if (error.details) {
        logError("Error details:\n" + JSON.stringify(error.details, null, 2));
        throw new SigningException(
          `Failed to sign: ${error.details.message} - ${error.details}`
        );
      }
      throw new SigningException(`Failed to sign: ${error.message}`);
    }
  }
}



