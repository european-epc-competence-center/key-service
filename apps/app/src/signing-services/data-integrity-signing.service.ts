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
   * @param keyType - Key type (currently only Ed25519_2020 supported)
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

    if (keyPair.signatureType !== SignatureType.ED25519_2020) {
      throw new UnsupportedException(
        "Currently only Ed25519 is supported for data integrity proof"
      );
    }
    
    const suite = new Ed25519Signature2020({
      key: keyPair,
    });

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
   * @param keyType - Key type (currently only Ed25519_2020 supported)
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
    if (keyPair.signatureType !== SignatureType.ED25519_2020) {
      throw new UnsupportedException(
        "Currently only Ed25519 is supported for data integrity proof"
      );
    }
    const suite = new Ed25519Signature2020({
      key: keyPair,
    });

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



