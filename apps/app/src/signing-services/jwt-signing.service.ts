import { Injectable } from "@nestjs/common";
import { KeyService } from "../key-services/key.service";
import {
  Issuer,
  VerifiableCredential,
  VerifiablePresentation,
} from "../types/verifiable-credential.types";
import * as jose from "jose";
import { SignatureType } from "../types/key-types.enum";

@Injectable()
export class JwtSigningService {
  constructor(private readonly keyService: KeyService) {}

  async signVC(
    credential: VerifiableCredential,
    verificationMethod: string,
    secrets: string[]
  ): Promise<string> {
    // set issuer from key pair controller
    const setIssuer = (keyPairId: string) => {
      if (!credential.issuer || typeof credential.issuer === "string") {
        credential.issuer = keyPairId.split("#")[0] as Issuer;
      } else {
        credential.issuer.id = keyPairId.split("#")[0] as string;
      }
    };

    // add issuance date in DM V1
    if (
      credential["@context"].includes(
        "https://www.w3.org/2018/credentials/v1"
      ) &&
      !credential.issuanceDate
    ) {
      credential.issuanceDate = new Date()
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z");
    }

    return this.sign(credential, verificationMethod, secrets, setIssuer);
  }

  async signVP(
    presentation: VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    challenge?: string,
    domain?: string,
  ): Promise<string> {
    return this.sign(presentation, verificationMethod, secrets, () => {}, challenge, domain);
  }

  private async sign(payload: VerifiableCredential | VerifiablePresentation, verificationMethod: string, secrets: string[], preSignHook?: (keyPairId: string) => void, nonce?: string, aud?: string): Promise<string> {
    const keyPair = await this.keyService.getKeyPair(
      verificationMethod,
      secrets
    );
    const signer = await keyPair.signer();
    const header = {
      kid: keyPair.id,
      alg: keyPair.signatureType,
      ...(nonce && { nonce }),
      ...(aud && { aud }),
    };

    if (preSignHook && keyPair.id) {
      preSignHook(keyPair.id);
    }

    const signingInput: string = [
      jose.base64url.encode(JSON.stringify(header)),
      jose.base64url.encode(
        JSON.stringify({
          ...payload,
          iat: Math.floor(Date.now() / 1000),
        })
      ),
    ].join(".");
    
    const signature = jose.base64url.encode(
      await signer.sign({ data: new TextEncoder().encode(signingInput) })
    );
    return [signingInput, signature].join(".");
  }
}
