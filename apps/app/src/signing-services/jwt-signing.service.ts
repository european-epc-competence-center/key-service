import { Injectable } from "@nestjs/common";
import { KeyService } from "../key-services/key.service";
import {
  Issuer,
  VerifiableCredential,
  VerifiablePresentation,
} from "../types/verifiable-credential.types";
import * as jose from "jose";

/**
 * OpenID4VCI 1.0 — `jwt` proof type (Appendix F.1): JOSE `typ` for key proof JWTs sent in
 * `proofs.jwt` on the [Credential Request](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request) (Section 8.2).
 * Used by `signProofOfPossession` / `POST /sign/pop/jwt`.
 */
const OPENID4VCI_PROOF_JWT_TYP = "openid4vci-proof+jwt";

@Injectable()
export class JwtSigningService {
  constructor(private readonly keyService: KeyService) {}

  async signCredential(
    credential: VerifiableCredential,
    verificationMethod: string,
    secrets: string[],
  ): Promise<string> {
    const setIssuer = (keyPairId: string) => {
      if (!credential.issuer || typeof credential.issuer === "string") {
        credential.issuer = keyPairId.split("#")[0] as Issuer;
      } else {
        credential.issuer.id = keyPairId.split("#")[0] as string;
      }
    };

    if (
      credential["@context"].includes(
        "https://www.w3.org/2018/credentials/v1",
      ) &&
      !credential.issuanceDate
    ) {
      credential.issuanceDate = new Date()
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z");
    }

    return this.signJwt(
      credential,
      verificationMethod,
      secrets,
      setIssuer,
      undefined,
      undefined,
    );
  }

  /** W3C JWT VP (`POST /sign/vp/jwt`). */
  async signPresentation(
    presentation: VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    challenge?: string,
    domain?: string,
  ): Promise<string> {
    return this.signJwt(
      presentation,
      verificationMethod,
      secrets,
      () => {},
      challenge,
      domain,
    );
  }

  /**
   * OpenID4VCI 1.0 Appendix F.1 [jwt proof type](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type):
   * a normal JWT for key proof (not a VC). JOSE header: `typ` `openid4vci-proof+jwt`, `alg`, `kid` (and optionally `jwk` / `x5c` / attestation — not set here).
   * JWT body: `aud` (Credential Issuer Identifier), `iat` (required); optional `iss` (e.g. wallet `client_id` / holder DID from `kid`), `nonce` (`c_nonce` when the issuer uses the Nonce Endpoint).
   *
   * HTTP: `POST /sign/pop/jwt` — `domain` is required (maps to `aud`); `verifiable` is ignored.
   */
  async signProofOfPossession(
    verificationMethod: string,
    secrets: string[],
    credentialIssuerIdentifier: string,
    challenge?: string,
  ): Promise<string> {
    const keyPair = await this.keyService.getKeyPair(
      verificationMethod,
      secrets,
    );
    const signer = await keyPair.signer();
    const iat = Math.floor(Date.now() / 1000);
    const iss = keyPair.id
      ? keyPair.id.includes("#")
        ? keyPair.id.split("#")[0]
        : keyPair.id
      : undefined;

    const jwtPayload: Record<string, unknown> = {
      aud: credentialIssuerIdentifier,
      iat,
      ...(iss !== undefined && iss !== "" && { iss }),
      ...(challenge !== undefined &&
        challenge !== "" && { nonce: challenge }),
    };

    const header: Record<string, unknown> = {
      typ: OPENID4VCI_PROOF_JWT_TYP,
      kid: keyPair.id,
      alg: keyPair.signatureType,
    };

    const signingInput: string = [
      jose.base64url.encode(JSON.stringify(header)),
      jose.base64url.encode(JSON.stringify(jwtPayload)),
    ].join(".");

    const signature = jose.base64url.encode(
      await signer.sign({ data: new TextEncoder().encode(signingInput) }),
    );
    return [signingInput, signature].join(".");
  }

  /** W3C JWT-VC: protected header carries `iat`/`iss`/`nonce`/`aud` as applicable. */
  private async signJwt(
    payload: VerifiableCredential | VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    preSignHook?: (keyPairId: string) => void,
    nonce?: string,
    aud?: string,
  ): Promise<string> {
    const keyPair = await this.keyService.getKeyPair(
      verificationMethod,
      secrets
    );
    const signer = await keyPair.signer();
    const iat = Math.floor(Date.now() / 1000);
    const iss = keyPair.id
      ? keyPair.id.includes("#")
        ? keyPair.id.split("#")[0]
        : keyPair.id
      : undefined;

    if (preSignHook && keyPair.id) {
      preSignHook(keyPair.id);
    }

    const basePayload =
      typeof payload === "object" && payload !== null
        ? { ...(payload as unknown as Record<string, unknown>) }
        : {};

    const jwtPayload: Record<string, unknown> = { ...basePayload };
    const header: Record<string, unknown> = {
      kid: keyPair.id,
      alg: keyPair.signatureType,
      iat,
      ...(iss !== undefined && iss !== "" && { iss }),
      ...(nonce !== undefined && nonce !== "" && { nonce }),
      ...(aud !== undefined && aud !== "" && { aud }),
    };

    const signingInput: string = [
      jose.base64url.encode(JSON.stringify(header)),
      jose.base64url.encode(JSON.stringify(jwtPayload)),
    ].join(".");
    
    const signature = jose.base64url.encode(
      await signer.sign({ data: new TextEncoder().encode(signingInput) })
    );
    return [signingInput, signature].join(".");
  }
}
