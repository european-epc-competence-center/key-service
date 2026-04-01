import { Injectable } from "@nestjs/common";
import { KeyService } from "../key-services/key.service";
import {
  Issuer,
  VerifiableCredential,
  VerifiablePresentation,
} from "../types/verifiable-credential.types";
import * as jose from "jose";

/** OID4VCI Appendix F.1 — JOSE `typ` for key proof JWTs (`signProofOfPossession` / `POST /sign/pop/jwt`). */
const OPENID4VCI_PROOF_JWT_TYP = "openid4vci-proof+jwt";

function isVerifiablePresentation(
  p: VerifiableCredential | VerifiablePresentation,
): p is VerifiablePresentation {
  return (
    typeof p === "object" &&
    p !== null &&
    "verifiableCredential" in p
  );
}

@Injectable()
export class JwtSigningService {
  constructor(private readonly keyService: KeyService) {}

  async signCredential(
    credential: VerifiableCredential,
    verificationMethod: string,
    secrets: string[],
    additionalHeaders?: Record<string, unknown>,
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
      additionalHeaders,
    );
  }

  /** W3C JWT VP (`POST /sign/vp/jwt`). */
  async signPresentation(
    presentation: VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    challenge?: string,
    domain?: string,
    additionalHeaders?: Record<string, unknown>,
  ): Promise<string> {
    return this.signJwt(
      presentation,
      verificationMethod,
      secrets,
      () => {},
      challenge,
      domain,
      additionalHeaders,
    );
  }

  /**
   * OpenID4VCI Appendix F.1 key proof JWT (`POST /sign/pop/jwt`): VC- or VP-shaped payload; proof claims in the JWT body only.
   */
  async signProofOfPossession(
    credential: VerifiableCredential,
    verificationMethod: string,
    secrets: string[],
    additionalHeaders?: Record<string, unknown>,
  ): Promise<string>;
  async signProofOfPossession(
    presentation: VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    challenge?: string,
    domain?: string,
    additionalHeaders?: Record<string, unknown>,
  ): Promise<string>;
  async signProofOfPossession(
    payload: VerifiableCredential | VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    arg4?: string | Record<string, unknown>,
    domain?: string,
    additionalHeaders?: Record<string, unknown>,
  ): Promise<string> {
    if (isVerifiablePresentation(payload)) {
      let challenge: string | undefined;
      let headers: Record<string, unknown> | undefined;
      if (typeof arg4 === "string") {
        challenge = arg4;
        headers = additionalHeaders;
      } else if (typeof arg4 === "object" && arg4 !== null) {
        headers = arg4 as Record<string, unknown>;
      } else {
        headers = additionalHeaders;
      }
      return this.signOpenId4VciProofJwt(
        payload,
        verificationMethod,
        secrets,
        () => {},
        challenge,
        domain,
        headers,
      );
    }

    const credential = payload as VerifiableCredential;
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

    const headers =
      typeof arg4 === "object" && arg4 !== null
        ? (arg4 as Record<string, unknown>)
        : undefined;

    return this.signOpenId4VciProofJwt(
      credential,
      verificationMethod,
      secrets,
      setIssuer,
      undefined,
      undefined,
      headers,
    );
  }

  private async signOpenId4VciProofJwt(
    payload: VerifiableCredential | VerifiablePresentation,
    verificationMethod: string,
    secrets: string[],
    preSignHook: ((keyPairId: string) => void) | undefined,
    nonce: string | undefined,
    aud: string | undefined,
    additionalHeaders?: Record<string, unknown>,
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

    if (preSignHook && keyPair.id) {
      preSignHook(keyPair.id);
    }

    const basePayload =
      typeof payload === "object" && payload !== null
        ? { ...(payload as unknown as Record<string, unknown>) }
        : {};

    const jwtPayload: Record<string, unknown> = {
      ...basePayload,
      iat,
      ...(iss !== undefined && iss !== "" && { iss }),
      ...(nonce !== undefined && nonce !== "" && { nonce }),
      ...(aud !== undefined && aud !== "" && { aud }),
    };

    const header: Record<string, unknown> = {
      typ: OPENID4VCI_PROOF_JWT_TYP,
      kid: keyPair.id,
      alg: keyPair.signatureType,
    };
    const bodyClaimKeys = new Set(["iat", "iss", "nonce", "aud"]);
    for (const [k, v] of Object.entries(additionalHeaders ?? {})) {
      if (bodyClaimKeys.has(k) || k === "typ") continue;
      header[k] = v;
    }

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
    additionalHeaders?: Record<string, unknown>,
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

    const extra = { ...(additionalHeaders ?? {}) };

    const basePayload =
      typeof payload === "object" && payload !== null
        ? { ...(payload as unknown as Record<string, unknown>) }
        : {};

    const jwtPayload: Record<string, unknown> = { ...basePayload };
    const header: Record<string, unknown> = {
      ...extra,
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
