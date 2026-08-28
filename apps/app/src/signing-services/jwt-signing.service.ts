import { Injectable } from "@nestjs/common";
import { KeyService } from "../key-services/key.service";
import {
  Issuer,
  VerifiableCredential,
  VerifiablePresentation,
} from "../types/verifiable-credential.types";
import * as jose from "jose";
import { formatSigningError, logSigningError } from "../utils/format-signing-error";
import { SigningException } from "../types/custom-exceptions";

/**
 * W3C VC-JOSE-COSE: JOSE `typ` for secured verifiable credentials as JWTs
 * ([Securing VCs](https://www.w3.org/TR/vc-jose-cose/#vc-jose)).
 */
const VC_JWT_TYP = "vc+jwt";

/**
 * W3C VC-JOSE-COSE: JOSE `typ` for secured verifiable presentations as JWTs
 * ([Securing VPs](https://www.w3.org/TR/vc-jose-cose/#vp-jose)).
 */
const VP_JWT_TYP = "vp+jwt";

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
    identifier: string,
    secrets: string[],
    publicIdentifier?: string,
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

    return this.signJwtVerifiable(
      credential,
      identifier,
      secrets,
      VC_JWT_TYP,
      publicIdentifier,
      credential.validUntil,
      setIssuer,
    );
  }

  /** W3C JWT VP (`POST /sign/vp/jwt`). Sets `exp` from `validUntil` ISO 8601 when present. */
  async signPresentation(
    presentation: VerifiablePresentation,
    identifier: string,
    secrets: string[],
    challenge?: string,
    domain?: string,
    validUntil?: string,
    publicIdentifier?: string,
  ): Promise<string> {
    return this.signJwtVerifiable(
      presentation,
      identifier,
      secrets,
      VP_JWT_TYP,
      publicIdentifier,
      validUntil || presentation.validUntil,
      () => {},
      challenge,
      domain,
    );
  }

  /**
   * OpenID4VCI 1.0 Appendix F.1 [jwt proof type](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type):
   * a normal JWT for key proof (not a VC). JOSE header: `typ` `openid4vci-proof+jwt`, `alg`, `kid` (and optionally `jwk` / `x5c` / attestation — not set here).
   * JWT body: `aud` (Credential Issuer Identifier), `iat` (required); optional `iss` (e.g. wallet `client_id` / holder DID from `kid`), `nonce` (`c_nonce` when the issuer uses the Nonce Endpoint), `exp` (derived from `validUntil` ISO 8601).
   *
   * HTTP: `POST /sign/pop/jwt` — `domain` is required (maps to `aud`); `verifiable` is optional and ignored.
   */
  async signProofOfPossession(
    identifier: string,
    secrets: string[],
    credentialIssuerIdentifier: string,
    challenge?: string,
    validUntil?: string,
    publicIdentifier?: string,
  ): Promise<string> {
    try {
      const keyPair = await this.keyService.getKeyPair(
        identifier,
        secrets,
        publicIdentifier,
      );
      const signer = await keyPair.signer();
      const iat = Math.floor(Date.now() / 1000);
      const iss = keyPair.id
        ? keyPair.id.includes("#")
          ? keyPair.id.split("#")[0]
          : keyPair.id
        : undefined;

      const exp = validUntil
        ? Math.floor(new Date(validUntil).getTime() / 1000)
        : undefined;

      const jwtPayload: Record<string, unknown> = {
        aud: credentialIssuerIdentifier,
        iat,
        ...(iss !== undefined && iss !== "" && { iss }),
        ...(challenge !== undefined &&
          challenge !== "" && { nonce: challenge }),
        ...(exp !== undefined && { exp }),
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
    } catch (error: unknown) {
      logSigningError(error);
      throw new SigningException(formatSigningError(error));
    }
  }

  /**
   * W3C JWT-VC / JWT-VP: JWS protected header carries `typ` (`vc+jwt` / `vp+jwt`), `alg`, `kid`,
   * and `iss` (signing key controller: `kid` without the fragment), per
   * [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/) and
   * [key discovery](https://w3c.github.io/vc-jose-cose/#using-header-params-claims-key-discovery).
   * Both VC and VP may pass `validUntil` (ISO 8601) → `exp`; VP may also pass `nonce` / `aud`.
   */
  private async signJwtVerifiable(
    payload: VerifiableCredential | VerifiablePresentation,
    identifier: string,
    secrets: string[],
    typ: typeof VC_JWT_TYP | typeof VP_JWT_TYP,
    publicIdentifier?: string,
    validUntil?: string,
    preSignHook?: (keyPairId: string) => void,
    nonce?: string,
    aud?: string,
  ): Promise<string> {
    try {
      const keyPair = await this.keyService.getKeyPair(
        identifier,
        secrets,
        publicIdentifier
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

      // When `validUntil` is provided, replace the VC/VP-level `validUntil` in the payload
      // with the request parameter value, and also set a JWT `exp` claim derived from it.
      if (validUntil) {
        basePayload.validUntil = validUntil;
      }

      const jwtPayload: Record<string, unknown> = { ...basePayload };

      Object.assign(jwtPayload, {
        iat,
        ...(nonce !== undefined && nonce !== "" && { nonce }),
        ...(aud !== undefined && aud !== "" && { aud }),
        ...(validUntil && {
          exp: Math.floor(new Date(validUntil).getTime() / 1000),
        }),
      });

      const header: Record<string, unknown> = {
        typ,
        kid: keyPair.id,
        alg: keyPair.signatureType,
        ...(iss !== undefined && iss !== "" && { iss }),
      };

      const signingInput: string = [
        jose.base64url.encode(JSON.stringify(header)),
        jose.base64url.encode(JSON.stringify(jwtPayload)),
      ].join(".");

      const signature = jose.base64url.encode(
        await signer.sign({ data: new TextEncoder().encode(signingInput) })
      );
      return [signingInput, signature].join(".");
    } catch (error: unknown) {
      logSigningError(error);
      throw new SigningException(formatSigningError(error));
    }
  }
}
