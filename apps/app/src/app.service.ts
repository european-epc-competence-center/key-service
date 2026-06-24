import { BadRequestException, Injectable } from "@nestjs/common";
import { JwtSigningService } from "./signing-services/jwt-signing.service";
import { DataIntegritySigningService } from "./signing-services/data-integrity-signing.service";
import { KeyService } from "./key-services/key.service";
import { PayloadEncryptionService } from "./key-services/payload-encryption.service";
import { SignType } from "./types/sign-types.enum";
import {
  GenerateRequestDto,
  KeyRequestDto,
  SignRequestDto,
  RawSignRequestDto,
} from "./types/request.dto";
import { VerifiableCredential, VerifiablePresentation } from "./types/verifiable-credential.types";
import { VerificationMethod } from "./types";
import { EncryptedPayloadDto } from "./types/encrypted-payload.dto";
import { SignatureType } from "./types/key-types.enum";
import { UnsupportedException } from "./types/custom-exceptions";

/** did:webvh signing input: SHA-256(proofOptions) ‖ SHA-256(document) = 32 + 32 bytes. */
const RAW_SIGN_INPUT_BYTES = 64;

@Injectable()
export class AppService {
  constructor(
    private readonly jwtSigningService: JwtSigningService,
    private readonly dataIntegritySigningService: DataIntegritySigningService,
    private readonly keyService: KeyService,
    private readonly encryptionService: PayloadEncryptionService
  ) {}

  /**
   * Decrypts payload if encryption is enabled and encryptedData field is present
   * @param body - Request body that may contain encryptedData field
   * @returns Decrypted payload or original body if not encrypted
   */
  private decryptPayloadIfNeeded<T>(body: any): T {
    // Only process if encryption is enabled
    if (!this.encryptionService.isEnabled()) {
      return body as T;
    }

    // Check if request contains encrypted data
    if (body && typeof body === "object" && "encryptedData" in body) {
      try {
        // Decrypt the payload
        const decryptedPayload = this.encryptionService.decryptJson<T>(
          body.encryptedData
        );

        return decryptedPayload;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        throw new BadRequestException(
          `Failed to decrypt request payload: ${errorMessage}`
        );
      }
    }

    // Return unencrypted payload as-is
    return body as T;
  }

  private getSigningService(type: SignType) {
    switch (type) {
      case SignType.JWT:
        return this.jwtSigningService;
      case SignType.DATA_INTEGRITY:
        return this.dataIntegritySigningService;
      case SignType.SD_JWT:
        throw new Error("Signed SD-JWT (not implemented)");
      default:
        throw new Error(
          `Unsupported sign type: ${type}. Choose one of ${Object.values(SignType).join(", ")}`
        );
    }
  }

  async signCredential(
    type: SignType,
    body: SignRequestDto | EncryptedPayloadDto
  ): Promise<VerifiableCredential | string> {
    // Decrypt payload if encrypted
    const decryptedBody = this.decryptPayloadIfNeeded<SignRequestDto>(body);
    
    const { verifiable, identifier, secrets } = decryptedBody;
    const service = this.getSigningService(type);
    return service.signCredential(
      verifiable as VerifiableCredential,
      identifier,
      secrets,
    );
  }

  async signPresentation(
    type: SignType,
    body: SignRequestDto | EncryptedPayloadDto
  ): Promise<VerifiablePresentation | string> {
    const { verifiable, identifier, secrets, challenge, domain, validUntil } =
      this.decryptPayloadIfNeeded<SignRequestDto>(body);
    const service = this.getSigningService(type);
    return service.signPresentation(
      verifiable as VerifiablePresentation,
      identifier,
      secrets,
      challenge,
      domain,
      validUntil?.trim() || undefined,
    );
  }

  /**
   * Proof-of-possession: same `type` values as `POST /sign/vp/:type`.
   * For `jwt`, OpenID4VCI Appendix F.1 — non-empty `domain` → JWT `aud`; `verifiable` optional and ignored.
   * For `data-integrity`, OpenID4VCI Appendix F.2 `di_vp` — builds a minimal VP shell and delegates to `signPresentation` (`domain` required, optional `challenge`); request `verifiable` is ignored.
   */
  async signProofOfPossession(
    type: SignType,
    body: SignRequestDto | EncryptedPayloadDto,
  ): Promise<VerifiablePresentation | string> {
    if (type === SignType.SD_JWT) {
      throw new BadRequestException(
        "Proof-of-possession supports jwt and data-integrity only (not sd-jwt)",
      );
    }

    const decryptedBody = this.decryptPayloadIfNeeded<SignRequestDto>(body);
    const { identifier, secrets, challenge, domain, validUntil } =
      decryptedBody;

    if (type === SignType.JWT) {
      const aud = domain?.trim();
      if (!aud) {
        throw new BadRequestException(
          "JWT proof of possession requires non-empty `domain` (Credential Issuer Identifier) for JWT claim `aud` (OpenID4VCI Appendix F.1).",
        );
      }
      return this.jwtSigningService.signProofOfPossession(
        identifier,
        secrets,
        aud,
        challenge?.trim() || undefined,
        validUntil?.trim() || undefined,
      );
    }

    if (!domain?.trim()) {
      throw new BadRequestException(
        "Data Integrity proof of possession requires non-empty `domain` (Credential Issuer Identifier) for proof `domain` (OpenID4VCI Appendix F.2 di_vp).",
      );
    }

    return this.signPresentation(SignType.DATA_INTEGRITY, {
      ...decryptedBody,
      verifiable: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        type: ["VerifiablePresentation"],
        holder: identifier?.split("#")[0] as string,
        ...(validUntil?.trim() && { validUntil: validUntil.trim() }),
      } satisfies VerifiablePresentation,
    });
  }

  /**
   * Raw Ed25519 signing for the did:webvh Java library (`POST /sign/raw`).
   *
   * The library pre-hashes everything and hands its Signer a finished 64-byte input
   * (`SHA-256(JCS(proofOptions)) ‖ SHA-256(JCS(document))`), expecting the raw Ed25519
   * signature back — it does the multibase/proofValue encoding itself. So we sign the bytes
   * with plain Ed25519 and do no extra hashing and no multibase encoding here.
   *
   * `data`/`signature` are base64 only because JSON can't carry raw bytes; we use standard
   * base64 (Java's `java.util.Base64`), not url-safe.
   */
  async signRaw(
    body: RawSignRequestDto | EncryptedPayloadDto
  ): Promise<{ signature: string }> {
    // Same encrypted-payload envelope as every other /sign endpoint.
    const { identifier, secrets, data } =
      this.decryptPayloadIfNeeded<RawSignRequestDto>(body);

    // getKeyPair decrypts the private key via `secrets` and applies failed-attempt protection.
    const keyPair = await this.keyService.getKeyPair(identifier, secrets);

    // did:webvh update keys are Ed25519; other algorithms can't be verified by the library.
    if (keyPair.signatureType !== SignatureType.ED25519_2020) {
      throw new UnsupportedException(
        `Raw signing supports Ed25519 keys only, but the stored key is ${keyPair.signatureType}`
      );
    }

    // Decode to bytes and reject anything that isn't exactly the 64-byte webvh input.
    const dataBytes = Buffer.from(data, "base64");
    if (dataBytes.length !== RAW_SIGN_INPUT_BYTES) {
      throw new BadRequestException(
        `Raw signing input must be exactly ${RAW_SIGN_INPUT_BYTES} bytes, but got ${dataBytes.length} after base64-decoding`
      );
    }

    // Plain Ed25519 over the bytes as-is; signer returns the raw signature.
    const signer = await keyPair.signer();
    const signatureBytes = await signer.sign({ data: dataBytes });

    return { signature: Buffer.from(signatureBytes).toString("base64") };
  }

  async generateKey(request: GenerateRequestDto | EncryptedPayloadDto): Promise<VerificationMethod> {
    // Decrypt payload if encrypted
    const decryptedRequest = this.decryptPayloadIfNeeded<GenerateRequestDto>(request);
    
    const { keyType, signatureType, identifier, secrets } = decryptedRequest;

    // Generate the key pair using the existing KeyService
    return await this.keyService.generateKeyPair(
      signatureType,
      keyType,
      identifier,
      secrets
    );
  }

  async deleteKey(request: KeyRequestDto | EncryptedPayloadDto): Promise<void> {
    // Decrypt payload if encrypted
    const decryptedRequest = this.decryptPayloadIfNeeded<KeyRequestDto>(request);
    
    const { identifier, secrets } = decryptedRequest;
    return await this.keyService.deleteKey(identifier, secrets);
  }
}
