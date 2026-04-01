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
} from "./types/request.dto";
import { VerifiableCredential, VerifiablePresentation } from "./types/verifiable-credential.types";
import { VerificationMethod } from "./types";
import { logInfo } from "./utils/log/logger";
import { EncryptedPayloadDto } from "./types/encrypted-payload.dto";

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
    const { verifiable, identifier, secrets, challenge, domain } =
      this.decryptPayloadIfNeeded<SignRequestDto>(body);
    const service = this.getSigningService(type);
    return service.signPresentation(
      verifiable as VerifiablePresentation,
      identifier,
      secrets,
      challenge,
      domain,
    );
  }

  /**
   * Proof-of-possession: same `type` values as `POST /sign/vp/:type`.
   * For `jwt`, OpenID4VCI Appendix F.1 key proof JWT — `domain` (Credential Issuer Identifier) is required for claim `aud`; `verifiable` is ignored.
   * `data-integrity` uses a VP like `/sign/vp/data-integrity`.
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

    const { verifiable, identifier, secrets, challenge, domain } =
      this.decryptPayloadIfNeeded<SignRequestDto>(body);
    const presentation = verifiable as VerifiablePresentation;

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
      );
    }

    return this.dataIntegritySigningService.signPresentation(
      presentation,
      identifier,
      secrets,
      challenge,
      domain,
    );
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
