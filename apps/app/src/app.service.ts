import { BadRequestException, Injectable } from "@nestjs/common";
import { JwtSigningService } from "./signing-services/jwt-signing.service";
import { DataIntegritySigningService } from "./signing-services/data-integrity-signing.service";
import { KeyService } from "./key-services/key.service";
import { PayloadEncryptionService } from "./key-services/payload-encryption.service";
import { SignType } from "./types/sign-types.enum";
import { GenerateRequestDto, PresentRequestDto, SignRequestDto } from "./types/request.dto";
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

  async signVC(
    type: SignType,
    body: SignRequestDto | EncryptedPayloadDto
  ): Promise<VerifiableCredential | string> {
    // Decrypt payload if encrypted
    const decryptedBody = this.decryptPayloadIfNeeded<SignRequestDto>(body);
    
    const { verifiable, identifier, secrets } = decryptedBody;
    const service = this.getSigningService(type);
    return service.signVC(verifiable as VerifiableCredential, identifier, secrets);
  }

  async signVP(
    type: SignType,
    body: PresentRequestDto | EncryptedPayloadDto
  ): Promise<VerifiablePresentation | string> {
    // Decrypt payload if encrypted
    const decryptedBody = this.decryptPayloadIfNeeded<PresentRequestDto>(body);
    
    const { verifiable, identifier, secrets, challenge, domain } = decryptedBody;
    const service = this.getSigningService(type);
    return service.signVP(verifiable as VerifiablePresentation, identifier, secrets, challenge, domain);
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
}
