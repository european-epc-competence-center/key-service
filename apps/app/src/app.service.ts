import { Injectable } from "@nestjs/common";
import { JwtSigningService } from "./signing-services/jwt-signing.service";
import { DataIntegritySigningService } from "./signing-services/data-integrity-signing.service";
import { KeyService } from "./key-services/key.service";
import { SignType } from "./types/sign-types.enum";
import { GenerateRequestDto, PresentRequestDto, SignRequestDto } from "./types/request.dto";
import { VerifiableCredential, VerifiablePresentation } from "./types/verifiable-credential.types";
import { VerificationMethod } from "./types";

@Injectable()
export class AppService {
  constructor(
    private readonly jwtSigningService: JwtSigningService,
    private readonly dataIntegritySigningService: DataIntegritySigningService,
    private readonly keyService: KeyService
  ) {}

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
    body: SignRequestDto
  ): Promise<VerifiableCredential | string> {
    const { verifiable, identifier, secrets } = body;
    const service = this.getSigningService(type);
    return service.signVC(verifiable as VerifiableCredential, identifier, secrets);
  }

  async signVP(
    type: SignType,
    body: PresentRequestDto
  ): Promise<VerifiablePresentation | string> {
    const { verifiable, identifier, secrets, challenge, domain } = body;
    const service = this.getSigningService(type);
    return service.signVP(verifiable as VerifiablePresentation, identifier, secrets, challenge, domain);
  }

  async generateKey(request: GenerateRequestDto): Promise<VerificationMethod> {
    const { keyType, signatureType, identifier, secrets } = request;

    // Generate the key pair using the existing KeyService
    return await this.keyService.generateKeyPair(
      signatureType,
      keyType,
      identifier,
      secrets
    );
  }
}
