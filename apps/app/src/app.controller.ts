import {
  Controller,
  Post,
  Param,
  Body,
  ParseEnumPipe,
} from "@nestjs/common";
import { AppService } from "./app.service";
import { SignType } from "./types/sign-types.enum";
import { GenerateRequestDto, KeyRequestDto, PresentRequestDto, SignRequestDto } from "./types/request.dto";
import { EncryptedPayloadDto } from "./types/encrypted-payload.dto";

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post("sign/vc/:type")
  async signCredential(
    @Param("type", new ParseEnumPipe(SignType)) type: SignType,
    @Body() body: SignRequestDto | EncryptedPayloadDto
  ) {
    return await this.appService.signCredential(type, body);
  }

  @Post("sign/vp/:type")
  async signPresentation(
    @Param("type", new ParseEnumPipe(SignType)) type: SignType,
    @Body() body: PresentRequestDto | EncryptedPayloadDto
  ) {
    return await this.appService.signPresentation(type, body);
  }

  @Post("sign/pop/:type")
  async signProofOfPossession(
    @Param("type", new ParseEnumPipe(SignType)) type: SignType,
    @Body() body: PresentRequestDto | EncryptedPayloadDto,
  ) {
    return await this.appService.signProofOfPossession(type, body);
  }

  @Post("generate")
  generateKey(@Body() body: GenerateRequestDto | EncryptedPayloadDto) {
    return this.appService.generateKey(body);
  }

  @Post("delete")
  deleteKey(@Body() body: KeyRequestDto | EncryptedPayloadDto) {
    return this.appService.deleteKey(body);
  }
}
