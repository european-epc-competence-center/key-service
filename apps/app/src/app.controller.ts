import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  ParseEnumPipe,
  Query,
} from "@nestjs/common";
import { AppService } from "./app.service";
import { SignType } from "./types/sign-types.enum";
import { GenerateRequestDto, PresentRequestDto, SignRequestDto } from "./types/request.dto";

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post("sign/vc/:type")
  async signVC(
    @Param("type", new ParseEnumPipe(SignType)) type: SignType,
    @Body() body: SignRequestDto
  ) {
    return await this.appService.signVC(type, body);
  }

  @Post("sign/vp/:type")
  async signVP(
    @Param("type", new ParseEnumPipe(SignType)) type: SignType,
    @Body() body: PresentRequestDto
  ) {
    return await this.appService.signVP(type, body);
  }

  @Post("generate")
  generateKey(@Body() body: GenerateRequestDto) {
    return this.appService.generateKey(body);
  }
}
