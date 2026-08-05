import {
  ArgumentMetadata,
  BadRequestException,
  Injectable,
  PipeTransform,
  Type,
} from "@nestjs/common";
import { plainToInstance } from "class-transformer";
import { validate, ValidationError } from "class-validator";
import { EncryptedPayloadDto } from "../types/encrypted-payload.dto";

const VALIDATION_OPTIONS = {
  whitelist: true,
  forbidNonWhitelisted: true,
  stopAtFirstError: false,
};

function flattenErrors(errors: ValidationError[]): string[] {
  const messages: string[] = [];
  for (const error of errors) {
    if (error.constraints) {
      messages.push(...Object.values(error.constraints));
    }
    if (error.children?.length) {
      messages.push(...flattenErrors(error.children));
    }
  }
  return messages;
}

/**
 * Validates request bodies when the controller parameter type is a TypeScript union
 * (e.g. `GenerateRequestDto | EncryptedPayloadDto`). Nest's global ValidationPipe
 * cannot resolve unions (runtime metatype becomes `Object`), so validation would
 * be skipped without this pipe.
 *
 * Encrypted requests (`encryptedData`) are validated as {@link EncryptedPayloadDto};
 * otherwise the provided plain DTO class is used.
 */
@Injectable()
export class RequestBodyValidationPipe implements PipeTransform {
  constructor(private readonly dto: Type<object>) {}

  async transform(value: unknown, metadata: ArgumentMetadata): Promise<object> {
    if (metadata.type !== "body") {
      return value as object;
    }

    const isEncrypted =
      value !== null &&
      typeof value === "object" &&
      Object.prototype.hasOwnProperty.call(value, "encryptedData");

    const metatype = isEncrypted ? EncryptedPayloadDto : this.dto;
    const object = plainToInstance(metatype, value ?? {});
    const errors = await validate(object as object, VALIDATION_OPTIONS);

    if (errors.length > 0) {
      throw new BadRequestException({
        message: flattenErrors(errors),
        error: "Bad Request",
        statusCode: 400,
      });
    }

    return object as object;
  }
}
