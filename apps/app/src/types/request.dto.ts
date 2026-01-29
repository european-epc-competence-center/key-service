import {
  IsString,
  IsNotEmpty,
  IsArray,
  ArrayMinSize,
  ArrayMaxSize,
  IsEnum,
  ValidateNested,
  IsObject,
  MaxLength,
  MinLength,
  Matches,
} from "class-validator";
import { Type, Transform } from "class-transformer";
import {
  VerifiableCredential,
  VerifiablePresentation,
} from "./verifiable-credential.types";
import { SignatureType } from "./key-types.enum";
import { KeyType } from "./key-format.enum";

/**
 * Maximum lengths for input validation to prevent buffer overflow attacks
 */
const MAX_STRING_LENGTH = 10000; // Max length for general strings
const MAX_SECRET_LENGTH = 1000; // Max length for individual secrets
const MAX_IDENTIFIER_LENGTH = 500; // Max length for identifiers
const MAX_SECRETS_ARRAY_SIZE = 10; // Max number of secrets allowed
const MIN_SECRETS_ARRAY_SIZE = 1; // Min number of secrets required

export class KeyRequestDto {
  /**
   * Secrets of the users for key pair authentication
   * Must be an array of strings with length constraints
   */
  @IsArray({ message: "Secrets must be an array" })
  @ArrayMinSize(MIN_SECRETS_ARRAY_SIZE, {
    message: `At least ${MIN_SECRETS_ARRAY_SIZE} secret is required`,
  })
  @ArrayMaxSize(MAX_SECRETS_ARRAY_SIZE, {
    message: `Maximum ${MAX_SECRETS_ARRAY_SIZE} secrets allowed`,
  })
  @IsString({ each: true, message: "Each secret must be a string" })
  @IsNotEmpty({ each: true, message: "Secrets cannot be empty" })
  @MinLength(1, {
    each: true,
    message: "Each secret must be at least 1 character",
  })
  @MaxLength(MAX_SECRET_LENGTH, {
    each: true,
    message: `Each secret must not exceed ${MAX_SECRET_LENGTH} characters`,
  })
  secrets!: string[];

  /**
   * Identifier for the signing key
   * Must be a non-empty string with length constraints
   */
  @IsNotEmpty({ message: "Identifier is required" })
  @IsString({ message: "Identifier must be a string" })
  @MinLength(1, { message: "Identifier must be at least 1 character" })
  @MaxLength(MAX_IDENTIFIER_LENGTH, {
    message: `Identifier must not exceed ${MAX_IDENTIFIER_LENGTH} characters`,
  })
  @Matches(/^[a-zA-Z0-9_\-:.]+$/, {
    message:
      "Identifier must contain only alphanumeric characters, hyphens, underscores, colons, and periods",
  })
  identifier!: string;
}

/**
 * DTO for signing operations
 * Implements comprehensive input validation to prevent injection attacks and buffer overflows
 */
export class SignRequestDto extends KeyRequestDto {
  /**
   * The verifiable credential or presentation to be signed
   * Must be a valid object structure
   */
  @IsNotEmpty({ message: "Verifiable credential/presentation is required" })
  @IsObject({ message: "Verifiable credential/presentation must be an object" })
  @ValidateNested()
  @Type(() => Object)
  verifiable!: VerifiableCredential | VerifiablePresentation;

  
}

/**
 * DTO for presentation signing operations
 * Extends SignRequestDto with additional challenge and domain properties
 * for verifiable presentation proof requirements
 */
export class PresentRequestDto extends SignRequestDto {
  /**
   * Challenge string for the presentation proof
   * Also accepts 'nonce' as an alternative property name
   * Must be a non-empty string with length constraints
   */
  @Transform(({ value, obj }) => value ?? obj.nonce)
  @IsString({ message: "Challenge must be a string" })
  @MaxLength(MAX_STRING_LENGTH, {
    message: `Challenge must not exceed ${MAX_STRING_LENGTH} characters`,
  })
  challenge?: string;

  /**
   * Domain string for the presentation proof
   * Also accepts 'audience' as an alternative property name
   * Must be a non-empty string with length constraints
   */
  @Transform(({ value, obj }) => value ?? obj.audience)
  @IsString({ message: "Domain must be a string" })
  @MaxLength(MAX_STRING_LENGTH, {
    message: `Domain must not exceed ${MAX_STRING_LENGTH} characters`,
  })
  domain?: string;
}

/**
 * DTO for key generation operations
 * Implements comprehensive input validation for key generation requests
 */
export class GenerateRequestDto extends KeyRequestDto {

  /**
   * Type of signing key to generate
   * Must be a valid SignatureType enum value
   */
  @IsNotEmpty({ message: "Signature type is required" })
  @IsEnum(SignatureType, {
    message: `Signature type must be one of: ${Object.values(SignatureType).join(", ")}`,
  })
  signatureType!: SignatureType;

  /**
   * Format of the key to generate
   * Must be a valid KeyType enum value
   */
  @IsNotEmpty({ message: "Key type is required" })
  @IsEnum(KeyType, {
    message: `Key type must be one of: ${Object.values(KeyType).join(", ")}`,
  })
  keyType!: KeyType;
}

/**
 * Export validation constants for use in tests and documentation
 */
export const VALIDATION_CONSTANTS = {
  MAX_STRING_LENGTH,
  MAX_SECRET_LENGTH,
  MAX_IDENTIFIER_LENGTH,
  MAX_SECRETS_ARRAY_SIZE,
  MIN_SECRETS_ARRAY_SIZE,
} as const;
