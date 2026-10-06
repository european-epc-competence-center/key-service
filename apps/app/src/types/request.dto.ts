import {
  IsString,
  IsNotEmpty,
  IsArray,
  ArrayMinSize,
  ArrayMaxSize,
  IsEnum,
  ValidateNested,
  IsObject,
  IsOptional,
  MaxLength,
  MinLength,
  Matches,
  IsBase64,
} from "class-validator";
import { Type, Transform } from "class-transformer";
import {
  DateTime,
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
const MAX_RAW_DATA_LENGTH = 10000; // Max length for base64-encoded raw signing input
const MIN_PASSPHRASE_LENGTH = 12;
const MAX_PASSPHRASE_LENGTH = 1000;
const MAX_EXPORTED_KEY_LENGTH = 65536;

/** Lookup ids may include a DID fragment (`#`) because generated keys are stored that way. */
export const IDENTIFIER_PATTERN = /^[a-zA-Z0-9_\-:.#]+$/;

/** Compact JWE: five base64url segments (RFC 7516). */
export const COMPACT_JWE_PATTERN =
  /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){4}$/;

export class SecretsRequestDto {
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
}

export class KeyRequestDto extends SecretsRequestDto {
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
  @Matches(IDENTIFIER_PATTERN, {
    message:
      "Identifier must contain only alphanumeric characters, hyphens, underscores, colons, periods, and hash marks",
  })
  identifier!: string;
}

/**
 * DTO for signing operations
 * Implements comprehensive input validation to prevent injection attacks and buffer overflows
 */
export class SignRequestDto extends KeyRequestDto {
  /**
   * The verifiable credential or presentation to be signed.
   * Required for `POST /sign/vc` and `POST /sign/vp` (enforced in the service).
   * Optional for `POST /sign/pop`: JWT PoP (F.1) ignores it; Data Integrity PoP (F.2 `di_vp`) ignores it (service builds the VP shell; `domain` required).
   */
  @IsOptional()
  @IsObject({ message: "Verifiable credential/presentation must be an object" })
  @ValidateNested()
  @Type(() => Object)
  verifiable?: VerifiableCredential | VerifiablePresentation;

  /**
   * Verification-method ID to publish in the signature when it differs from `identifier` — for
   * example, when the same public key is published in paired `did:web` and `did:webvh` DID
   * documents. `identifier` still locates the stored key; this only replaces the published
   * `proof.verificationMethod` / JWT `kid` and the controller derived from it.
   */
  @IsOptional()
  @IsNotEmpty({ message: "Public identifier cannot be empty" })
  @IsString({ message: "Public identifier must be a string" })
  @MaxLength(MAX_IDENTIFIER_LENGTH, {
    message: `Public identifier must not exceed ${MAX_IDENTIFIER_LENGTH} characters`,
  })
  publicIdentifier?: string;

  /**
   * Challenge / nonce (e.g. VP proof, OpenID4VCI `c_nonce` → JWT `nonce` on PoP).
   * Also accepts property name `nonce`.
   */
  @IsOptional()
  @Transform(({ value, obj }) => value ?? obj.nonce)
  @IsString({ message: "Challenge must be a string" })
  @MaxLength(MAX_STRING_LENGTH, {
    message: `Challenge must not exceed ${MAX_STRING_LENGTH} characters`,
  })
  challenge?: string;

  /**
   * Domain / audience (VP Data Integrity proof `domain`; OpenID4VCI Credential Issuer Identifier on PoP — F.1 JWT `aud`, F.2 `di_vp` proof `domain`).
   * Also accepts property name `audience`.
   */
  @IsOptional()
  @Transform(({ value, obj }) => value ?? obj.audience)
  @IsString({ message: "Domain must be a string" })
  @MaxLength(MAX_STRING_LENGTH, {
    message: `Domain must not exceed ${MAX_STRING_LENGTH} characters`,
  })
  domain?: string;

  /**
   * Expiry of the proof signature (VP and proof-of-possession).
   * JWT: converted to an `exp` claim.
   * Data Integrity: overwrites `validUntil` on the presentation object.
   */
  @IsOptional()
  @IsString({ message: "validUntil must be an ISO 8601 date-time string" })
  @Matches(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/,
    {
      message:
        "validUntil must be a valid ISO 8601 date-time string (e.g. 2026-12-31T23:59:59Z)",
    },
  )
  validUntil?: DateTime;
}

/**
 * DTO for raw-byte signing operations (`POST /sign/raw`).
 *
 * Signs arbitrary bytes with any stored key, using the key's native algorithm; no multibase/proofValue
 * encoding. Any key type and input length are accepted.
 */
export class RawSignRequestDto extends KeyRequestDto {
  /**
   * The raw bytes to sign, standard base64 (e.g. Java `java.util.Base64`); any non-empty byte string.
   */
  @IsNotEmpty({ message: "Data is required" })
  @IsString({ message: "Data must be a string" })
  @IsBase64({}, { message: "Data must be a base64-encoded string" })
  @MaxLength(MAX_RAW_DATA_LENGTH, {
    message: `Data must not exceed ${MAX_RAW_DATA_LENGTH} characters`,
  })
  data!: string;
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
 * DTO for exporting a stored key (`POST /export`).
 * `secrets` unlock the stored key. `passphrase` encrypts the returned JWE
 * and is the only secret protecting that export.
 */
export class ExportKeyRequestDto extends KeyRequestDto {
  @IsNotEmpty({ message: "Passphrase is required" })
  @IsString({ message: "Passphrase must be a string" })
  @MinLength(MIN_PASSPHRASE_LENGTH, {
    message: `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`,
  })
  @MaxLength(MAX_PASSPHRASE_LENGTH, {
    message: `Passphrase must not exceed ${MAX_PASSPHRASE_LENGTH} characters`,
  })
  passphrase!: string;
}

/**
 * DTO for importing a passphrase-encrypted key (`POST /import`).
 * `passphrase` decrypts the JWE. `secrets` encrypt the key in storage.
 */
export class ImportKeyRequestDto extends SecretsRequestDto {
  @IsNotEmpty({ message: "Passphrase is required" })
  @IsString({ message: "Passphrase must be a string" })
  @MinLength(MIN_PASSPHRASE_LENGTH, {
    message: `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`,
  })
  @MaxLength(MAX_PASSPHRASE_LENGTH, {
    message: `Passphrase must not exceed ${MAX_PASSPHRASE_LENGTH} characters`,
  })
  passphrase!: string;

  @IsNotEmpty({ message: "Exported key is required" })
  @IsString({ message: "Exported key must be a string" })
  @Matches(COMPACT_JWE_PATTERN, {
    message: "Exported key must be a compact JWE",
  })
  @MaxLength(MAX_EXPORTED_KEY_LENGTH, {
    message: `Exported key must not exceed ${MAX_EXPORTED_KEY_LENGTH} characters`,
  })
  exportedKey!: string;

  /**
   * Storage id for the imported key. The export already carries the id that
   * located the key, and import uses that id when this field is omitted.
   * That is the usual case when migrating a DID from one wallet to another:
   * the identifier stays the same and only the storage secrets change.
   * Set this only when this deployment must look the same key up under a different id.
   */
  @IsOptional()
  @IsNotEmpty({ message: "Identifier cannot be empty" })
  @IsString({ message: "Identifier must be a string" })
  @MaxLength(MAX_IDENTIFIER_LENGTH, {
    message: `Identifier must not exceed ${MAX_IDENTIFIER_LENGTH} characters`,
  })
  @Matches(IDENTIFIER_PATTERN, {
    message:
      "Identifier must contain only alphanumeric characters, hyphens, underscores, colons, periods, and hash marks",
  })
  identifier?: string;
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
  MAX_RAW_DATA_LENGTH,
  MIN_PASSPHRASE_LENGTH,
  MAX_PASSPHRASE_LENGTH,
  MAX_EXPORTED_KEY_LENGTH,
} as const;
