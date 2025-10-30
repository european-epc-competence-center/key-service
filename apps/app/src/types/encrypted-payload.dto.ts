import {
  IsString,
  IsNotEmpty,
  MaxLength,
  MinLength,
} from "class-validator";

/**
 * Maximum length for encrypted payloads
 * Base64-encoded encrypted data can be larger than original data
 */
const MAX_ENCRYPTED_PAYLOAD_LENGTH = 100000; // 100KB

/**
 * DTO for encrypted payload requests
 * Used when sending encrypted data to the service
 */
export class EncryptedPayloadDto {
  /**
   * Base64-encoded encrypted payload
   * Format: base64(iv:authTag:ciphertext)
   */
  @IsNotEmpty({ message: "Encrypted data is required" })
  @IsString({ message: "Encrypted data must be a string" })
  @MinLength(1, { message: "Encrypted data cannot be empty" })
  @MaxLength(MAX_ENCRYPTED_PAYLOAD_LENGTH, {
    message: `Encrypted data must not exceed ${MAX_ENCRYPTED_PAYLOAD_LENGTH} characters`,
  })
  encryptedData!: string;
}

/**
 * Export validation constants
 */
export const ENCRYPTED_PAYLOAD_VALIDATION = {
  MAX_ENCRYPTED_PAYLOAD_LENGTH,
} as const;

