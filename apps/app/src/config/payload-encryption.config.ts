/**
 * Inter-Service Request Decryption Configuration
 * 
 * Enables automatic decryption of encrypted requests from other services.
 * Uses AES-256-GCM with a shared secret for service-to-service communication.
 * 
 * Environment Variables:
 * - INTER_SERVICE_ENCRYPTION_ENABLED: Enable/disable request decryption (default: false)
 * - INTER_SERVICE_SHARED_SECRET: Shared secret for decryption (exactly 32 characters for AES-256)
 * 
 * Security Notes:
 * - The shared secret MUST be exactly 32 characters (256 bits) for AES-256
 * - Use the same secret on all services that need to communicate
 * - Store the secret securely (Kubernetes secrets, Docker secrets, etc.)
 * - Always use HTTPS/TLS for transport security as well
 */

export interface PayloadEncryptionConfig {
  enabled: boolean;
  secret?: Buffer;
}

/**
 * Get the inter-service shared secret from environment variable
 */
function getInterServiceSharedSecret(): Buffer | undefined {
  const secretString = process.env.INTER_SERVICE_SHARED_SECRET;

  if (!secretString) {
    return undefined;
  }

  // Convert to Buffer and validate length
  const secretBuffer = Buffer.from(secretString, "utf8");
  if (secretBuffer.length !== 32) {
    throw new Error(
      `INTER_SERVICE_SHARED_SECRET must be exactly 32 characters (256 bits). ` +
      `Got ${secretBuffer.length} characters. Generate a 32-character secret.`
    );
  }

  return secretBuffer;
}

export const payloadEncryptionConfig: PayloadEncryptionConfig = {
  enabled: process.env.INTER_SERVICE_ENCRYPTION_ENABLED === "true",
  secret: getInterServiceSharedSecret(),
};

// Validate configuration
if (payloadEncryptionConfig.enabled && !payloadEncryptionConfig.secret) {
  throw new Error(
    "Inter-service encryption is enabled but no shared secret is configured. " +
    "Set INTER_SERVICE_SHARED_SECRET environment variable (32 characters)."
  );
}

