export interface FailedAttemptsCacheConfig {
  cooldownPeriodSeconds: number;
  maxFailedAttempts: number;
}

export const failedAttemptsCacheConfig: FailedAttemptsCacheConfig = {
  // Cooldown period in milliseconds (default: 15 minutes)
  cooldownPeriodSeconds: parseInt(
    process.env.FAILED_ATTEMPTS_COOLDOWN_PERIOD_SECONDS || "900"
  ),

  // Maximum failed decryption attempts within cooldown period (default: 3)
  maxFailedAttempts: parseInt(
    process.env.FAILED_ATTEMPTS_MAX_FAILED_ATTEMPTS || "3"
  ),
};
