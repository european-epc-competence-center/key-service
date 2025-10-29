import { Injectable, OnModuleDestroy } from "@nestjs/common";
import NodeCache from "node-cache";
import { failedAttemptsCacheConfig } from "../config/failed-attempts.config";

@Injectable()
export class FailedAttemptsCacheService implements OnModuleDestroy {
  private readonly cache: NodeCache;

  constructor() {
    // Initialize cache with TTL based on cooldown period
    this.cache = new NodeCache({
      stdTTL: failedAttemptsCacheConfig.cooldownPeriodSeconds,
      checkperiod: 60,
      useClones: false, // For better performance
    });
  }
  onModuleDestroy() {
    this.cache.close();
  }

  /**
   * Check if the identifier is currently blocked due to too many failed attempts
   */
  isBlocked(identifier: string): boolean {
    const record = this.cache.get<number>(identifier);

    return !!record && record >= failedAttemptsCacheConfig.maxFailedAttempts;
  }

  /**
   * Record a failed decryption attempt for the given identifier
   */
  recordFailedAttempt(identifier: string): void {
    const existingRecord = this.cache.get<number>(identifier);

    if (existingRecord) {
      this.cache.set(identifier, existingRecord + 1);
    } else {
      // First failed attempt for this identifier
      this.cache.set(identifier, 1);
    }
  }
}
