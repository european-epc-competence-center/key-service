import { CorsOptions } from "@nestjs/common/interfaces/external/cors-options.interface";

/**
 * CORS Configuration
 * 
 * Environment Variables:
 * - CORS_ENABLED: Enable/disable CORS (default: true)
 * - CORS_ORIGINS: Comma-separated list of allowed origins (default: all origins if not set)
 * - CORS_METHODS: Comma-separated list of allowed methods (default: GET,HEAD,PUT,PATCH,POST,DELETE)
 * - CORS_CREDENTIALS: Allow credentials (default: false)
 * - CORS_MAX_AGE: Preflight cache duration in seconds (default: 86400)
 */

export interface CorsConfig {
  enabled: boolean;
  options?: CorsOptions;
}

export const corsConfig: CorsConfig = {
  enabled: process.env.CORS_ENABLED === "true", // Default disabled because of service to service communication
  options: process.env.CORS_ORIGINS ? {
    origin: process.env.CORS_ORIGINS.split(",").map(origin => origin.trim()),
    methods: process.env.CORS_METHODS?.split(",").map(method => method.trim()) || [
      "GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"
    ],
    credentials: process.env.CORS_CREDENTIALS === "true",
    maxAge: process.env.CORS_MAX_AGE ? parseInt(process.env.CORS_MAX_AGE) : 86400,
  } : undefined, // If no origins specified, use default NestJS CORS (allows all origins)
};
