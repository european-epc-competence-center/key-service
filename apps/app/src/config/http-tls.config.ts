import { readFileSync } from "fs";
import * as path from "path";
import type { HttpsOptions } from "@nestjs/common/interfaces/external/https-options.interface";
import { ConfigurationException } from "../types/custom-exceptions";

export interface HttpTlsConfig {
  enabled: boolean;
  mtls: boolean;
  httpsOptions?: HttpsOptions;
}

function readRequiredPem(filePath: string, label: string): Buffer {
  const resolvedPath = path.resolve(filePath);
  try {
    return readFileSync(resolvedPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new ConfigurationException(
      `HTTP TLS is enabled but ${label} at ${resolvedPath} is not readable: ${message}`
    );
  }
}

export function buildHttpTlsConfig(env: NodeJS.ProcessEnv = process.env): HttpTlsConfig {
  if (env.TLS_ENABLED !== "true") {
    return { enabled: false, mtls: false };
  }

  const certPath = env.TLS_CERT;
  const keyPath = env.TLS_KEY;
  const caPath = env.TLS_CA;

  if (!certPath || !keyPath || !caPath) {
    throw new ConfigurationException(
      "HTTP TLS is enabled but TLS_CERT, TLS_KEY, and TLS_CA must all be configured"
    );
  }

  const mtls = env.TLS_MTLS === "true";
  const httpsOptions: HttpsOptions = {
    cert: readRequiredPem(certPath, "server certificate"),
    key: readRequiredPem(keyPath, "server private key"),
    ca: readRequiredPem(caPath, "CA certificate"),
    requestCert: mtls,
    // Allow connections without a client cert at the TLS layer so Kubernetes
    // health probes (which do not present a cert) still succeed. Non-health
    // routes enforce client certificates in main.ts when mTLS is enabled.
    rejectUnauthorized: false,
  };

  return { enabled: true, mtls, httpsOptions };
}

export function describeHttpTlsConfig(config: HttpTlsConfig): string {
  if (!config.enabled) {
    return "disabled";
  }
  return config.mtls ? "mTLS (HTTPS + client certificate required)" : "TLS (HTTPS)";
}
