import * as fs from "fs";
import * as path from "path";
import * as tls from "tls";
import { ConfigurationException } from "../types/custom-exceptions";
import { logInfo, logWarn } from "../utils/log/logger";

export type DatabaseSslMode =
  | "disable"
  | "require"
  | "verify-ca"
  | "verify-full";

const VALID_SSL_MODES: DatabaseSslMode[] = [
  "disable",
  "require",
  "verify-ca",
  "verify-full",
];

export interface DatabaseSslOptions {
  rejectUnauthorized?: boolean;
  ca?: string | Buffer;
  cert?: string | Buffer;
  key?: string | Buffer;
  checkServerIdentity?: (
    hostname: string,
    cert: tls.PeerCertificate
  ) => Error | undefined;
}

export interface DatabaseSslSummary {
  enabled: boolean;
  mode: DatabaseSslMode;
  mtls: boolean;
  rejectUnauthorized: boolean;
}

function readPemFile(filePath: string, envVar: string): Buffer {
  const resolvedPath = path.resolve(filePath);
  try {
    return fs.readFileSync(resolvedPath);
  } catch (err) {
    throw new ConfigurationException(
      `Failed to read ${envVar} from ${resolvedPath}: ${err instanceof Error ? err.message : err}`
    );
  }
}

function parseSslMode(env: NodeJS.ProcessEnv): DatabaseSslMode {
  const mode = (env.DB_SSL_MODE?.toLowerCase() ?? "verify-full") as DatabaseSslMode;
  if (!VALID_SSL_MODES.includes(mode)) {
    throw new ConfigurationException(
      `Invalid DB_SSL_MODE "${env.DB_SSL_MODE}". Expected one of: ${VALID_SSL_MODES.join(", ")}`
    );
  }
  return mode;
}

function assertProductionSslMode(
  env: NodeJS.ProcessEnv,
  mode: DatabaseSslMode
): void {
  if (env.NODE_ENV !== "production") {
    return;
  }
  if (mode === "require") {
    throw new ConfigurationException(
      "DB_SSL_MODE=require is not allowed when NODE_ENV=production — use verify-full with DB_SSL_CA"
    );
  }
}

function resolveRejectUnauthorized(
  env: NodeJS.ProcessEnv,
  mode: DatabaseSslMode
): boolean {
  const isProduction = env.NODE_ENV === "production";
  const explicitReject = env.DB_SSL_REJECT_UNAUTHORIZED;

  if (explicitReject === "false") {
    if (isProduction) {
      throw new ConfigurationException(
        "DB_SSL_REJECT_UNAUTHORIZED=false is not allowed when NODE_ENV=production"
      );
    }
    return false;
  }

  if (mode === "require") {
    return explicitReject === "true";
  }

  return true;
}

function effectiveRejectUnauthorized(
  env: NodeJS.ProcessEnv,
  mode: DatabaseSslMode
): boolean {
  if (mode === "verify-ca" || mode === "verify-full") {
    return true;
  }
  return resolveRejectUnauthorized(env, mode);
}

export function buildDatabaseSslConfig(
  env: NodeJS.ProcessEnv = process.env
): boolean | DatabaseSslOptions {
  if (env.DB_SSL !== "true") {
    return false;
  }

  const mode = parseSslMode(env);
  if (mode === "disable") {
    logWarn(
      "DB_SSL=true but DB_SSL_MODE=disable — database connection will not use TLS"
    );
    return false;
  }

  assertProductionSslMode(env, mode);

  const rejectUnauthorized = resolveRejectUnauthorized(env, mode);
  const sslConfig: DatabaseSslOptions = { rejectUnauthorized };

  if (mode === "verify-ca" || mode === "verify-full") {
    if (!env.DB_SSL_CA) {
      throw new ConfigurationException(
        `DB_SSL_CA is required when DB_SSL_MODE=${mode}`
      );
    }
    sslConfig.ca = readPemFile(env.DB_SSL_CA, "DB_SSL_CA");
    sslConfig.rejectUnauthorized = true;

    if (mode === "verify-ca") {
      sslConfig.checkServerIdentity = (_hostname, _cert) => undefined;
    }
  }

  const hasClientCert = Boolean(env.DB_SSL_CERT);
  const hasClientKey = Boolean(env.DB_SSL_KEY);

  if (hasClientCert || hasClientKey) {
    if (!hasClientCert || !hasClientKey) {
      throw new ConfigurationException(
        "DB_SSL_CERT and DB_SSL_KEY must both be set for mTLS client authentication"
      );
    }
    sslConfig.cert = readPemFile(env.DB_SSL_CERT!, "DB_SSL_CERT");
    sslConfig.key = readPemFile(env.DB_SSL_KEY!, "DB_SSL_KEY");
  }

  return sslConfig;
}

export function describeDatabaseSslConfig(
  env: NodeJS.ProcessEnv = process.env
): DatabaseSslSummary {
  if (env.DB_SSL !== "true") {
    return {
      enabled: false,
      mode: "disable",
      mtls: false,
      rejectUnauthorized: false,
    };
  }

  const mode = parseSslMode(env);
  if (mode === "disable") {
    return {
      enabled: false,
      mode,
      mtls: false,
      rejectUnauthorized: false,
    };
  }

  return {
    enabled: true,
    mode,
    mtls: Boolean(env.DB_SSL_CERT && env.DB_SSL_KEY),
    rejectUnauthorized: effectiveRejectUnauthorized(env, mode),
  };
}

export function logDatabaseSslConfig(env: NodeJS.ProcessEnv = process.env): void {
  const summary = describeDatabaseSslConfig(env);
  if (!summary.enabled) {
    return;
  }

  logInfo(
    `Database TLS enabled (mode=${summary.mode}, mTLS=${summary.mtls}, rejectUnauthorized=${summary.rejectUnauthorized})`
  );
}
