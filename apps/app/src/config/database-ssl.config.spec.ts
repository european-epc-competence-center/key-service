import * as fs from "fs";
import * as path from "path";
import {
  buildDatabaseSslConfig,
  describeDatabaseSslConfig,
} from "./database-ssl.config";
import { ConfigurationException } from "../types/custom-exceptions";

jest.mock("fs");
jest.mock("../utils/log/logger", () => ({
  logInfo: jest.fn(),
  logWarn: jest.fn(),
}));

describe("buildDatabaseSslConfig", () => {
  const caPath = "/run/secrets/db-tls/ca.crt";
  const certPath = "/run/secrets/db-tls/client.crt";
  const keyPath = "/run/secrets/db-tls/client.key";
  const pemContent = Buffer.from("-----BEGIN CERTIFICATE-----\ntest\n");

  beforeEach(() => {
    jest.clearAllMocks();
    (fs.readFileSync as jest.Mock).mockReturnValue(pemContent);
  });

  it("returns false when DB_SSL is not true", () => {
    expect(buildDatabaseSslConfig({})).toBe(false);
    expect(buildDatabaseSslConfig({ DB_SSL: "false" })).toBe(false);
  });

  it("returns false when DB_SSL_MODE is disable", () => {
    expect(
      buildDatabaseSslConfig({ DB_SSL: "true", DB_SSL_MODE: "disable" })
    ).toBe(false);
  });

  it("throws for invalid DB_SSL_MODE", () => {
    expect(() =>
      buildDatabaseSslConfig({ DB_SSL: "true", DB_SSL_MODE: "invalid" })
    ).toThrow(ConfigurationException);
  });

  it("builds require mode without CA", () => {
    const config = buildDatabaseSslConfig({
      DB_SSL: "true",
      DB_SSL_MODE: "require",
    });

    expect(config).toEqual({ rejectUnauthorized: false });
    expect(fs.readFileSync).not.toHaveBeenCalled();
  });

  it("allows rejectUnauthorized=false in development for require mode", () => {
    const config = buildDatabaseSslConfig({
      DB_SSL: "true",
      DB_SSL_MODE: "require",
      DB_SSL_REJECT_UNAUTHORIZED: "false",
      NODE_ENV: "development",
    });

    expect(config).toEqual({ rejectUnauthorized: false });
  });

  it("rejects rejectUnauthorized=false in production", () => {
    expect(() =>
      buildDatabaseSslConfig({
        DB_SSL: "true",
        DB_SSL_MODE: "require",
        DB_SSL_REJECT_UNAUTHORIZED: "false",
        NODE_ENV: "production",
      })
    ).toThrow(ConfigurationException);
  });

  it("rejects require mode in production", () => {
    expect(() =>
      buildDatabaseSslConfig({
        DB_SSL: "true",
        DB_SSL_MODE: "require",
        NODE_ENV: "production",
      })
    ).toThrow(ConfigurationException);
  });

  it("requires DB_SSL_CA for verify-full", () => {
    expect(() =>
      buildDatabaseSslConfig({
        DB_SSL: "true",
        DB_SSL_MODE: "verify-full",
      })
    ).toThrow(ConfigurationException);
  });

  it("builds verify-full with CA and forced rejectUnauthorized", () => {
    const config = buildDatabaseSslConfig({
      DB_SSL: "true",
      DB_SSL_MODE: "verify-full",
      DB_SSL_CA: caPath,
    });

    expect(config).toEqual({
      rejectUnauthorized: true,
      ca: pemContent,
    });
    expect(fs.readFileSync).toHaveBeenCalledWith(path.resolve(caPath));
  });

  it("defaults to verify-full when DB_SSL_MODE is unset", () => {
    expect(() => buildDatabaseSslConfig({ DB_SSL: "true" })).toThrow(
      ConfigurationException
    );
  });

  it("builds verify-ca with hostname check disabled", () => {
    const config = buildDatabaseSslConfig({
      DB_SSL: "true",
      DB_SSL_MODE: "verify-ca",
      DB_SSL_CA: caPath,
    });

    expect(config).toMatchObject({
      rejectUnauthorized: true,
      ca: pemContent,
    });
    expect(typeof (config as { checkServerIdentity?: unknown }).checkServerIdentity).toBe(
      "function"
    );
    expect(
      (config as { checkServerIdentity: () => undefined }).checkServerIdentity()
    ).toBeUndefined();
  });

  it("builds mTLS config when client cert and key are provided", () => {
    const config = buildDatabaseSslConfig({
      DB_SSL: "true",
      DB_SSL_MODE: "verify-full",
      DB_SSL_CA: caPath,
      DB_SSL_CERT: certPath,
      DB_SSL_KEY: keyPath,
    });

    expect(config).toEqual({
      rejectUnauthorized: true,
      ca: pemContent,
      cert: pemContent,
      key: pemContent,
    });
    expect(fs.readFileSync).toHaveBeenCalledTimes(3);
  });

  it("requires both client cert and key for mTLS", () => {
    expect(() =>
      buildDatabaseSslConfig({
        DB_SSL: "true",
        DB_SSL_MODE: "verify-full",
        DB_SSL_CA: caPath,
        DB_SSL_CERT: certPath,
      })
    ).toThrow(ConfigurationException);

    expect(() =>
      buildDatabaseSslConfig({
        DB_SSL: "true",
        DB_SSL_MODE: "verify-full",
        DB_SSL_CA: caPath,
        DB_SSL_KEY: keyPath,
      })
    ).toThrow(ConfigurationException);
  });

  it("throws when a PEM file is missing", () => {
    (fs.readFileSync as jest.Mock).mockImplementation(() => {
      throw new Error("ENOENT");
    });

    expect(() =>
      buildDatabaseSslConfig({
        DB_SSL: "true",
        DB_SSL_MODE: "verify-full",
        DB_SSL_CA: caPath,
      })
    ).toThrow(ConfigurationException);
  });
});

describe("describeDatabaseSslConfig", () => {
  it("reports disabled TLS by default", () => {
    expect(describeDatabaseSslConfig({})).toEqual({
      enabled: false,
      mode: "disable",
      mtls: false,
      rejectUnauthorized: false,
    });
  });

  it("reports mTLS when client credentials are configured", () => {
    expect(
      describeDatabaseSslConfig({
        DB_SSL: "true",
        DB_SSL_MODE: "verify-full",
        DB_SSL_CA: "/ca.crt",
        DB_SSL_CERT: "/client.crt",
        DB_SSL_KEY: "/client.key",
      })
    ).toEqual({
      enabled: true,
      mode: "verify-full",
      mtls: true,
      rejectUnauthorized: true,
    });
  });
});
