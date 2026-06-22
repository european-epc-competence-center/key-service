import { mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

import { ConfigurationException } from "../types/custom-exceptions";
import { buildHttpTlsConfig, describeHttpTlsConfig } from "./http-tls.config";

describe("buildHttpTlsConfig", () => {
  let certDir: string;

  beforeEach(() => {
    certDir = mkdtempSync(join(tmpdir(), "key-service-http-tls-"));
    writeFileSync(join(certDir, "server.crt"), "cert");
    writeFileSync(join(certDir, "server.key"), "key");
    writeFileSync(join(certDir, "ca.crt"), "ca");
  });

  it("returns disabled when TLS_ENABLED is not true", () => {
    expect(buildHttpTlsConfig({})).toEqual({ enabled: false, mtls: false });
  });

  it("builds HTTPS options when TLS is enabled", () => {
    const config = buildHttpTlsConfig({
      TLS_ENABLED: "true",
      TLS_CERT: join(certDir, "server.crt"),
      TLS_KEY: join(certDir, "server.key"),
      TLS_CA: join(certDir, "ca.crt"),
    });

    expect(config.enabled).toBe(true);
    expect(config.mtls).toBe(false);
    expect(config.httpsOptions?.requestCert).toBe(false);
  });

  it("requires client certificates when TLS_MTLS is true", () => {
    const config = buildHttpTlsConfig({
      TLS_ENABLED: "true",
      TLS_MTLS: "true",
      TLS_CERT: join(certDir, "server.crt"),
      TLS_KEY: join(certDir, "server.key"),
      TLS_CA: join(certDir, "ca.crt"),
    });

    expect(config.mtls).toBe(true);
    expect(config.httpsOptions?.requestCert).toBe(true);
    expect(config.httpsOptions?.rejectUnauthorized).toBe(false);
  });

  it("throws when PEM paths are missing", () => {
    expect(() =>
      buildHttpTlsConfig({
        TLS_ENABLED: "true",
        TLS_CERT: join(certDir, "server.crt"),
      })
    ).toThrow(ConfigurationException);
  });
});

describe("describeHttpTlsConfig", () => {
  it("describes disabled TLS", () => {
    expect(describeHttpTlsConfig({ enabled: false, mtls: false })).toBe("disabled");
  });

  it("describes mTLS", () => {
    expect(describeHttpTlsConfig({ enabled: true, mtls: true })).toContain("mTLS");
  });
});
