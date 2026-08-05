import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  JsonLdContextCache,
  resolveContextCacheDirs,
  DEFAULT_INJECT_CONTEXT_DIR,
} from "./jsonld-context-cache";

describe("resolveContextCacheDirs", () => {
  it("uses JSONLD_CONTEXT_DIRS when set", () => {
    const dirs = resolveContextCacheDirs(
      "/app",
      `/a${path.delimiter}/b`,
      DEFAULT_INJECT_CONTEXT_DIR,
      () => false
    );
    expect(dirs).toEqual(["/a", "/b"]);
  });

  it("defaults to cwd/contexts and optional inject dir when present", () => {
    const dirs = resolveContextCacheDirs(
      "/app",
      undefined,
      "/contexts",
      (p) => p === "/contexts"
    );
    expect(dirs).toEqual([path.resolve("/app", "contexts"), "/contexts"]);
  });

  it("omits inject dir when it does not exist", () => {
    const dirs = resolveContextCacheDirs(
      "/app",
      undefined,
      "/contexts",
      () => false
    );
    expect(dirs).toEqual([path.resolve("/app", "contexts")]);
  });
});

describe("JsonLdContextCache", () => {
  let tempRoot: string;

  beforeEach(() => {
    JsonLdContextCache.reset();
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ctx-cache-"));
  });

  afterEach(() => {
    JsonLdContextCache.reset();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  function writeCacheDir(
    name: string,
    manifest: Record<string, string>,
    files: Record<string, unknown>
  ): string {
    const dir = path.join(tempRoot, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "manifest.json"),
      JSON.stringify(manifest)
    );
    for (const [file, doc] of Object.entries(files)) {
      fs.writeFileSync(path.join(dir, file), JSON.stringify(doc));
    }
    return dir;
  }

  it("loads contexts from a manifest", () => {
    const dir = writeCacheDir(
      "bundled",
      { "https://example.com/ctx/v1": "v1.jsonld" },
      { "v1.jsonld": { "@context": { ex: "https://example.com#" } } }
    );

    JsonLdContextCache.load([dir]);

    expect(JsonLdContextCache.size()).toBe(1);
    expect(JsonLdContextCache.has("https://example.com/ctx/v1")).toBe(true);
    expect(JsonLdContextCache.get("https://example.com/ctx/v1")).toEqual({
      "@context": { ex: "https://example.com#" },
    });
  });

  it("lets later directories override earlier ones", () => {
    const first = writeCacheDir(
      "first",
      { "https://example.com/ctx": "a.jsonld" },
      { "a.jsonld": { from: "first" } }
    );
    const second = writeCacheDir(
      "second",
      { "https://example.com/ctx": "b.jsonld" },
      { "b.jsonld": { from: "second" } }
    );

    JsonLdContextCache.load([first, second]);

    expect(JsonLdContextCache.get("https://example.com/ctx")).toEqual({
      from: "second",
    });
  });

  it("skips missing directories without throwing", () => {
    expect(() =>
      JsonLdContextCache.load([path.join(tempRoot, "missing")])
    ).not.toThrow();
    expect(JsonLdContextCache.size()).toBe(0);
  });

  it("refuses path traversal outside the cache directory", () => {
    const dir = writeCacheDir("safe", {}, {});
    const outside = path.join(tempRoot, "secret.jsonld");
    fs.writeFileSync(outside, JSON.stringify({ leaked: true }));
    fs.writeFileSync(
      path.join(dir, "manifest.json"),
      JSON.stringify({
        "https://example.com/evil": "../secret.jsonld",
      })
    );

    JsonLdContextCache.load([dir]);

    expect(JsonLdContextCache.has("https://example.com/evil")).toBe(false);
  });

  it("loads nested subdirectory manifests (e.g. gs1)", () => {
    const root = path.join(tempRoot, "contexts");
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, "manifest.json"), JSON.stringify({}));

    const gs1 = writeCacheDir(
      "contexts/gs1",
      { "https://ref.gs1.org/gs1/vc/license-context": "license.jsonld" },
      { "license.jsonld": { "@context": { GS1PrefixLicenseCredential: "gs1:x" } } }
    );
    expect(gs1).toBe(path.join(root, "gs1"));

    JsonLdContextCache.load([root]);

    expect(
      JsonLdContextCache.has("https://ref.gs1.org/gs1/vc/license-context")
    ).toBe(true);
  });

  it("loads the repo bundled contexts directory", () => {
    const bundled = path.resolve(process.cwd(), "contexts");
    if (!fs.existsSync(path.join(bundled, "manifest.json"))) {
      return; // skip if cwd is unexpected
    }

    JsonLdContextCache.load([bundled]);

    expect(JsonLdContextCache.size()).toBeGreaterThanOrEqual(14);
    expect(
      JsonLdContextCache.has("https://www.w3.org/ns/credentials/v2")
    ).toBe(true);
    expect(
      JsonLdContextCache.has("https://w3id.org/security/data-integrity/v2")
    ).toBe(true);
    expect(
      JsonLdContextCache.has("https://ref.gs1.org/gs1/vc/license-context")
    ).toBe(true);
    expect(
      JsonLdContextCache.has("https://ref.gs1.org/gs1/vc/declaration-context")
    ).toBe(true);
    expect(
      JsonLdContextCache.has("https://ref.gs1.org/gs1/vc/product-context")
    ).toBe(true);
    expect(
      JsonLdContextCache.has(
        "https://raw.githubusercontent.com/european-epc-competence-center/jsonld-context/refs/heads/main/context/render-method"
      )
    ).toBe(true);
    expect(
      JsonLdContextCache.has(
        "https://raw.githubusercontent.com/european-epc-competence-center/jsonld-context/refs/heads/main/context/epcis/epcis-credential-context.json-ld"
      )
    ).toBe(true);
  });
});
