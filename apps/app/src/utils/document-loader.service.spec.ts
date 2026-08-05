import { DocumentLoaderService } from "./document-loader.service";
import { JsonLdContextCache } from "./jsonld-context-cache";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

describe("DocumentLoaderService", () => {
  let tempDir: string;
  const originalFetch = global.fetch;

  beforeEach(() => {
    JsonLdContextCache.reset();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "doc-loader-"));
    fs.writeFileSync(
      path.join(tempDir, "manifest.json"),
      JSON.stringify({
        "https://example.com/static-context": "static.jsonld",
      })
    );
    fs.writeFileSync(
      path.join(tempDir, "static.jsonld"),
      JSON.stringify({ "@context": { static: "https://example.com#" } })
    );
    JsonLdContextCache.load([tempDir]);
  });

  afterEach(() => {
    JsonLdContextCache.reset();
    fs.rmSync(tempDir, { recursive: true, force: true });
    global.fetch = originalFetch;
  });

  it("resolves persistent contexts without fetching", async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;

    const loader = await DocumentLoaderService.getDocumentLoader();
    const result = await loader("https://example.com/static-context");

    expect(result.document).toEqual({
      "@context": { static: "https://example.com#" },
    });
    expect(result.tag).toBe("static");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fetches unknown contexts when not in the persistent cache", async () => {
    const remoteDoc = { "@context": { remote: "https://remote.example#" } };
    global.fetch = jest.fn().mockResolvedValue({
      json: async () => remoteDoc,
    }) as unknown as typeof fetch;

    const loader = await DocumentLoaderService.getDocumentLoader();
    const result = await loader("https://remote.example/ctx");

    expect(result.document).toEqual(remoteDoc);
    expect(global.fetch).toHaveBeenCalledWith("https://remote.example/ctx");
  });
});
