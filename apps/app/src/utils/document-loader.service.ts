// @ts-ignore: No types for 'jsonld-signatures'
import jsonldSignatures from "jsonld-signatures";
import NodeCache from "node-cache";
import { JsonLdContextCache } from "./jsonld-context-cache";

const IPFS_GATEWAYS = [
  "https://ipfs.io",
  "https://gateway.pinata.cloud",
  "https://cloudflare-ipfs.com",
];

/** In-memory TTL cache for contexts fetched over the network (not bundled). */
const runtimeCache = new NodeCache({ stdTTL: 3600 });

export class DocumentLoaderService {
  /**
   * Returns a JSON-LD document loader that resolves contexts in order:
   * 1. Persistent filesystem cache (bundled + injected) — no network
   * 2. In-memory TTL cache of previously fetched documents
   * 3. HTTP / IPFS fetch (then stored in the in-memory cache)
   */
  static async getDocumentLoader() {
    JsonLdContextCache.load();

    const documentLoader = jsonldSignatures.extendContextLoader(
      async (url: string) => {
        const persistent = JsonLdContextCache.get(url);
        if (persistent !== undefined) {
          return {
            contextUrl: null,
            documentUrl: url,
            document: persistent,
            tag: "static",
          };
        }

        let document = runtimeCache.get(url);

        if (!document) {
          console.warn(`Fetching document from ${url}`);
          if (url.startsWith("ipfs://")) {
            await Promise.any(
              IPFS_GATEWAYS.map(async (gateway) => {
                return await (
                  await fetch(`${gateway}/ipfs/${url.split("ipfs://")[1]}`)
                ).json();
              })
            )
              .then((result: any) => {
                document = result;
              })
              .catch((error: unknown) => {
                console.log(error);
              });
          } else {
            const fetchresult = await fetch(url);
            document = await fetchresult.json();
          }
          if (document) {
            runtimeCache.set(url, document);
            console.warn(`Fetched document from ${url}: ${JSON.stringify(document)}`);
          }
        }

        return {
          contextUrl: null,
          documentUrl: url,
          document: document,
        };
      }
    );
    return documentLoader;
  }
}
