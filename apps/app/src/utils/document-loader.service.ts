// @ts-ignore: No types for 'jsonld-signatures'
import jsonldSignatures from "jsonld-signatures";
import NodeCache from "node-cache";

const IPFS_GATEWAYS = [
  "https://ipfs.io",
  "https://gateway.pinata.cloud",
  "https://cloudflare-ipfs.com",
];

// 1 hour TTL by default
const cache = new NodeCache({ stdTTL: 3600 });

export class DocumentLoaderService {
  static async getDocumentLoader() {
    const documentLoader = jsonldSignatures.extendContextLoader(
      async (url: string) => {
        // check cache
        let document = cache.get(url);

        // fetch if not in cache
        if (!document) {
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
            // console.warn(`Fetched @context from ${url}. Use with care!`);
            document = await fetchresult.json();
          }
          if (document) cache.set(url, document);
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
