# JSON-LD Context Cache

Persistent, filesystem-backed cache of JSON-LD `@context` documents used during Data Integrity signing. Bundled contexts are resolved without network access.

## Layout

Each cache directory contains:

- `manifest.json` — map of context URL → relative filename
- `*.jsonld` — context document files

Immediate child directories that also contain a `manifest.json` are loaded automatically (e.g. `contexts/gs1/`).

### Bundled packs

| Directory | Source |
|-----------|--------|
| `contexts/` | Core W3C / W3ID contexts |
| `contexts/gs1/` | GS1 VC contexts used by company-wallet GS1 plugin (`license`, `declaration`, `product`, EECC `render-method`, EECC `epcis-credential`) |

## Default directories

Loaded in order (later entries override earlier ones for the same URL):

1. `<workdir>/contexts` — shipped with the image / repo (`/app/contexts` in Docker), including nested packs such as `gs1/`
2. `/contexts` — conventional mount point for deploy-time injection (loaded only if present)

Override with `JSONLD_CONTEXT_DIRS` (colon-separated on Linux):

```bash
JSONLD_CONTEXT_DIRS=/app/contexts:/contexts:/opt/custom-contexts
```

## Injecting extra contexts at deploy time

Mount a directory that contains its own `manifest.json` and context files, for example at `/contexts`:

```json
{
  "https://example.com/contexts/my-vocab/v1": "my-vocab-v1.jsonld"
}
```

Docker:

```bash
docker run -v ./my-contexts:/contexts:ro ...
```

Helm: set `keyService.extraContexts` (ConfigMap or existing ConfigMap) — see `helm/README.md`.
