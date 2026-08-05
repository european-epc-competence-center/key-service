# JSON-LD Context Cache

Persistent, filesystem-backed cache of JSON-LD `@context` documents used during Data Integrity signing. Bundled contexts are resolved without network access.

## Layout

Each cache directory contains:

- `manifest.json` — map of context URL → relative filename
- `*.jsonld` — context document files

## Default directories

Loaded in order (later entries override earlier ones for the same URL):

1. `<workdir>/contexts` — shipped with the image / repo (`/app/contexts` in Docker)
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
