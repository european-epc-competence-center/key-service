#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="${SCRIPT_DIR}/../docker/signing-key"

if [[ -f "$KEY_FILE" ]]; then
  echo "Signing key already exists at docker/signing-key"
  exit 0
fi

echo "Generating local signing key at docker/signing-key"
openssl rand -base64 64 > "$KEY_FILE"
# 644 so distroless nonroot (uid 65532) can read the bind-mounted file in Docker Compose
chmod 644 "$KEY_FILE"
echo "Done. This file is gitignored — do not commit it."
