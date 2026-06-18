#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../docker/certs/postgres"
VALIDITY_DAYS="${POSTGRES_TLS_DAYS:-825}"
FORCE=false

usage() {
  cat <<EOF
Generate a local PostgreSQL TLS PKI for Docker Compose development.

Output directory: docker/certs/postgres/
  ca.crt, ca.key       Certificate authority
  server.crt, server.key   PostgreSQL server certificate
  client.crt, client.key   key-service client certificate (mTLS)

Options:
  --force   Regenerate even when certificates already exist

Environment:
  POSTGRES_TLS_DAYS        Validity in days (default: 825)
  POSTGRES_TLS_CLIENT_CN   Client certificate CN; must match DB username when using
                           pg_hba clientcert=verify-full (default: postgres)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -f "${CERT_DIR}/server.crt" && -f "${CERT_DIR}/client.crt" && "${FORCE}" != "true" ]]; then
  echo "PostgreSQL TLS certificates already exist at docker/certs/postgres"
  echo "Use --force to regenerate."
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required but was not found in PATH" >&2
  exit 1
fi

mkdir -p "${CERT_DIR}"

SERVER_SANS="DNS:postgres,DNS:localhost,DNS:company-wallet-postgresql,DNS:key-store,DNS:key-service-postgresql"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Generating PostgreSQL TLS certificates in docker/certs/postgres (${VALIDITY_DAYS} days)"

# Certificate authority
openssl genrsa -out "${CERT_DIR}/ca.key" 4096
openssl req -new -x509 -days "${VALIDITY_DAYS}" -key "${CERT_DIR}/ca.key" \
  -out "${CERT_DIR}/ca.crt" \
  -subj "/CN=key-service-postgres-ca"

# Server certificate
openssl genrsa -out "${CERT_DIR}/server.key" 2048
openssl req -new -key "${CERT_DIR}/server.key" \
  -out "${TMP_DIR}/server.csr" \
  -subj "/CN=postgres" \
  -addext "subjectAltName=${SERVER_SANS}"
openssl x509 -req -days "${VALIDITY_DAYS}" \
  -in "${TMP_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/server.crt" \
  -copy_extensions copy

# Client certificate for key-service mTLS (CN must match the DB user for pg_hba clientcert=verify-full)
CLIENT_CN="${POSTGRES_TLS_CLIENT_CN:-postgres}"
openssl genrsa -out "${CERT_DIR}/client.key" 2048
openssl req -new -key "${CERT_DIR}/client.key" \
  -out "${TMP_DIR}/client.csr" \
  -subj "/CN=${CLIENT_CN}"
openssl x509 -req -days "${VALIDITY_DAYS}" \
  -in "${TMP_DIR}/client.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/client.crt"

chmod 600 "${CERT_DIR}/ca.key"
chmod 644 "${CERT_DIR}/ca.crt" "${CERT_DIR}/server.crt" "${CERT_DIR}/client.crt"
# server.key is copied by postgres entrypoint as root; client.key is read by distroless nonroot (uid 65532)
chmod 644 "${CERT_DIR}/server.key" "${CERT_DIR}/client.key"
rm -f "${CERT_DIR}/ca.srl"

echo "Done. Certificates are gitignored — do not commit them."
echo
echo "Docker Compose (full stack):"
echo "  npm run docker:up"
echo
echo "Host dev against Docker postgres:"
echo "  docker compose -f docker/docker-compose.yml up -d postgres"
echo "  export DB_SSL=true DB_SSL_MODE=verify-full"
echo "  export DB_SSL_CA=./docker/certs/postgres/ca.crt"
echo "  export DB_SSL_CERT=./docker/certs/postgres/client.crt"
echo "  export DB_SSL_KEY=./docker/certs/postgres/client.key"
echo "  npm run dev"
echo
echo "Kubernetes client secret example:"
echo "  kubectl create secret generic key-service-db-tls \\"
echo "    --from-file=ca.crt=${CERT_DIR}/ca.crt \\"
echo "    --from-file=client.crt=${CERT_DIR}/client.crt \\"
echo "    --from-file=client.key=${CERT_DIR}/client.key"
