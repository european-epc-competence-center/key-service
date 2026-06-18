#!/bin/sh
set -e

# Copy mounted TLS material into a root-owned temp dir with postgres-readable
# permissions. Bind-mounted keys from the host are often mode 600 and owned by
# the developer UID, which the postgres user (uid 70) cannot read.
CERT_SRC="/var/lib/postgresql/certs"
CERT_DST="/tmp/postgres-tls"

SSL_ARGS=""
if [ -f "${CERT_SRC}/server.crt" ]; then
  mkdir -p "${CERT_DST}"
  cp "${CERT_SRC}/ca.crt" "${CERT_SRC}/server.crt" "${CERT_SRC}/server.key" "${CERT_DST}/"
  chown postgres:postgres "${CERT_DST}/"* 2>/dev/null || chown 70:70 "${CERT_DST}/"*
  chmod 644 "${CERT_DST}/ca.crt" "${CERT_DST}/server.crt"
  chmod 600 "${CERT_DST}/server.key"

  SSL_ARGS="-c ssl=on -c ssl_cert_file=${CERT_DST}/server.crt -c ssl_key_file=${CERT_DST}/server.key -c ssl_ca_file=${CERT_DST}/ca.crt -c ssl_min_protocol_version=TLSv1.2 -c hba_file=/etc/postgresql/pg_hba.conf"
fi

# shellcheck disable=SC2086
exec /usr/local/bin/docker-entrypoint.sh postgres ${SSL_ARGS} "$@"
