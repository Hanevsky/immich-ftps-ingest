#!/usr/bin/env bash
# Create a .env ready for docker compose / Portainer after certs exist.
# Usage:
#   ./scripts/generate-ftps-cert.sh 192.168.1.10
#   ./scripts/make-env.sh 192.168.1.10
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <server-ip> [ftp-user:pass] [immich-api-key]" >&2
  exit 2
fi

SERVER_IP=$1
FTP_USERS=${2:-camera_a7c2:CHANGE_ME_TO_16_PLUS_RANDOM_CHARS}
IMMICH_API_KEY=${3:-CHANGE_ME_IMMICH_API_KEY}

if [ ! -f certs/server.crt ] || [ ! -f certs/server.key ]; then
  echo "Missing certs/server.crt or certs/server.key — run generate-ftps-cert.sh first." >&2
  exit 1
fi

{
  printf 'FTP_USERS=%s\n' "$FTP_USERS"
  printf 'FTP_MASQUERADE_ADDRESS=%s\n' "$SERVER_IP"
  printf 'IMMICH_API_KEY=%s\n' "$IMMICH_API_KEY"
  printf 'FTP_CERT_PEM="'
  # Escape for dotenv double-quoted multiline is awkward; use literal newlines via $''
  # Compose/Portainer prefer raw PEM in the UI. For CLI .env we embed with quotes.
  awk '{gsub(/"/,"\\\""); printf "%s\\n", $0}' certs/server.crt
  printf '"\n'
  printf 'FTP_KEY_PEM="'
  awk '{gsub(/"/,"\\\""); printf "%s\\n", $0}' certs/server.key
  printf '"\n'
} > .env

echo "Wrote .env — edit FTP_USERS and IMMICH_API_KEY if placeholders remain."
echo "Import certs/cacert.pem into the camera, then: docker compose up -d"
