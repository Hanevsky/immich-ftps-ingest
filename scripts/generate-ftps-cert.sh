#!/usr/bin/env bash
# Cross-platform FTPS CA + server certificate generator (OpenSSL).
# Usage:
#   ./scripts/generate-ftps-cert.sh 192.168.1.10
# Output: ./certs/{server.crt,server.key,cacert.pem,ca.key}
# Keep ca.key offline; import cacert.pem into the camera.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <server-ip>" >&2
  exit 2
fi

SERVER_IP=$1
CERT_DIR=certs
DAYS=825

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

if [ -e server.crt ] || [ -e server.key ] || [ -e ca.key ]; then
  echo "Refusing to overwrite existing certs; remove them or rotate deliberately." >&2
  exit 1
fi

# CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/CN=Camera FTPS Local CA" -out cacert.pem

# Server key + CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=${SERVER_IP}" -out server.csr

cat > server.ext <<EOF
subjectAltName = IP:${SERVER_IP}
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment
EOF

openssl x509 -req -in server.csr -CA cacert.pem -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -sha256 -extfile server.ext

rm -f server.csr server.ext cacert.srl

echo "Done: $CERT_DIR/{server.crt,server.key,cacert.pem,ca.key}"
echo "Import cacert.pem into the camera; keep ca.key private."
