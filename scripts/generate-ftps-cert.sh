#!/usr/bin/env bash
# Cross-platform FTPS CA + server certificate generator (OpenSSL).
# Usage:
#   ./scripts/generate-ftps-cert.sh 203.0.113.10
#   ./scripts/generate-ftps-cert.sh 203.0.113.10 ftp.example.com
# Output: ./certs/{server.crt,server.key,cacert.pem,ca.key}
# Keep ca.key offline; import cacert.pem into the camera.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <server-ip> [dns-name...]" >&2
  exit 2
fi

SERVER_IP=$1
shift
DNS_NAMES=("$@")
CERT_DIR=certs
DAYS=825

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

if [ -e server.crt ] || [ -e server.key ] || [ -e ca.key ]; then
  echo "Refusing to overwrite existing certs; remove them or rotate deliberately." >&2
  exit 1
fi

SAN="IP:${SERVER_IP}"
CN=$SERVER_IP
for dns in "${DNS_NAMES[@]+"${DNS_NAMES[@]}"}"; do
  SAN="${SAN},DNS:${dns}"
  if [ "$CN" = "$SERVER_IP" ]; then
    CN=$dns
  fi
done

cat > .ca-openssl.cnf <<EOF
[req]
prompt = no
distinguished_name = ca_dn
x509_extensions = v3_ca

[ca_dn]
CN = Sony FTP Local Root CA

[v3_ca]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat > .server-openssl.cnf <<EOF
[req]
prompt = no
distinguished_name = server_dn

[server_dn]
CN = ${CN}

[v3_server]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${SAN}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
  -keyout ca.key -out cacert.pem -config .ca-openssl.cnf

openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -keyout server.key -out server.csr -config .server-openssl.cnf

openssl x509 -req -in server.csr -CA cacert.pem -CAkey ca.key -CAcreateserial \
  -out server.leaf.crt -days "$DAYS" -sha256 \
  -extfile .server-openssl.cnf -extensions v3_server

cat server.leaf.crt cacert.pem > server.crt
openssl verify -CAfile cacert.pem server.leaf.crt

rm -f server.csr server.leaf.crt cacert.srl .ca-openssl.cnf .server-openssl.cnf

echo "Done: $CERT_DIR/{server.crt,server.key,cacert.pem,ca.key}"
echo "SAN=${SAN}"
echo "Import cacert.pem into the camera; keep ca.key private."
