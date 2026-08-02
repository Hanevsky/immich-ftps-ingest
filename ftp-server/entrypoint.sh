#!/bin/sh
# Start FTPS server. Avoid chown/chmod — under Portainer/cap_drop they often fail.
# Prefer dropping to uid 10001 when volumes are writable; otherwise run as root.
set -eu

mkdir -p /tmp /srv/ftp/sony

CERT_DIR=/run/ftp-certs
mkdir -p "$CERT_DIR" 2>/dev/null || true

# If the certs mount is missing/read-only, keep material on tmpfs (re-created each start).
if ! touch "$CERT_DIR/.writable" 2>/dev/null; then
  CERT_DIR=/tmp/ftp-certs
  mkdir -p "$CERT_DIR"
fi
rm -f "$CERT_DIR/.writable" 2>/dev/null || true

export FTP_CERT_FILE="${FTP_CERT_FILE:-$CERT_DIR/server.crt}"
export FTP_KEY_FILE="${FTP_KEY_FILE:-$CERT_DIR/server.key}"

if ! touch /srv/ftp/sony/.writable 2>/dev/null; then
  echo "FATAL: /srv/ftp/sony is not writable — mount the sony_staging volume" >&2
  exit 1
fi
rm -f /srv/ftp/sony/.writable

if runuser -u app -g app -- test -w "$CERT_DIR" \
  && runuser -u app -g app -- test -w /srv/ftp/sony; then
  exec runuser -u app -g app -- python /app/server.py
fi

echo "WARNING: running FTPS server as root (volume not writable by uid 10001)" >&2
exec python /app/server.py
