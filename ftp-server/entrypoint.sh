#!/bin/sh
# Prepare writable dirs on named volumes, then drop to app user.
# With compose cap_drop:ALL, CAP_CHOWN is often missing — never fail the stack for that.
set -eu

mkdir -p /run/ftp-certs /srv/ftp/sony /tmp

if chown -R 10001:10001 /run/ftp-certs /srv/ftp/sony 2>/dev/null; then
  chmod 0700 /run/ftp-certs
  chmod 0755 /srv/ftp/sony
else
  # Fallback when CHOWN is dropped: sticky world-writable volume roots.
  chmod 1777 /run/ftp-certs /srv/ftp/sony
fi

exec runuser -u app -g app -- python /app/server.py
