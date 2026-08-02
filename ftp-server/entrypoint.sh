#!/bin/sh
# Prepare writable FTPS cert dir on the named volume, then drop to app user.
set -eu

mkdir -p /run/ftp-certs /srv/ftp/sony /tmp
chown -R 10001:10001 /run/ftp-certs /srv/ftp/sony
chmod 0700 /run/ftp-certs

# Debian slim provides runuser (util-linux).
exec runuser -u app -g app -- python /app/server.py
