#!/bin/sh

set -eu
umask 077

STATE_DIR=/state
DATA_DIR=/data
MANIFEST_FILE="${STATE_DIR}/imported-files.txt"
LOCK_FILE="${STATE_DIR}/import.lock"
BATCH_FILE=/tmp/import-batch.txt
CANDIDATE_FILE=/tmp/import-candidates.txt

log() {
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

fail() {
  log "FATAL: $*"
  exit 2
}

validate_integer() {
  variable_name=$1
  value=$2
  minimum=$3
  maximum=$4

  case "$value" in
    ''|*[!0-9]*) fail "${variable_name} must be an integer" ;;
  esac
  if [ "$value" -lt "$minimum" ] || [ "$value" -gt "$maximum" ]; then
    fail "${variable_name} must be between ${minimum} and ${maximum}"
  fi
}

is_allowed_file() {
  file_path=$1
  file_name=${file_path##*/}

  case "$file_name" in
    ''|.*|-*) return 1 ;;
    *..*|*/*|*\\*) return 1 ;;
  esac
  case "$file_name" in
    *.*) extension=${file_name##*.} ;;
    *) return 1 ;;
  esac

  extension=$(printf '%s' "$extension" | tr '[:upper:]' '[:lower:]')
  case ",${IMPORT_ALLOWED_EXTENSIONS_NORMALIZED}," in
    *,"${extension}",*) return 0 ;;
    *) return 1 ;;
  esac
}

validate_configuration() {
  # Docker secrets: prefer files over environment variables.
  if [ -n "${FTP_USERS_FILE:-}" ]; then
    [ -f "$FTP_USERS_FILE" ] || fail "FTP_USERS_FILE is missing"
    FTP_USERS=$(cat "$FTP_USERS_FILE")
    export FTP_USERS
  fi
  if [ -n "${IMMICH_API_KEY_FILE:-}" ]; then
    [ -f "$IMMICH_API_KEY_FILE" ] || fail "IMMICH_API_KEY_FILE is missing"
    IMMICH_API_KEY=$(cat "$IMMICH_API_KEY_FILE")
    export IMMICH_API_KEY
  fi

  if [ -z "${IMMICH_INSTANCE_URL:-}" ]; then
    [ -n "${IMMICH_HOST:-}" ] || fail "IMMICH_HOST is required"
    host=${IMMICH_HOST%/}
    case "$host" in
      */api) IMMICH_INSTANCE_URL=$host ;;
      *) IMMICH_INSTANCE_URL="${host}/api" ;;
    esac
  fi
  [ -n "${IMMICH_API_KEY:-}" ] || fail "IMMICH_API_KEY is required"

  api_key_marker=$(printf '%s' "$IMMICH_API_KEY" | tr '[:upper:]' '[:lower:]')
  case "$api_key_marker" in
    *change_me*|*change-me*|*changeme*|*replace_me*|*replace-me*)
      fail "IMMICH_API_KEY is still a placeholder"
      ;;
  esac

  # Plain HTTP to Immich is allowed only with an explicit opt-in.
  allow_http=$(printf '%s' "${IMMICH_ALLOW_HTTP:-false}" | tr '[:upper:]' '[:lower:]')
  case "$allow_http" in
    true|false) ;;
    *) fail "IMMICH_ALLOW_HTTP must be true or false" ;;
  esac

  case "${IMMICH_INSTANCE_URL}" in
    https://*/api|https://*/api/) ;;
    http://*/api|http://*/api/)
      [ "$allow_http" = "true" ] \
        || fail "HTTP is disabled; use HTTPS or set IMMICH_ALLOW_HTTP=true"
      log "WARNING: Immich API uses unencrypted HTTP; only use this on a trusted LAN/Docker network"
      ;;
    *)
      fail "IMMICH_HOST must be an http(s) URL ( /api is added automatically )"
      ;;
  esac

  if [ -n "${IMMICH_CA_CERT:-}" ]; then
    case "$IMMICH_CA_CERT" in
      /run/immich-certs/*) ;;
      *) fail "IMMICH_CA_CERT must point inside /run/immich-certs" ;;
    esac
    [ -f "$IMMICH_CA_CERT" ] || fail "IMMICH_CA_CERT does not exist"
    NODE_EXTRA_CA_CERTS=$IMMICH_CA_CERT
    export NODE_EXTRA_CA_CERTS
  elif [ -f /run/immich-certs/ca.crt ]; then
    NODE_EXTRA_CA_CERTS=/run/immich-certs/ca.crt
    export NODE_EXTRA_CA_CERTS
  fi

  IMPORT_INTERVAL_SEC=${IMPORT_INTERVAL_SEC:-60}
  IMPORT_BATCH_SIZE=${IMPORT_BATCH_SIZE:-100}
  IMPORT_CONCURRENCY=${IMPORT_CONCURRENCY:-2}
  validate_integer IMPORT_INTERVAL_SEC "$IMPORT_INTERVAL_SEC" 10 86400
  validate_integer IMPORT_BATCH_SIZE "$IMPORT_BATCH_SIZE" 1 1000
  validate_integer IMPORT_CONCURRENCY "$IMPORT_CONCURRENCY" 1 16

  IMPORT_ALLOWED_EXTENSIONS_NORMALIZED=$(
    printf '%s' "${IMPORT_ALLOWED_EXTENSIONS:-jpg,jpeg,arw,heif,hif,dng,mp4,mov,mts,xmp}" \
      | tr '[:upper:]' '[:lower:]' \
      | tr -d ' '
  )
  [ -n "$IMPORT_ALLOWED_EXTENSIONS_NORMALIZED" ] \
    || fail "IMPORT_ALLOWED_EXTENSIONS must not be empty"

  mkdir -p "$STATE_DIR" "${IMMICH_CONFIG_DIR:-/tmp/immich-config}" "${HOME:-/tmp/home}"
  touch "$MANIFEST_FILE"

  # Defense in depth: never honor deletion flags inherited from an image or host.
  unset IMMICH_DELETE_ASSETS IMMICH_DELETE_DUPLICATES
}

already_imported() {
  grep -F -x -q -- "$1" "$MANIFEST_FILE"
}

collect_batch() {
  : > "$BATCH_FILE"
  LC_ALL=C find "$DATA_DIR" -maxdepth 1 -type f ! -name '.*' -print \
    | LC_ALL=C sort > "$CANDIDATE_FILE"

  count=0
  while IFS= read -r file_path; do
    is_allowed_file "$file_path" || continue
    already_imported "$file_path" && continue
    printf '%s\n' "$file_path" >> "$BATCH_FILE"
    count=$((count + 1))
    [ "$count" -ge "$IMPORT_BATCH_SIZE" ] && break
  done < "$CANDIDATE_FILE"

  printf '%s' "$count"
}

mark_batch_imported() {
  # FTP-created names cannot contain newlines, so one absolute path per line is
  # safe. If this append is interrupted, Immich's hash check makes retries safe.
  while IFS= read -r file_path; do
    printf '%s\n' "$file_path" >> "$MANIFEST_FILE"
  done < "$BATCH_FILE"
  # Persist the append before considering the batch durable.
  sync "$MANIFEST_FILE" 2>/dev/null || sync
}

run_import_cycle() {
  batch_count=$(collect_batch)
  if [ "$batch_count" -eq 0 ]; then
    log "No new completed files to import"
    date +%s > "${STATE_DIR}/last-cycle"
    return 0
  fi

  set -- upload \
    --no-progress \
    --concurrency "$IMPORT_CONCURRENCY" \
    --visibility timeline

  if [ -n "${IMMICH_ALBUM_NAME:-}" ]; then
    set -- "$@" --album-name "$IMMICH_ALBUM_NAME"
  fi

  while IFS= read -r file_path; do
    set -- "$@" "$file_path"
  done < "$BATCH_FILE"

  log "Starting Immich upload batch files=${batch_count}"
  if immich "$@"; then
    mark_batch_imported
    date +%s > "${STATE_DIR}/last-cycle"
    log "Immich upload batch completed files=${batch_count}"
  else
    exit_code=$?
    log "ERROR: Immich upload failed exit_code=${exit_code}; batch will be retried"
    return 0
  fi
}

run_locked_cycle() (
  exec 9> "$LOCK_FILE"
  if ! flock -n 9; then
    log "Another importer cycle holds the lock; skipping"
    exit 0
  fi
  run_import_cycle
)

shutdown() {
  log "Importer stopping"
  exit 0
}

trap shutdown INT TERM

validate_configuration
log "Importer started interval_seconds=${IMPORT_INTERVAL_SEC} batch_size=${IMPORT_BATCH_SIZE}"

interruptible_sleep() {
  sleep_pid=
  sleep "$1" &
  sleep_pid=$!
  trap 'shutdown' INT TERM
  wait "$sleep_pid" 2>/dev/null || true
  sleep_pid=
  trap shutdown INT TERM
}

while :; do
  run_locked_cycle
  interruptible_sleep "$IMPORT_INTERVAL_SEC"
done
