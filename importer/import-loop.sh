#!/bin/sh

set -eu
umask 077

# read_only rootfs: keep writable paths on tmpfs (/tmp) or named volumes.
HOME=/tmp/home
IMMICH_CONFIG_DIR=/tmp/immich-config
export HOME IMMICH_CONFIG_DIR

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
  # Must be exported: Immich CLI reads IMMICH_INSTANCE_URL from the process env
  # (or --url). Without it, upload falls back to auth.yml and fails with
  # "No auth file exists. Please login first."
  export IMMICH_INSTANCE_URL
  [ -n "${IMMICH_API_KEY:-}" ] || fail "IMMICH_API_KEY is required"
  export IMMICH_API_KEY

  api_key_marker=$(printf '%s' "$IMMICH_API_KEY" | tr '[:upper:]' '[:lower:]')
  case "$api_key_marker" in
    *change_me*|*change-me*|*changeme*|*replace_me*|*replace-me*)
      fail "IMMICH_API_KEY is still a placeholder"
      ;;
  esac

  # Default true: Immich on the Docker network is usually plain HTTP.
  allow_http=$(printf '%s' "${IMMICH_ALLOW_HTTP:-true}" | tr '[:upper:]' '[:lower:]')
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

  mkdir -p /run/immich-certs
  if [ -n "${IMMICH_CA_CERT_PEM:-}" ]; then
    # Support dotenv-style escaped newlines from .env files.
    printf '%s\n' "$IMMICH_CA_CERT_PEM" | sed 's/\\n/\n/g' > /run/immich-certs/ca.crt
    NODE_EXTRA_CA_CERTS=/run/immich-certs/ca.crt
    export NODE_EXTRA_CA_CERTS
  elif [ -f /run/immich-certs/ca.crt ]; then
    NODE_EXTRA_CA_CERTS=/run/immich-certs/ca.crt
    export NODE_EXTRA_CA_CERTS
  fi

  # Tuned for camera bursts on a Docker LAN: short poll, larger batches, more
  # parallel uploads. Override via env if Immich or the host is saturated.
  IMPORT_INTERVAL_SEC=${IMPORT_INTERVAL_SEC:-15}
  IMPORT_BATCH_SIZE=${IMPORT_BATCH_SIZE:-200}
  IMPORT_CONCURRENCY=${IMPORT_CONCURRENCY:-8}
  validate_integer IMPORT_INTERVAL_SEC "$IMPORT_INTERVAL_SEC" 5 86400
  validate_integer IMPORT_BATCH_SIZE "$IMPORT_BATCH_SIZE" 1 2000
  validate_integer IMPORT_CONCURRENCY "$IMPORT_CONCURRENCY" 1 32

  skip_hash=$(printf '%s' "${IMPORT_SKIP_HASH:-true}" | tr '[:upper:]' '[:lower:]')
  case "$skip_hash" in
    true|false) IMPORT_SKIP_HASH=$skip_hash ;;
    *) fail "IMPORT_SKIP_HASH must be true or false" ;;
  esac

  delete_after=$(printf '%s' "${IMPORT_DELETE_AFTER_UPLOAD:-true}" | tr '[:upper:]' '[:lower:]')
  case "$delete_after" in
    true|false) IMPORT_DELETE_AFTER_UPLOAD=$delete_after ;;
    *) fail "IMPORT_DELETE_AFTER_UPLOAD must be true or false" ;;
  esac

  IMPORT_ALLOWED_EXTENSIONS_NORMALIZED=$(
    printf '%s' "${IMPORT_ALLOWED_EXTENSIONS:-jpg,jpeg,arw,heif,hif,dng,mp4,mov,mts,xmp}" \
      | tr '[:upper:]' '[:lower:]' \
      | tr -d ' '
  )
  [ -n "$IMPORT_ALLOWED_EXTENSIONS_NORMALIZED" ] \
    || fail "IMPORT_ALLOWED_EXTENSIONS must not be empty"

  mkdir -p "$STATE_DIR" "${IMMICH_CONFIG_DIR:-/tmp/immich-config}" "${HOME:-/tmp/home}"
  touch "$MANIFEST_FILE"

  # Only honor deletion via our explicit CLI flags below — ignore host env noise.
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
    # Manifest is a crash-safety net; after delete-on-success the dir is usually empty.
    already_imported "$file_path" && continue
    printf '%s\n' "$file_path" >> "$BATCH_FILE"
    count=$((count + 1))
    [ "$count" -ge "$IMPORT_BATCH_SIZE" ] && break
  done < "$CANDIDATE_FILE"

  printf '%s' "$count"
}

delete_batch_files() {
  deleted=0
  failed=0
  while IFS= read -r file_path; do
    [ -e "$file_path" ] || continue
    if rm -f -- "$file_path"; then
      deleted=$((deleted + 1))
    else
      failed=$((failed + 1))
      log "WARNING: could not delete staging file path=${file_path}"
    fi
  done < "$BATCH_FILE"
  if [ "$failed" -gt 0 ]; then
    log "WARNING: staging cleanup incomplete deleted=${deleted} failed=${failed}"
  elif [ "$deleted" -gt 0 ]; then
    log "Deleted staging files count=${deleted}"
  fi
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

# Exit codes for the outer drain loop:
#   0 — idle, partial batch, or error → sleep before next poll
#   1 — full batch uploaded → immediately process the next batch
run_import_cycle() {
  batch_count=$(collect_batch)
  if [ "$batch_count" -eq 0 ]; then
    log "No new completed files to import"
    date +%s > "${STATE_DIR}/last-cycle"
    return 0
  fi

  # Global --url/--key must come before the subcommand so CLI skips auth.yml.
  set -- \
    --url "$IMMICH_INSTANCE_URL" \
    --key "$IMMICH_API_KEY" \
    upload \
    --no-progress \
    --concurrency "$IMPORT_CONCURRENCY" \
    --visibility timeline

  if [ "$IMPORT_SKIP_HASH" = "true" ]; then
    set -- "$@" --skip-hash
  fi

  if [ "$IMPORT_DELETE_AFTER_UPLOAD" = "true" ]; then
    # CLI removes locals after upload / server-side duplicate detection.
    set -- "$@" --delete --delete-duplicates
  fi

  if [ -n "${IMMICH_ALBUM_NAME:-}" ]; then
    set -- "$@" --album-name "$IMMICH_ALBUM_NAME"
  fi

  while IFS= read -r file_path; do
    set -- "$@" "$file_path"
  done < "$BATCH_FILE"

  log "Starting Immich upload batch files=${batch_count} concurrency=${IMPORT_CONCURRENCY} skip_hash=${IMPORT_SKIP_HASH} delete=${IMPORT_DELETE_AFTER_UPLOAD}"
  if immich "$@"; then
    mark_batch_imported
    if [ "$IMPORT_DELETE_AFTER_UPLOAD" = "true" ]; then
      # Belt-and-suspenders: remove anything the CLI left behind (e.g. races).
      delete_batch_files
    fi
    date +%s > "${STATE_DIR}/last-cycle"
    log "Immich upload batch completed files=${batch_count}"
    if [ "$batch_count" -ge "$IMPORT_BATCH_SIZE" ]; then
      return 1
    fi
    return 0
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
  # Drain full batches without sleeping so large camera dumps clear quickly.
  while :; do
    set +e
    run_import_cycle
    cycle_status=$?
    set -e
    [ "$cycle_status" -eq 1 ] || break
  done
)

shutdown() {
  log "Importer stopping"
  exit 0
}

trap shutdown INT TERM

validate_configuration
log "Importer started interval_seconds=${IMPORT_INTERVAL_SEC} batch_size=${IMPORT_BATCH_SIZE} concurrency=${IMPORT_CONCURRENCY} skip_hash=${IMPORT_SKIP_HASH} delete_after_upload=${IMPORT_DELETE_AFTER_UPLOAD}"

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
