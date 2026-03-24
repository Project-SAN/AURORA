#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

resolve_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$ROOT" "$path"
  fi
}

INFO_PATH="$(resolve_path "${1:-config/localnet/policy-info.json}")"
TARGET="${2:-example.com:80}"
REQUEST_PATH="$(resolve_path "${3:-target/localnet/http-request.bin}")"
RESPONSE_PATH="$(resolve_path "${4:-target/localnet/http-response.bin}")"
PROXY_ADDR="${HORNET_PROXY_ADDR:-127.0.0.1:18080}"
HOST="${TARGET%:*}"
PORT="${TARGET##*:}"

if [ ! -f "$INFO_PATH" ]; then
  echo "policy info not found: $INFO_PATH" >&2
  exit 1
fi

mkdir -p "$(dirname "$REQUEST_PATH")"
mkdir -p "$(dirname "$RESPONSE_PATH")"

if [ ! -f "$REQUEST_PATH" ]; then
  local_target="$HOST"
  if [ "$PORT" != "80" ]; then
    local_target="${HOST}:${PORT}"
  fi
  printf 'GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
    "$local_target" \
    "$local_target" >"$REQUEST_PATH"
fi

if ! lsof -nP -iTCP:"${PROXY_ADDR##*:}" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "proxy is not listening on $PROXY_ADDR" >&2
  exit 1
fi

nc "${PROXY_ADDR%:*}" "${PROXY_ADDR##*:}" <"$REQUEST_PATH" >"$RESPONSE_PATH"
echo "response saved to $RESPONSE_PATH"
echo "target was $TARGET via proxy $PROXY_ADDR"
