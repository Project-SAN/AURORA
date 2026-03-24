#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/target/localnet"
ROUTER_BIN="$ROOT/target/debug/aurora_router"
PROXY_BIN="$ROOT/target/debug/aurora_proxy"

mkdir -p "$LOG_DIR"

kill_from_pidfile() {
  local pidfile="$1"
  if [ -f "$pidfile" ]; then
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

kill_listener_on_port() {
  local port="$1"
  local pids
  pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -z "$pids" ]; then
    return 0
  fi
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done <<<"$pids"
}

wait_for_file() {
  local path="$1"
  local timeout="${2:-30}"
  local i
  for ((i = 0; i < timeout; i++)); do
    if [ -f "$path" ] && [ -s "$path" ]; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for file: $path" >&2
  return 1
}

wait_for_port() {
  local port="$1"
  local timeout="${2:-30}"
  local i
  for ((i = 0; i < timeout; i++)); do
    if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for 127.0.0.1:$port" >&2
  return 1
}

start_router() {
  local name="$1"
  local env_file="$ROOT/config/localnet/router-${name}.env"
  local log_file="$LOG_DIR/router-${name}.log"
  local pidfile="$LOG_DIR/router-${name}.pid"

  kill_from_pidfile "$pidfile"
  nohup bash -lc "
    cd \"$ROOT\"
    set -a
    source \"$env_file\"
    set +a
    exec \"$ROUTER_BIN\"
  " >"$log_file" 2>&1 &
  echo $! >"$pidfile"
}

start_proxy() {
  local pidfile="$LOG_DIR/proxy.pid"
  kill_from_pidfile "$pidfile"
  nohup bash -lc "
    cd \"$ROOT\"
    exec env \
      HORNET_PROXY_BIND=\"${HORNET_PROXY_BIND:-127.0.0.1:18080}\" \
      HORNET_POLICY_INFO=\"${HORNET_POLICY_INFO:-$ROOT/config/localnet/policy-info.json}\" \
      HORNET_PROXY_ROUTE_ONLY=\"${HORNET_PROXY_ROUTE_ONLY:-0}\" \
      HORNET_PROXY_ZKBOO_ROUNDS=\"${HORNET_PROXY_ZKBOO_ROUNDS:-1}\" \
      HORNET_PROXY_RESPONSE_TIMEOUT_SECS=\"${HORNET_PROXY_RESPONSE_TIMEOUT_SECS:-20}\" \
      \"$PROXY_BIN\"
  " >"$LOG_DIR/proxy.log" 2>&1 &
  echo $! >"$pidfile"
}

kill_from_pidfile "$LOG_DIR/router-entry.pid"
kill_from_pidfile "$LOG_DIR/router-middle.pid"
kill_from_pidfile "$LOG_DIR/router-exit.pid"
kill_from_pidfile "$LOG_DIR/proxy.pid"
kill_listener_on_port 7101
kill_listener_on_port 7102
kill_listener_on_port 7103
kill_listener_on_port 18080

rm -f \
  "$ROOT/target/localnet/router-entry-state.json" \
  "$ROOT/target/localnet/router-middle-state.json" \
  "$ROOT/target/localnet/router-exit-state.json"

(
  cd "$ROOT"
  cargo build -p aurora-router -p aurora-proxy
)

start_router "entry"
start_router "middle"
start_router "exit"

wait_for_file "$ROOT/target/localnet/router-entry-state.json"
wait_for_file "$ROOT/target/localnet/router-middle-state.json"
wait_for_file "$ROOT/target/localnet/router-exit-state.json"

start_proxy
wait_for_port 18080

echo "Local 3-router demo is ready."
echo "proxy: http://127.0.0.1:18080"
echo "demo : curl -x http://127.0.0.1:18080 http://example.com/"
echo "alt  : scripts/localnet_send.sh"
