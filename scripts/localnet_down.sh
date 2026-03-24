#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/target/localnet"

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

kill_from_pidfile "$LOG_DIR/router-entry.pid"
kill_from_pidfile "$LOG_DIR/router-middle.pid"
kill_from_pidfile "$LOG_DIR/router-exit.pid"
kill_from_pidfile "$LOG_DIR/proxy.pid"
kill_listener_on_port 7101
kill_listener_on_port 7102
kill_listener_on_port 7103
kill_listener_on_port 18080

echo "Local 3-router demo stopped."
