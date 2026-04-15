#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/target/qemu-aarch64-logs"

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

kill_from_pidfile "$LOG_DIR/router-entry-bootstrap.pid"
kill_from_pidfile "$LOG_DIR/router-middle-bootstrap.pid"
kill_from_pidfile "$LOG_DIR/router-exit-bootstrap.pid"
kill_from_pidfile "$LOG_DIR/entry.pid"
kill_from_pidfile "$LOG_DIR/middle.pid"
kill_from_pidfile "$LOG_DIR/exit.pid"
kill_from_pidfile "$LOG_DIR/http.pid"
kill_from_pidfile "$LOG_DIR/proxy.pid"
kill_listener_on_port 18111
kill_listener_on_port 18112
kill_listener_on_port 18113
kill_listener_on_port 18101
kill_listener_on_port 18102
kill_listener_on_port 18103

echo "QEMU AArch64 localnet stopped."
