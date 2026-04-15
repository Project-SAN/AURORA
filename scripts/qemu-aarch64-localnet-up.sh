#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/target/qemu-aarch64-logs"
QEMU_DIR="$ROOT/target/qemu"
REQ_DIR="$ROOT/target/qemu-aarch64-logs"
CARGO_BIN="${CARGO_BIN:-cargo}"
CARGO_TOOLCHAIN="${CARGO_TOOLCHAIN:-}"
ROUTER_BIN="${ROUTER_BIN:-$ROOT/target/debug/aurora_router}"
PROXY_BIN="${PROXY_BIN:-$ROOT/target/debug/aurora_proxy}"
ENTRY_SCRIPT="${ENTRY_SCRIPT:-$ROOT/scripts/qemu-aarch64-localnet-entry.sh}"
MIDDLE_SCRIPT="${MIDDLE_SCRIPT:-$ROOT/scripts/qemu-aarch64-middle.sh}"
EXIT_SCRIPT="${EXIT_SCRIPT:-$ROOT/scripts/qemu-aarch64-exit.sh}"

mkdir -p "$LOG_DIR" "$QEMU_DIR" "$REQ_DIR"

rm -f \
  "$ROOT/target/qemu/router-entry-state.json" \
  "$ROOT/target/qemu/router-middle-state.json" \
  "$ROOT/target/qemu/router-exit-state.json"

cargo_cmd() {
  if [ -n "$CARGO_TOOLCHAIN" ]; then
    "$CARGO_BIN" "+$CARGO_TOOLCHAIN" "$@"
  else
    "$CARGO_BIN" "$@"
  fi
}

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
  local timeout="${2:-90}"
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

copy_into_image() {
  local image="$1"
  local router="$2"
  local cfg="$ROOT/config/qemu/${router}.router_config.json"
  local dir="$ROOT/config/qemu/${router}.directory.json"
  local state="$ROOT/target/qemu/${router}-state.json"
  local guest_state="$QEMU_DIR/${router}-guest-state.json"
  python3 - "$state" "$guest_state" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    state = json.load(f)
state["policies"] = []
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump(state, f, separators=(",", ":"))
PY
  mdel -i "$image" ::router_config.json >/dev/null 2>&1 || true
  mdel -i "$image" ::directory.json >/dev/null 2>&1 || true
  mdel -i "$image" ::router_state.json >/dev/null 2>&1 || true
  mdel -i "$image" ::ROUTER_S.JSO >/dev/null 2>&1 || true
  mcopy -i "$image" "$cfg" ::router_config.json
  mcopy -i "$image" "$dir" ::directory.json
  mcopy -i "$image" "$guest_state" ::router_state.json
  mcopy -i "$image" "$guest_state" ::ROUTER_S.JSO
}

bootstrap_router() {
  local env_file="$1"
  local log_file="$2"
  local bind_addr="$3"
  (
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
    export HORNET_ROUTER_BIND="$bind_addr"
    exec "$ROUTER_BIN"
  ) >"$log_file" 2>&1 &
  echo $!
}

start_http() {
  kill_from_pidfile "$LOG_DIR/http.pid"
  nohup python3 -m http.server 8080 --bind 0.0.0.0 >"$LOG_DIR/http.log" 2>&1 &
  echo $! >"$LOG_DIR/http.pid"
}

start_proxy() {
  kill_from_pidfile "$LOG_DIR/proxy.pid"
  (
    export HORNET_PROXY_BIND=127.0.0.1:18080
    export HORNET_POLICY_INFO="$ROOT/config/qemu/policy-info.host.json"
    export HORNET_PROXY_ROUTE_ONLY="${HORNET_PROXY_ROUTE_ONLY:-1}"
    export HORNET_PROXY_ZKBOO_ROUNDS=1
    export HORNET_PROXY_RESPONSE_TIMEOUT_SECS=120
    export HORNET_PROXY_ENTRY_ADDR=127.0.0.1:18111
    export HORNET_PROXY_RETURN_HOST=10.0.2.2
    export HORNET_PROXY_RESPONSE_BIND=0.0.0.0:0
    exec "$PROXY_BIN"
  ) >"$LOG_DIR/proxy.log" 2>&1 &
  echo $! >"$LOG_DIR/proxy.pid"
}

start_qemu() {
  local name="$1"
  local cmd="$2"
  local pidfile="$LOG_DIR/${name}.pid"
  local serial_log="$LOG_DIR/${name}.serial.log"
  local qemu_log="$LOG_DIR/${name}.qemu.log"
  kill_from_pidfile "$pidfile"
  : >"$serial_log"
  nohup env QEMU_SERIAL="file:$serial_log" "$cmd" >"$qemu_log" 2>&1 &
  echo $! >"$pidfile"
}

kill_from_pidfile "$LOG_DIR/router-entry-bootstrap.pid"
kill_from_pidfile "$LOG_DIR/router-middle-bootstrap.pid"
kill_from_pidfile "$LOG_DIR/router-exit-bootstrap.pid"
kill_from_pidfile "$LOG_DIR/entry.pid"
kill_from_pidfile "$LOG_DIR/middle.pid"
kill_from_pidfile "$LOG_DIR/exit.pid"
kill_from_pidfile "$LOG_DIR/proxy.pid"
kill_listener_on_port 18111
kill_listener_on_port 18112
kill_listener_on_port 18113
kill_listener_on_port 18101
kill_listener_on_port 18102
kill_listener_on_port 18103

cargo_cmd build -p aurora-userland --features router --target aarch64-unknown-none
cargo_cmd build -p aurora-kernel --features userland --target aarch64-unknown-uefi
cargo_cmd build -p aurora-router -p aurora-proxy

bootstrap_router "$ROOT/config/qemu/router-entry.host.env" "$LOG_DIR/router-entry-host.log" "127.0.0.1:18011" \
  >"$LOG_DIR/router-entry-bootstrap.pid"
bootstrap_router "$ROOT/config/qemu/router-middle.host.env" "$LOG_DIR/router-middle-host.log" "127.0.0.1:18012" \
  >"$LOG_DIR/router-middle-bootstrap.pid"
bootstrap_router "$ROOT/config/qemu/router-exit.host.env" "$LOG_DIR/router-exit-host.log" "127.0.0.1:18013" \
  >"$LOG_DIR/router-exit-bootstrap.pid"

wait_for_file "$ROOT/target/qemu/router-entry-state.json"
wait_for_file "$ROOT/target/qemu/router-middle-state.json"
wait_for_file "$ROOT/target/qemu/router-exit-state.json"

kill_from_pidfile "$LOG_DIR/router-entry-bootstrap.pid"
kill_from_pidfile "$LOG_DIR/router-middle-bootstrap.pid"
kill_from_pidfile "$LOG_DIR/router-exit-bootstrap.pid"

copy_into_image "$ROOT/qemu-img/virtio-fat-entry.img" "router-entry"
copy_into_image "$ROOT/qemu-img/virtio-fat-middle.img" "router-middle"
copy_into_image "$ROOT/qemu-img/virtio-fat-exit.img" "router-exit"

start_http
start_proxy
start_qemu "entry" "$ENTRY_SCRIPT"
start_qemu "middle" "$MIDDLE_SCRIPT"
start_qemu "exit" "$EXIT_SCRIPT"

wait_for_port 18080
sleep 5

echo "QEMU AArch64 3-node localnet is ready."
echo "proxy: http://127.0.0.1:18080 (route-only guest state is preloaded)"
echo "send : scripts/qemu-localnet-send.sh"
echo "down : scripts/qemu-aarch64-localnet-down.sh"

if [ "${QEMU_WAIT:-0}" = "1" ]; then
  wait_pids=()
  for name in entry middle exit; do
    pidfile="$LOG_DIR/${name}.pid"
    if [ -f "$pidfile" ]; then
      pid="$(cat "$pidfile" 2>/dev/null || true)"
      if [ -n "$pid" ]; then
        wait_pids+=("$pid")
      fi
    fi
  done
  if [ "${#wait_pids[@]}" -gt 0 ]; then
    wait "${wait_pids[@]}" || true
  fi
fi
