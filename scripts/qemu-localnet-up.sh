#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/target/qemu-logs"
QEMU_DIR="$ROOT/target/qemu"
REQ_DIR="$ROOT/target/qemu-logs"

mkdir -p "$LOG_DIR" "$QEMU_DIR" "$REQ_DIR" "$ROOT/target/uefi-boot/EFI/BOOT"

rm -f \
  "$ROOT/target/qemu/router-entry-state.json" \
  "$ROOT/target/qemu/router-middle-state.json" \
  "$ROOT/target/qemu/router-exit-state.json"

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
  mdel -i "$image" ::router_config.json >/dev/null 2>&1 || true
  mdel -i "$image" ::directory.json >/dev/null 2>&1 || true
  mdel -i "$image" ::router_state.json >/dev/null 2>&1 || true
  mdel -i "$image" ::ROUTER_S.JSO >/dev/null 2>&1 || true
  mcopy -i "$image" "$cfg" ::router_config.json
  mcopy -i "$image" "$dir" ::directory.json
  mcopy -i "$image" "$state" ::router_state.json
  mcopy -i "$image" "$state" ::ROUTER_S.JSO
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
    exec cargo run -p aurora-router
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
  nohup env \
    HORNET_PROXY_BIND=127.0.0.1:18080 \
    HORNET_POLICY_INFO="$ROOT/config/qemu/policy-info.host.json" \
    HORNET_PROXY_ROUTE_ONLY=0 \
    HORNET_PROXY_ZKBOO_ROUNDS=1 \
    HORNET_PROXY_RESPONSE_TIMEOUT_SECS=120 \
    HORNET_PROXY_ENTRY_ADDR=127.0.0.1:18111 \
    HORNET_PROXY_RETURN_HOST=10.0.2.2 \
    HORNET_PROXY_RESPONSE_BIND=0.0.0.0:0 \
    cargo run -p aurora-proxy >"$LOG_DIR/proxy.log" 2>&1 &
  echo $! >"$LOG_DIR/proxy.pid"
}

start_qemu() {
  local name="$1"
  local cmd="$2"
  local pidfile="$LOG_DIR/${name}.pid"
  local logfile="$LOG_DIR/${name}.serial.log"
  kill_from_pidfile "$pidfile"
  nohup "$cmd" >"$logfile" 2>&1 &
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

cargo build -p aurora-userland --features router --target x86_64-unknown-none
cargo build -p aurora-kernel --features userland --target x86_64-unknown-uefi
cp "$ROOT/target/x86_64-unknown-uefi/debug/aurora-kernel.efi" \
  "$ROOT/target/uefi-boot/EFI/BOOT/BOOTX64.EFI"

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
start_qemu "entry" "$ROOT/scripts/qemu-entry.sh"
start_qemu "middle" "$ROOT/scripts/qemu-middle.sh"
start_qemu "exit" "$ROOT/scripts/qemu-exit.sh"

wait_for_port 18080
# Avoid probing guest router listeners with nc -z: the probe creates an empty
# TCP accept, and the userland router then sits in read_exact waiting for a
# frame header on that socket. Give the guests a short boot window instead.
sleep 5

echo "QEMU 3-node localnet is ready."
echo "proxy: http://127.0.0.1:18080 (setup is automatic)"
echo "send : scripts/qemu-localnet-send.sh"
