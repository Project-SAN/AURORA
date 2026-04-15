#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

export QEMU_ROLE="${QEMU_ROLE:-entry}"
export SERVICE_PORT="${SERVICE_PORT:-7000}"
export HOST_FWD_PORT="${HOST_FWD_PORT:-18111}"
export QEMU_FORWARD_CLI="${QEMU_FORWARD_CLI:-1}"
export CLI_HOST_FWD_PORT="${CLI_HOST_FWD_PORT:-18101}"
export NET_MAC="${NET_MAC:-52:54:00:12:34:56}"

exec "$ROOT/scripts/qemu-aarch64-entry.sh"
