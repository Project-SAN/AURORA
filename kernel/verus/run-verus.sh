#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${VERUS_BIN:-}" ]]; then
  VERUS="${VERUS_BIN}"
elif command -v verus >/dev/null 2>&1; then
  VERUS="$(command -v verus)"
elif [[ -x "${HOME}/.local/bin/verus" ]]; then
  VERUS="${HOME}/.local/bin/verus"
elif [[ -n "${VERUS_HOME:-}" && -x "${VERUS_HOME}/source/target-verus/release/verus" ]]; then
  VERUS="${VERUS_HOME}/source/target-verus/release/verus"
else
  echo "verus binary not found. Set VERUS_BIN or VERUS_HOME." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
"${VERUS}" --crate-name paging_verus "${ROOT_DIR}/kernel/src/paging.verus.rs"
"${VERUS}" --crate-name memory_verus "${ROOT_DIR}/kernel/src/memory.verus.rs"
