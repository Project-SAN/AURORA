#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QEMU_BIN="${QEMU_BIN:-qemu-system-aarch64}"
QEMU_MEM="${QEMU_MEM:-512M}"
QEMU_ROLE="${QEMU_ROLE:-entry}"
QEMU_MACHINE="${QEMU_MACHINE:-virt,gic-version=max}"
QEMU_SERIAL="${QEMU_SERIAL:-stdio}"
QEMU_DTB="${QEMU_DTB:-}"
UEFI_CODE="${UEFI_CODE:-}"
UEFI_VARS_TEMPLATE="${UEFI_VARS_TEMPLATE:-}"
QEMU_FIRMWARE_DIR="${QEMU_FIRMWARE_DIR:-}"
KERNEL_EFI="${KERNEL_EFI:-$ROOT/target/aarch64-unknown-uefi/debug/aurora-kernel.efi}"
BOOT_ROOT="${BOOT_ROOT:-$ROOT/target/uefi-boot-aarch64-${QEMU_ROLE}}"
BOOT_DIR="$BOOT_ROOT/EFI/BOOT"
DATA_IMG="${DATA_IMG:-$ROOT/qemu-img/virtio-fat-${QEMU_ROLE}.img}"
QEMU_SNAPSHOT="${QEMU_SNAPSHOT:-0}"
SERVICE_PORT="${SERVICE_PORT:-1234}"
HOST_FWD_PORT="${HOST_FWD_PORT:-18114}"
QEMU_FORWARD_CLI="${QEMU_FORWARD_CLI:-0}"
CLI_GUEST_PORT="${CLI_GUEST_PORT:-7001}"
CLI_HOST_FWD_PORT="${CLI_HOST_FWD_PORT:-0}"
NETDEV_OPTS="${NETDEV_OPTS:-}"
NET_MAC="${NET_MAC:-52:54:00:12:34:56}"
UEFI_VARS_FILE="${UEFI_VARS_FILE:-$ROOT/target/uefi-vars-aarch64-${QEMU_ROLE}.fd}"

resolve_firmware() {
  local code_candidates=(
    "$UEFI_CODE"
    "$QEMU_FIRMWARE_DIR/edk2-aarch64-code.fd"
    "$QEMU_FIRMWARE_DIR/AAVMF_CODE.fd"
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
    "/opt/homebrew/share/qemu/AAVMF_CODE.fd"
    "/usr/local/share/qemu/edk2-aarch64-code.fd"
    "/usr/local/share/qemu/AAVMF_CODE.fd"
  )
  for p in "${code_candidates[@]}"; do
    if [ -n "$p" ] && [ -f "$p" ]; then
      UEFI_CODE="$p"
      break
    fi
  done

  if [ -z "$UEFI_CODE" ] || [ ! -f "$UEFI_CODE" ]; then
    echo "Missing AArch64 UEFI firmware code: set UEFI_CODE or QEMU_FIRMWARE_DIR" >&2
    exit 1
  fi

  local vars_candidates=(
    "$UEFI_VARS_TEMPLATE"
    "$QEMU_FIRMWARE_DIR/edk2-aarch64-vars.fd"
    "$QEMU_FIRMWARE_DIR/edk2-arm-vars.fd"
    "$QEMU_FIRMWARE_DIR/AAVMF_VARS.fd"
    "/opt/homebrew/share/qemu/edk2-aarch64-vars.fd"
    "/opt/homebrew/share/qemu/edk2-arm-vars.fd"
    "/opt/homebrew/share/qemu/AAVMF_VARS.fd"
    "/usr/local/share/qemu/edk2-aarch64-vars.fd"
    "/usr/local/share/qemu/edk2-arm-vars.fd"
    "/usr/local/share/qemu/AAVMF_VARS.fd"
  )
  for p in "${vars_candidates[@]}"; do
    if [ -n "$p" ] && [ -f "$p" ]; then
      UEFI_VARS_TEMPLATE="$p"
      break
    fi
  done

  if [ -z "$UEFI_VARS_TEMPLATE" ] || [ ! -f "$UEFI_VARS_TEMPLATE" ]; then
    echo "Missing AArch64 UEFI vars template: set UEFI_VARS_TEMPLATE or QEMU_FIRMWARE_DIR" >&2
    exit 1
  fi
}

resolve_firmware

if [ ! -f "$KERNEL_EFI" ]; then
  echo "Missing kernel EFI binary: $KERNEL_EFI" >&2
  echo "Build it with: cargo build -p aurora-kernel --target aarch64-unknown-uefi" >&2
  exit 1
fi

if [ ! -f "$DATA_IMG" ]; then
  echo "Missing data image: $DATA_IMG" >&2
  exit 1
fi

if [ -n "$QEMU_DTB" ] && [ ! -f "$QEMU_DTB" ]; then
  echo "Missing DTB file: $QEMU_DTB" >&2
  exit 1
fi

mkdir -p "$BOOT_DIR"
cp "$KERNEL_EFI" "$BOOT_DIR/BOOTAA64.EFI"

if [ -z "$NETDEV_OPTS" ]; then
  NETDEV_OPTS="user,id=n0,hostfwd=tcp::${HOST_FWD_PORT}-:${SERVICE_PORT}"
  if [ "$QEMU_FORWARD_CLI" = "1" ] && [ "$CLI_HOST_FWD_PORT" != "0" ]; then
    NETDEV_OPTS="$NETDEV_OPTS,hostfwd=tcp::${CLI_HOST_FWD_PORT}-:${CLI_GUEST_PORT}"
  fi
fi

if [ "${QEMU_RESET_VARS:-0}" = "1" ] || [ ! -f "$UEFI_VARS_FILE" ]; then
  cp "$UEFI_VARS_TEMPLATE" "$UEFI_VARS_FILE"
fi
chmod u+w "$UEFI_VARS_FILE"

DATA_DRIVE_OPTS="if=none,format=raw,file=$DATA_IMG,id=blkfs"
if [ "$QEMU_SNAPSHOT" = "1" ]; then
  DATA_DRIVE_OPTS="$DATA_DRIVE_OPTS,snapshot=on"
fi

DTB_ARGS=()
if [ -n "$QEMU_DTB" ]; then
  DTB_ARGS=(-dtb "$QEMU_DTB")
fi

exec "$QEMU_BIN" \
  -machine "$QEMU_MACHINE" \
  -cpu cortex-a72 \
  -m "$QEMU_MEM" \
  -global virtio-mmio.force-legacy=off \
  -display none \
  -serial "$QEMU_SERIAL" \
  -monitor none \
  "${DTB_ARGS[@]}" \
  -drive if=pflash,format=raw,readonly=on,file="$UEFI_CODE" \
  -drive if=pflash,format=raw,file="$UEFI_VARS_FILE" \
  -drive if=virtio,format=raw,file=fat:rw:"$BOOT_ROOT" \
  -drive "$DATA_DRIVE_OPTS" \
  -netdev "$NETDEV_OPTS" \
  -device virtio-net-device,netdev=n0,mac="$NET_MAC" \
  -device virtio-blk-device,drive=blkfs
