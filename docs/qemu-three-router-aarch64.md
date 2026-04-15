# QEMU 3 ノード送信テスト AArch64

AArch64 UEFI guest 上の 3 ノード `entry -> middle -> exit` を通し、route-only で HTTP リクエストを送る手順です。state の bootstrap と proxy / HTTP server は既存の x86 デモと同じくホスト側で行い、guest 側 router は `aarch64-unknown-none` の `aurora-userland --features router` を使います。

## 前提

- `qemu-system-aarch64` が使えること
- `mcopy` / `mdir` が使えること
- macOS の場合は `/opt/homebrew/share/qemu/AAVMF_CODE.fd` などの AArch64 UEFI firmware があること

## 起動

```bash
scripts/qemu-aarch64-localnet-up.sh
```

このスクリプトは以下をまとめて行います。

- `aurora-userland --features router --target aarch64-unknown-none` を build
- `aurora-kernel --features userland --target aarch64-unknown-uefi` を build
- ホスト側 `aurora-router` 3 プロセスで `target/qemu/router-*-state.json` を bootstrap
- `router_config.json` / `directory.json` / `router_state.json` を各 `qemu-img/virtio-fat-*.img` に注入
- ホスト HTTP server (`0.0.0.0:8080`) 起動
- ホスト HTTP proxy (`127.0.0.1:18080`) を route-only mode で起動
- AArch64 guest 3 台起動 (`127.0.0.1:18111`, `:18112`, `:18113` を hostfwd)

## データ送信

送信 helper は x86 版と同じです。

```bash
scripts/qemu-localnet-send.sh \
  config/qemu/policy-info.host.json \
  example.com:80 \
  target/qemu-aarch64-logs/http-request.bin \
  target/qemu-aarch64-logs/http-response.bin
```

proxy 宛てに直接送る場合:

```bash
curl -x http://127.0.0.1:18080 http://example.org/
```

## 停止

```bash
scripts/qemu-aarch64-localnet-down.sh
```

## ログ

- QEMU serial: `target/qemu-aarch64-logs/*.serial.log`
- bootstrap router: `target/qemu-aarch64-logs/router-*-host.log`
- HTTP server: `target/qemu-aarch64-logs/http.log`
- HTTP proxy: `target/qemu-aarch64-logs/proxy.log`
