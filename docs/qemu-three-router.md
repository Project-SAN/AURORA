# QEMU 3 ノード送信テスト

`setup` から始めて、QEMU 上の 3 ノード `entry -> middle -> exit` を通し、policy 有効のまま HTTP リクエストを送る手順です。ホスト側で state を bootstrap し、その state / directory / router config を各 QEMU 用 FAT イメージへ注入してから起動します。

## 前提

- `qemu-system-x86_64` が使えること
- `mcopy` / `mdir` が使えること
- macOS の場合は `/opt/homebrew/share/qemu/edk2-x86_64-code.fd` などの UEFI firmware があること

## 起動

```bash
scripts/qemu-localnet-up.sh
```

このスクリプトは以下をまとめて行います。

- `localnet_prep` と `localnet_prep -- --qemu-from-localnet`
- ホスト側 `aurora_router` 3 プロセスで `target/qemu/router-*-state.json` を bootstrap
- 既存の `target/qemu/router-*-state.json` を削除して stale route を持ち越さないようにする
- `router_config.json` / `directory.json` / `router_state.json` を各 `qemu-img/virtio-fat-*.img` に注入
- ホスト HTTP サーバ (`0.0.0.0:8080`) 起動
- ホスト HTTP proxy (`127.0.0.1:18080`) を通常送信モードで起動
- QEMU ノード 3 台起動 (`127.0.0.1:18111`, `:18112`, `:18113` を hostfwd)

送信側が使う設定は [config/qemu/policy-info.host.json](/Users/hiro/workspace/project-san/AURORA/config/qemu/policy-info.host.json) です。QEMU ゲスト内では `10.0.2.2:*` を使いますが、ホスト CLI からは `127.0.0.1:*` に正規化した方を使います。

## setup 送信

```bash
cargo run --features std --bin aurora_sender config/qemu/policy-info.host.json
```

## データ送信

送信者側は entry に直接投げず、必ずホスト側 proxy (`aurora_proxy`) を経由します。

```bash
scripts/qemu-localnet-send.sh
```

デフォルトでは proxy に対して `GET / HTTP/1.0` を流し、proxy 配下の `aurora_data_sender` が policy capsule 付きの通常送信でターゲットへ送ります。レスポンスは `target/qemu-logs/http-response.bin` に保存されます。

`example.com` を確認する最短手順:

```bash
scripts/qemu-localnet-up.sh
curl -x http://127.0.0.1:18080 http://example.com/
```

proxy に直接流す場合:

```bash
curl -x http://127.0.0.1:18080 http://example.com/
```

helper script で任意ターゲットを送る場合:

```bash
scripts/qemu-localnet-send.sh config/qemu/policy-info.host.json example.com:80 /absolute/path/to/request.bin /absolute/path/to/response.bin
```

固定長 payload を policy と合わせる必要があるので、独自 request を渡す場合は `LOCALNET_ZKBOO_PAYLOAD_LEN_BYTES` と整合する長さにしてください。デフォルトは 96 bytes です。

## 停止

```bash
scripts/qemu-localnet-down.sh
```

## ログ

- QEMU serial: `target/qemu-logs/*.{serial,log}`
- bootstrap router: `target/qemu-logs/router-*-host.log`
- HTTP server: `target/qemu-logs/http.log`
- HTTP proxy: `target/qemu-logs/proxy.log`

## 現在の既定値

- policy は有効 (`skip_policy=false`)
- proxy は通常送信モード (`HORNET_PROXY_ROUTE_ONLY=0`)
- 許可ホストは `example.com`
- policy payload 長は 96 bytes
