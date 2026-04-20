# QEMU 3 ノード送信テスト

`setup` から始めて、QEMU 上の 3 ノード `entry -> middle -> exit` を通し、policy 有効のまま HTTP リクエストを送る手順です。チェックイン済みの `config/qemu/` を使い、ホスト側で state を bootstrap し、その state / directory / router config を各 QEMU 用 FAT イメージへ注入してから起動します。現在のデモ policy は固定 allow-host ではなく、`config/blocklist.json` に載っていない HTTP Host を許可します。

## 前提

- `qemu-system-x86_64` が使えること
- `mcopy` / `mdir` が使えること
- macOS の場合は `/opt/homebrew/share/qemu/edk2-x86_64-code.fd` などの UEFI firmware があること

## 起動

```bash
scripts/qemu-localnet-up.sh
```

このスクリプトは以下をまとめて行います。

- ホスト側 `aurora_router` 3 プロセスで `target/qemu/router-*-state.json` を bootstrap
- 既存の `target/qemu/router-*-state.json` を削除して stale route を持ち越さないようにする
- `router_config.json` / `directory.json` / `router_state.json` を各 `qemu-img/virtio-fat-*.img` に注入
- ホスト HTTP サーバ (`0.0.0.0:8080`) 起動
- ホスト HTTP proxy (`127.0.0.1:18080`) を通常送信モードで起動
- QEMU ノード 3 台起動 (`127.0.0.1:18111`, `:18112`, `:18113` を hostfwd)

送信側が使う設定は [config/qemu/policy-info.json](/Users/hiro/workspace/project-san/AURORA/config/qemu/policy-info.json) です。各 router には `bind` と `proxy_bind` があり、router 間経路には `10.0.2.2:*`、ホスト上の proxy 接続には `127.0.0.1:*` を使います。

## データ送信

送信者側は entry に直接投げず、必ずホスト側 proxy (`aurora_proxy`) を経由します。

```bash
scripts/qemu-localnet-send.sh
```

proxy は起動時に自動で `setup` を流します。デフォルトでは proxy に対して `GET / HTTP/1.0` を流し、proxy 自身が policy capsule 付きの通常送信でターゲットへ送ります。レスポンスは `target/qemu-logs/http-response.bin` に保存されます。

blocklist 非掲載ホストを確認する最短手順:

```bash
scripts/qemu-localnet-up.sh
curl -x http://127.0.0.1:18080 http://example.org/
```

proxy に直接流す場合:

```bash
curl -x http://127.0.0.1:18080 http://example.org/
```

helper script で任意ターゲットを送る場合:

```bash
scripts/qemu-localnet-send.sh config/qemu/policy-info.json example.org:80 /absolute/path/to/request.bin /absolute/path/to/response.bin
```

固定長 payload を policy と合わせる必要があるので、独自 request を渡す場合は `LOCALNET_ZKBOO_PAYLOAD_LEN_BYTES` と整合する長さにしてください。デフォルトは 96 bytes です。

`config/blocklist.json` を更新した場合は、QEMU 用 artifact も `cargo run --example generate_demo_configs` で再生成してください。

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
- deny-list は `config/blocklist.json`
- policy payload 長は 96 bytes
