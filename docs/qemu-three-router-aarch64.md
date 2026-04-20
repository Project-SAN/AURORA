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
  config/qemu/policy-info.json \
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

## 現状の制約

現時点の AArch64 3 ノード localnet は、`route-only guest state preloaded` 方式です。ホスト側 `aurora-router` で生成した state から `policies` を取り除いた軽量 state を作り、それを各 guest の FAT image に注入します。guest 側 router はその軽量 state の `routes` / `sv` / `node_secret` だけを読み、directory の full policy state は読み直しません。

この方式で `entry -> middle -> exit` の転送、exit から外部 TCP への送信、backward response の復号までは確認済みです。一方で、x86 localnet と同じ full policy mode ではありません。full policy state を guest 内でそのまま読むと、現在の AArch64 EL0 userland では JSON サイズ、policy runtime 復元、FAT 経由の読み込み、メモリ使用量が重くなりやすいため、M7では安定した経路疎通を優先して route-only にしています。

## 次の実装候補: Full Policy Guest Mode

次に進めるなら、別マイルストーンとして `full policy guest mode` を実装します。目的は、AArch64 guest router がホストで軽量化された route-only state ではなく、policy runtime を含む full state または signed directory を自力で読み込み、通常の policy enforcement path で `entry -> middle -> exit` を通すことです。

実装するものは次の通りです。

- guest 用 state format を整理します。現在の `StoredState` JSON をそのまま読む方式に加えて、AArch64 guest でも扱いやすい compact/binary state format を用意し、policy runtime 復元に必要な情報だけを持たせます。
- directory 読み込み経路を軽くします。巨大な signed directory JSON を毎回 EL0 で全量 parse するのではなく、bootstrap 時に guest 用 directory/state artifact を生成し、guest は検証済み artifact を読む構成にします。
- guest router の起動モードを明示します。`skip_policy` と route-only の暗黙挙動ではなく、`route_only` / `full_policy` のような設定を `router_config.json` に持たせ、serial log でもどちらで起動したか分かるようにします。
- proxy の route-only 分岐と full policy 分岐を AArch64 localnet で両方検証できるようにします。full policy mode では setup packet を省略せず、policy-aware path のまま entry に投入します。
- メモリとI/Oの上限を計測します。AArch64 UEFI image、ramdisk、EL0 heap、FAT image 読み込みサイズをログに出し、full policy state が失敗した場合にどこで詰まったか分かるようにします。

実装方針は次の順序が安全です。

1. まずホスト側で guest 用 full-policy artifact を生成します。`scripts/qemu-aarch64-localnet-up.sh` の bootstrap 後に、full `router-*-state.json` から guest で不要なpretty formattingを削り、必要なら binary/compact JSON に変換します。
2. `userland/src/router_storage.rs` に AArch64 用 loader を追加します。最初は compact JSON で `policies` を読む実装にし、重ければ binary format に切り替えます。route-only loader は残し、設定で切り替えられるようにします。
3. `userland/src/router_app.rs` の起動分岐を整理します。state に policy runtime がある場合だけ directory reload を省略し、full policy mode では `Router::policy_runtime()` が有効であることを起動ログに出します。
4. full policy mode の proxy 設定を追加します。AArch64 localnet script で `HORNET_PROXY_ROUTE_ONLY=0` を選べるようにし、setup packet と policy payload の経路を有効化します。
5. 1 hop の entry-only 検証から始めます。いきなり3ノードではなく、entry guest が setup/data を受けて policy runtime を使えることを確認し、その後 `entry -> middle -> exit` に拡張します。
6. 最後に3ノード HTTP 200 を確認します。成功条件は、serial log に setup処理、forward policy処理、exit request、backward response が残り、proxy 側で `got response bytes > 0` になることです。

この作業では、route-only mode は残します。full policy mode の実装途中でguest側JSON/heap/FSの問題が出ても、M7の疎通検証を壊さないためです。
