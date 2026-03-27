# ローカル 3 ルータ検証手順

チェックイン済みの `config/localnet/` を使うと、ホスト上で `aurora_router` を 3 プロセス起動し、`entry -> middle -> exit` の最小構成をすぐに再現できます。`aurora_proxy` を前段に置くと、proxy が `setup` を自動送信し、そのまま blocklist に載っていない `http://example.com/` や `http://example.org/` のような HTTP リクエストを 3 ホップ経由で流せます。

## 前提

- Rust toolchain がインストール済み
- `cargo build -p aurora-router -p aurora-proxy` を実行できること
- `nc` または `ncat` が利用できること
- `example.com:80` または `example.org:80` へ到達できるネットワークがあること

## 設定ファイル

```bash
ls config/localnet
```

- `config/localnet/` には以下が含まれる:
  - `router-entry|middle|exit.directory.json` – 各ルータ専用のディレクトリアナウンス。
  - `router-*.env` – ディレクトリ/バインド/状態ファイルを指定する環境変数セット。
  - `policy-info.json` – ポリシー ID と各ルータのバインド設定をまとめたメタ情報。
- `target/localnet/` 以下の state は実行時に生成されます（初回起動時は存在しなくて OK）。
- deny-list の元データは `config/blocklist.json` です。更新後は `cargo run --example generate_demo_configs` を実行して `config/localnet/` と `config/qemu/` の artifact を再生成してください。

## スクリプトによる自動化

`scripts/` 以下の補助スクリプトで、ローカル 3 ルータと proxy をまとめて起動できます。起動時に `target/localnet/router-*-state.json` は削除され、毎回クリーンな state で bootstrap します。

```bash
# ルータ 3 台 + proxy の起動
scripts/localnet_up.sh

# PA から bootstrap する版
scripts/localnet_pa_up.sh

# blocklist に載っていないホストへ HTTP GET
curl -x http://127.0.0.1:18080 http://example.org/
curl -x http://127.0.0.1:18081 http://example.com/

# helper script で送る場合
scripts/localnet_send.sh
scripts/localnet_send.sh config/localnet/policy-info.json example.org:80

# ルータの停止
scripts/localnet_down.sh
scripts/localnet_pa_down.sh
```

ログは `target/localnet/router-*.log` と `target/localnet/proxy.log` に出ます。
PA 版のログは `target/localnet-pa/authority.log`, `target/localnet-pa/router-*.log`, `target/localnet-pa/proxy.log` に出ます。

## 手動起動

スクリプトを使わずに起動する場合は、各 `.env` を読み込んで 3 台の `aurora_router` を別ターミナルで立ち上げ、その後に `aurora_proxy` を起動します。

```bash
# entry
(
  set -a
  source config/localnet/router-entry.env
  set +a
  cargo run -p aurora-router
)

# middle
(
  set -a
  source config/localnet/router-middle.env
  set +a
  cargo run -p aurora-router
)

# exit
(
  set -a
  source config/localnet/router-exit.env
  set +a
  cargo run -p aurora-router
)
```

## HTTP プロキシ (`aurora_proxy`)

`aurora_proxy` はローカル HTTP プロキシとして待ち受け、起動時に自動で `setup` を送り、その後の HTTP リクエストを内部で送信します。

```bash
HORNET_PROXY_BIND=127.0.0.1:18080 \
HORNET_POLICY_INFO=config/localnet/policy-info.json \
HORNET_PROXY_ROUTE_ONLY=0 \
HORNET_PROXY_ZKBOO_ROUNDS=1 \
cargo run -p aurora-proxy
```

例:

```bash
curl -x http://127.0.0.1:18080 http://example.org/
```

> [!IMPORTANT]
> `aurora_proxy` は `HTTP` と `HTTPS CONNECT` の両方を扱えます。`CONNECT` は setup 後に session 継続型トンネルとして流れます。

## 動作確認

1. 各ルータのログにエラーが出ず、`target/localnet/router-*-state.json` が生成されること
2. `aurora_proxy` 起動時に entry 側で `setup sent` / setup 処理ログが出ること
3. `curl -x http://127.0.0.1:18080 http://example.org/` が成功し、`target/localnet/proxy.log` に forward ログが出ること
4. `blocked.example` のような blocklist 登録済みホストでは proxy 側が失敗すること

ブロック確認:

```bash
curl -x http://127.0.0.1:18080 http://blocked.example/
```

オフライン環境では、別ターミナルで `python3 -m http.server 8080 --bind 127.0.0.1` を立ててから、下記に差し替えるとローカルだけで双方向デモを見せられます。

```bash
curl -x http://127.0.0.1:18080 http://127.0.0.1:8080/
```

**補足:** `policy-info.json` に含まれる `policy_id` を使ってエンドツーエンド試験を行います。blocklist を更新した場合は `cargo run --example generate_demo_configs` で `config/localnet/` 一式をまとめて更新してください。
