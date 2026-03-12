# ローカル 3 ルータ検証手順

チェックイン済みの `config/localnet/` を使うと、`aurora_router` を 3 プロセス起動して最小のローカル網を構築できます。各ルータは独立したディレクトリ JSON/状態ファイルを参照するため、エントリ → 中継 → エグジットの順に別ポートで待ち受けます。

## 前提

- Rust toolchain がインストール済み。
- `cargo run --bin aurora_router` を実行できること（`std` feature はデフォルト有効）。
- `nc` や `ncat` 等、シンプルな TCP サーバ/クライアントが利用可能であること（エグジット側の出口確認用）。

## 設定ファイル

```bash
ls config/localnet
```

- `config/localnet/` には以下が含まれる:
  - `router-entry|middle|exit.directory.json` – 各ルータ専用のディレクトリアナウンス。
  - `router-*.env` – ディレクトリ/バインド/状態ファイルを指定する環境変数セット。
  - `policy-info.json` – ポリシー ID と各ルータのバインド設定をまとめたメタ情報。
- `target/localnet/` 以下の state は実行時に生成されます（初回起動時は存在しなくて OK）。

## エグジット先のダミーサーバ

出口ルータは `127.0.0.1:7200` へ `ExitTcp` する設定になっています。ログを観測するため、任意のターミナルで TCP サーバを立てておきます。

```bash
# 例: nc
nc -lk 7200
```

## ルータ起動

3 つのターミナルを開き、下記のようにそれぞれの `.env` を読み込みながら `aurora_router` を起動します。`env $(cat ... | xargs)` は POSIX シェルを前提とした短縮形です。

```bash
# 入口ルータ
env $(cat config/localnet/router-entry.env | xargs) cargo run --bin aurora_router

# 中継ルータ
env $(cat config/localnet/router-middle.env | xargs) cargo run --bin aurora_router

# 出口ルータ
env $(cat config/localnet/router-exit.env | xargs) cargo run --bin aurora_router
```

- 各ルータは自分専用の `router-*.directory.json` を読み込み、`target/localnet/router-*-state.json` にポリシー/ルート/SV を永続化します。
- ログに `directory sync failed` が出る場合は、`config/localnet/*.directory.json` と `policy-info.json` の整合を確認してください。

## スクリプトによる自動化

手動で 3 つのターミナルを管理するのが面倒な場合は、`scripts/` 以下の補助スクリプトを使ってください。

```bash
# ルータの起動（ログは target/localnet/*.log に保存）
scripts/localnet_up.sh

# セットアップ + データ送信（必要に応じて HOST/MESSAGE を指定）
scripts/localnet_send.sh               # safe.example / "hello hornet"
scripts/localnet_send.sh config/localnet/policy-info.json safe.example "custom message"

# ルータの停止
scripts/localnet_down.sh
```

`config/localnet/` は固定ファイルとして管理しています。通常の検証では追加の生成手順は不要です。

## HTTP プロキシ (`aurora_proxy`)

`aurora_proxy` はローカル HTTP プロキシとして待ち受け、起動時に自動で `setup` を送り、その後の HTTP リクエストを内部で送信します。

```bash
HORNET_PROXY_BIND=127.0.0.1:18080 \
HORNET_POLICY_INFO=config/localnet/policy-info.json \
HORNET_PROXY_ZKBOO_ROUNDS=8 \
cargo run --features std --bin aurora_proxy
```

例:

```bash
curl -x http://127.0.0.1:18080 http://example.com/
```

> [!IMPORTANT]
> `aurora_proxy` は `HTTP` と `HTTPS CONNECT` の両方を扱えます。`CONNECT` は setup 後に session 継続型トンネルとして流れます。

## 動作確認

1. 各ルータのログにエラーが出ず、`target/localnet/router-*-state.json` が生成されること。
2. `aurora_proxy` 起動時に入口ルータ側で setup 処理ログが出ること。
3. `curl -x http://127.0.0.1:18080 http://safe.example/` 等でエラーが出ず、出口 (`nc -lk 7200` など) にフレームが到達すること。
4. `cargo test tests::pipeline` などの既存パイプラインテストが green であること（ポリシーカプセルの検証ロジックをカバー）。

**補足:** `policy-info.json` に含まれる `policy_id` を使ってエンドツーエンド試験を行います。値を更新する場合は `config/localnet/` 一式をまとめて更新してください。
