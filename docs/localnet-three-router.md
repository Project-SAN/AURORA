# ローカル 3 ルータ検証手順

`src/bin/localnet_prep.rs` が生成する設定ファイルを使うと、`hornet_router` を 3 プロセス起動して最小のローカル網を構築できます。各ルータは独立したディレクトリ JSON/状態ファイルを参照するため、エントリ → 中継 → エグジットの順に別ポートで待ち受けます。

## 前提

- Rust toolchain がインストール済み。
- `cargo run --bin hornet_router` を実行できること（`std` feature はデフォルト有効）。
- `nc` や `ncat` 等、シンプルな TCP サーバ/クライアントが利用可能であること（エグジット側の出口確認用）。

## 設定ファイル生成

```bash
cargo run --bin localnet_prep
```

- `config/localnet/` に以下が生成される:
  - `router-entry|middle|exit.directory.json` – 各ルータ専用のディレクトリアナウンス。HMAC 共有鍵は `localnet-secret`。
  - `router-*.env` – 上記ディレクトリを読み込むための環境変数セット。バインドアドレス（7101/7102/7103）と状態ファイルパスが含まれる。
  - `policy-info.json` – ポリシー ID と各ルータのバインド設定をまとめたメタ情報。
- `target/localnet/` 以下に状態ファイルが保存されるよう準備されます（初回起動時は存在しなくて OK）。

## エグジット先のダミーサーバ

出口ルータは `127.0.0.1:7200` へ `ExitTcp` する設定になっています。ログを観測するため、任意のターミナルで TCP サーバを立てておきます。

```bash
# 例: nc
nc -lk 7200
```

## ルータ起動

3 つのターミナルを開き、下記のようにそれぞれの `.env` を読み込みながら `hornet_router` を起動します。`env $(cat ... | xargs)` は POSIX シェルを前提とした短縮形です。

```bash
# 入口ルータ
env $(cat config/localnet/router-entry.env | xargs) cargo run --bin hornet_router

# 中継ルータ
env $(cat config/localnet/router-middle.env | xargs) cargo run --bin hornet_router

# 出口ルータ
env $(cat config/localnet/router-exit.env | xargs) cargo run --bin hornet_router
```

- 各ルータは自分専用の `router-*.directory.json` を読み込み、`target/localnet/router-*-state.json` にポリシー/ルート/SV を永続化します。
- ログに `directory sync failed` が出る場合は、`localnet_prep` を再実行してディレクトリを再生成してください。

## ユーザ送信 CLI (`hornet_sender`)

ルータの state (`target/localnet/router-*-state.json`) が生成されたら、`hornet_sender` でエントリルータにセットアップパケットを送信できます。内部で各 state からノード公開鍵を復元し、ディレクトリメタデータを TLV として付与します。

```bash
cargo run --bin hornet_sender config/localnet/policy-info.json
```

- 入口ルータ (`policy-info.json` の先頭) に TCP でフレームを書き込んで完了します。
- state ファイルが存在しない場合は「ルータを一度起動して state を生成してください」と表示されるため、まずルータを起動→停止して state を用意してください。

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

`localnet_up.sh` は内部で `cargo run --bin localnet_prep` を実行し、各ルータをバックグラウンドで起動したままにします。`localnet_down.sh` で必ず明示的に停止してください。

## データフレーム送信 CLI (`hornet_data_sender`)

政策検証済みのデータパケットは次のように送信できます。ブロックリストには `config/blocklist.json`（または `LOCALNET_BLOCKLIST` で差し替え）を利用します。

```bash
cargo run --bin hornet_data_sender config/localnet/policy-info.json safe.example "hello hornet"
```

- 第2引数: ポリシーに適合するホスト名。ブロック対象を指定するとクライアント側で証明が失敗します。
- 第3引数: 任意のメッセージ文字列（省略可）。ポリシーカプセル + ターゲット葉に続いてペイロード末尾へ追加されます。
- CLI は AHDR/CHDR/ペイロードを構築し、入口ルータ (`127.0.0.1:7101`) に forward フレームを送信します。

## 動作確認

1. 各ルータのログにエラーが出ず、`target/localnet/router-*-state.json` が生成されること。
2. `cargo run --bin hornet_sender config/localnet/policy-info.json` を実行すると入口ルータ側で setup 処理ログが出ること。
3. `cargo run --bin hornet_data_sender config/localnet/policy-info.json safe.example` を実行してもエラーが出ず、出口 (`nc -lk 7200` など) にフレームが到達すること。
4. `cargo test tests::pipeline` などの既存パイプラインテストが green であること（ポリシーカプセルの検証ロジックをカバー）。

**補足:** 将来的に送信デモを追加するときは、ここで生成した `policy-info.json` に含まれる `policy_id` と `localnet-secret` を利用してエンドツーエンド試験を行う想定です。
