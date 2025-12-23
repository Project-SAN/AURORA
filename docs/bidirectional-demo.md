# 双方向HORNET通信のデモ

このドキュメントでは、HORNETプロトコルの双方向通信（Bidirectional HORNET）を実際に動作させる手順を説明します。

## 概要

このデモでは、以下の構成で双方向通信を実現します：

```
Client → Entry Router → Middle Router → Exit Router → HTTP Server
       ←               ←                ←              ← (Response)
```

- **前方パス**: クライアントからHTTPサーバーへのリクエスト
- **後方パス**: HTTPサーバーからクライアントへのレスポンス

各ルータはオニオンルーティングにより、パケットの暗号化/復号化を行います。

## 前提条件

- Rust toolchain（cargo）がインストールされていること
- Python 3がインストールされていること（簡易HTTPサーバー用）

## セットアップ手順

### 1. 設定ファイルの生成

ローカルネットワーク用の設定ファイルを生成します：

```bash
cargo run --bin localnet_prep
```

これにより、`config/localnet/` ディレクトリに以下のファイルが生成されます：
- `router-entry.directory.json` - Entryルータ用設定
- `router-middle.directory.json` - Middleルータ用設定
- `router-exit.directory.json` - Exitルータ用設定
- `policy-info.json` - ポリシー情報

### 2. ルータの起動

3つのターミナルウィンドウを開き、それぞれで以下のコマンドを実行します：

**Entry Router (ターミナル1):**
```bash
HORNET_ROUTER_BIND=127.0.0.1:7101 \
HORNET_DIRECTORY_PATH=config/localnet/router-entry.directory.json \
HORNET_STORAGE_PATH=target/localnet/router-entry-state.json \
cargo run --bin hornet_router
```

**Middle Router (ターミナル2):**
```bash
HORNET_ROUTER_BIND=127.0.0.1:7102 \
HORNET_DIRECTORY_PATH=config/localnet/router-middle.directory.json \
HORNET_STORAGE_PATH=target/localnet/router-middle-state.json \
cargo run --bin hornet_router
```

**Exit Router (ターミナル3):**
```bash
HORNET_ROUTER_BIND=127.0.0.1:7103 \
HORNET_DIRECTORY_PATH=config/localnet/router-exit.directory.json \
HORNET_STORAGE_PATH=target/localnet/router-exit-state.json \
cargo run --bin hornet_router
```

各ルータが正常に起動すると、それぞれのポート（7101, 7102, 7103）でリスニングを開始します。

### 3. HTTPサーバーの起動

4つ目のターミナルで、テスト用のHTTPサーバーを起動します：

```bash
python3 -m http.server 8080
```

## テスト実行

### データ送信とレスポンス受信

データセンダーを実行して、双方向通信をテストします：

```bash
cargo run --bin hornet_data_sender config/localnet/policy-info.json 127.0.0.1:8080
```

### 期待される出力

成功すると、以下のような出力が表示されます：

```
Resolved 127.0.0.1:8080 to V4([127, 0, 0, 1]):8080
Listening for response on 127.0.0.1:XXXXX
データ送信完了: 127.0.0.1:7101 へ 1342 バイト (hops=3)
Waiting for response...
Connection from 127.0.0.1:XXXXX
Received Response:
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.12.4
Date: ...
Content-type: text/html; charset=utf-8
Content-Length: 872

<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
...
```

### ポリシー拒否のテスト

ブロックリストに登録されたドメインへのアクセスが正しく拒否されることを確認できます。

#### ブロックされたドメインへのアクセス（blocked.example）

```bash
cargo run --bin hornet_data_sender config/localnet/policy-info.json blocked.example:8080
```

**期待される出力:**
```
Resolved blocked.example:8080 to ...
hornet_data_sender error: failed to prove payload: PolicyViolation
```

ポリシー証明の生成段階で `Error::PolicyViolation` が発生し、パケットは送信されません。

#### 実際のブロックされたドメインへのアクセス（lp.sejuku.ne）

```bash
cargo run --bin hornet_data_sender config/localnet/policy-info.json lp.sejuku.ne:443
```

**期待される出力:**
```
Resolved lp.sejuku.ne to V4([...]):443
hornet_data_sender error: failed to prove payload: PolicyViolation
```

同様に、ポリシー違反により証明生成が失敗します。

> [!IMPORTANT]
> これらのテストでは、クライアント側でポリシー検証が実行され、ブロックリストに含まれるドメインに対してはゼロ知識証明の生成が失敗します。この動作により、プライバシーを保ちながらポリシー適合性を確保できます。

#### 許可されたドメインの確認

ブロックリストに含まれないドメインへのアクセスは成功することを確認：

```bash
cargo run --bin hornet_data_sender config/localnet/policy-info.json 127.0.0.1:8080
```

正常にHTTPレスポンスを受信できるはずです。


## パケットフロー詳細

### 前方パス（Forward Path）

1. **Client**: HTTPリクエストを作成し、3層のオニオン暗号化を適用
2. **Entry Router**: 外側のレイヤーを復号化し、Middleへ転送
3. **Middle Router**: 次のレイヤーを復号化し、Exitへ転送
4. **Exit Router**: 最後のレイヤーを復号化し、HTTPサーバーへ接続

### 後方パス（Backward Path）

1. **Exit Router**: HTTPレスポンスを受信し、暗号化レイヤーを追加
2. **Middle Router**: さらに暗号化レイヤーを追加
3. **Entry Router**: さらに暗号化レイヤーを追加
4. **Client**: 3層すべてを復号化して元のHTTPレスポンスを復元

## トラブルシューティング

### ルータが起動しない

- ポート7101-7103が既に使用されていないか確認してください
- `netstat -tlnp | grep 710` または `ss -tlnp | grep 710` でポートの状態を確認

### "Connection refused" エラー

- すべてのルータが起動していることを確認してください
- 環境変数 `HORNET_ROUTER_BIND` が正しく設定されているか確認してください

### レスポンスが暗号化されたまま

これは修正済みですが、もし発生した場合は：
- `src/bin/hornet_data_sender.rs` で鍵の順序が正しくreverse()されているか確認
- `src/node/backward.rs` でポリシーカプセルの処理が削除されているか確認

## ログの確認

各ルータのログを確認するには：

```bash
# バックグラウンドで実行した場合
cat entry.log middle.log exit.log

# デバッグ出力の確認
tail -f entry.log  # Entry Routerのログをリアルタイム表示
```

## クリーンアップ

テスト後、プロセスを停止するには：

```bash
# すべてのルータを停止
pkill -f hornet_router

# HTTPサーバーを停止
pkill -f "python3 -m http.server"
```

## 技術的な詳細

### 暗号化スキーム

- **オニオンルーティング**: 各ホップで1つのレイヤーを追加/削除
- **対称鍵暗号**: AES-CTRベースの暗号化
- **鍵導出**: セットアップフェーズで各ノードと共有鍵を確立

### ポリシー適用

- Exitルータは、ブロックリストに基づいてポリシーを検証
- ポリシーカプセルは前方パスでのみ処理（後方パスでは不要）

## 参考資料

- [HORNET: High-speed Onion Routing at the Network Layer](https://arxiv.org/abs/1507.05724)
- [プロジェクトREADME](../README.md)
