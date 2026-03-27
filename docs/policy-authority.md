# Policy Authority (PA) 現行仕様メモ

このリポジトリでの `PA` は、AURORA/HORNET に対して `directory announcement` を発行する主体です。現状の wire/JSON 契約から見ると、PA の責務は次の 3 点に集約されます。

1. `PolicyMetadata` を配布する
2. policy ごとの `RouteAnnouncement` を配布する
3. 上記を署名付き JSON として公開する

## 現行の公開フォーマット

ルータや proxy が検証しているのは `src/setup/directory.rs` の署名付き JSON です。

```json
{
  "version": 1,
  "issued_at": 1700000000,
  "policies": [ ... ],
  "routes": [ ... ],
  "signature": "<hex>"
}
```

- `policies`: `PolicyMetadata` の配列
- `routes`: policy ごとの forwarding/exit 経路
- `signature`: 署名対象 JSON の hex エンコード済み署名

署名時は `signature` フィールドだけ空文字列にした JSON 全体をシリアライズし、そのバイト列に対して署名します。検証時も同じ再シリアライズを行います。

## 署名方式

初期実装では `Ed25519` を採用しています。これは楕円曲線署名で、既存ルータ実装とも整合します。

- 秘密鍵入力: 32-byte seed
- 公開鍵: 32 bytes
- 署名: 64 bytes
- JSON 上の表現: いずれも hex

今後別方式を追加する場合でも、PA の責務自体は「directory を署名して配布する」ままで変わりません。

## このリポジトリでの実装

`authority` クレートに以下を実装しています。

- `PolicyAuthority`: policy/routes を組み立てて署名するライブラリ API
- `AuthorityConfig`: PA 用設定ファイル
- `aurora_authority`: 署名済み directory を `GET /` または `GET /directory` で返す最小 HTTP サーバ

## 設定ファイル例

```json
{
  "bind_addr": "127.0.0.1:8080",
  "signature_scheme": "ed25519",
  "issued_at": 1700000000,
  "signing_key_seed_hex": "1111111111111111111111111111111111111111111111111111111111111111",
  "policies": [
    {
      "policy_id": [66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66],
      "version": 1,
      "expiry": 600,
      "flags": 0,
      "verifiers": [
        {
          "kind": 1,
          "verifier_blob": [170,187,204]
        }
      ]
    }
  ],
  "routes": [
    {
      "policy_id": "4242424242424242424242424242424242424242424242424242424242424242",
      "interface": "router-entry",
      "segments": [
        {
          "type": "next_hop4",
          "ip": "127.0.0.1",
          "port": 7102
        }
      ]
    }
  ]
}
```

起動例:

```sh
cargo run -p authority -- --config authority/config.json
```

起動時に `directory_public_key` が標準エラーへ出るので、ルータ側の `directory_public_key` と合わせて使います。
