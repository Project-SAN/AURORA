# ZKMB-HORNET プロトコル仕様草案

## 概要
ZKMB-HORNET は、HORNET ルーティングに第三者機関発行のゼロ知識証明カプセルを組み込み、
ポリシー内容を秘匿したまま通信制御を行うためのプロトコル草案である。
送信者はポリシー適合性を証明する `PolicyCapsule` をペイロードへ付与し、
各中継ノードは `PolicyMetadata` 内の検証器記述を用いて証明を確認する。
ノード運営者や他の参加者はポリシー内容を知ることなく違反パケットを遮断できる。

## 参加アクター
- **Policy Authority (PA)**: ポリシー回路を Plonk 系 SNARK でコンパイルし、証明 API を提供する第三者機関。
- **Source Client**: 通信平文をコミットし、PA の API から証明（PolicyCapsule）を取得してパケットを送信する正規クライアント。
- **Forwarding Nodes**: HORNET の中継ノード。セットアップ時に `PolicyMetadata` を受け取り、データ平面でカプセル検証を行う。
- **Destination**: カプセル除去後のアプリケーションペイロードを受信するエンドポイント。

## データ構造
### PolicyMetadata TLV
AHDR 内に封入される TLV。TLV タイプは `0xA1` を予約。
```
u8  tlv_type   = 0xA1
u16 tlv_len    = |payload|
payload = struct PolicyMetadataPayload {
    policy_id: [u8; 32],
    version: u16,
    expiry: u32,
    flags: u16,
    verifier_blob_len: u32,
    verifier_blob: [u8; verifier_blob_len],
}
```
- `policy_id`: ポリシー回路とバージョンを識別。
- `verifier_blob`: `dusk-plonk` の `composer::Verifier::to_bytes()` 出力（検証鍵・開鍵・公開入力配置・トランスクリプト種別を含む）。
- `expiry`: UNIX time (秒)。期限切れ後は再セットアップ要求を行う。

### PolicyCapsule ペイロード
データパケットのアプリケーションペイロード先頭に挿入する構造。
```
struct PolicyCapsule {
    magic: [u8; 4] = "ZKMB",
    policy_id: [u8; 32],
    capsule_version: u8,
    reserved: u8,
    proof_len: u16,
    commit_len: u16,
    aux_len: u16,
    proof: [u8; proof_len],
    commitment: [u8; commit_len],
    aux_data: [u8; aux_len],
}
```
- `proof`: Plonk 証明。数百バイト～1KB を想定。
- `commitment`: 平文／TLS transcript 等のコミットメント（Poseidon/BLAKE3 など）。
- `aux_data`: 追加公開入力。例: セッション ID、時刻 nonce。

カプセル直後にアプリケーションペイロードが続く。

## プロトコルフロー
1. **セットアップ**
   - ソースはディレクトリから経路情報と `PolicyMetadata` を取得。
   - AHDR 生成時に `PolicyMetadata` TLV を挿入。各ノードは AHDR 復号時に TLV を取り出し、`policy_id → verifier` をレジストリへ登録。

2. **証明生成**
   - ソースはペイロードから検査対象値（例: HTTP Host ドメイン）を抽出し、ハッシュ化した値を回路入力に使う。
   - クライアントは外部証明サービス API (`POLICY_PROOF_URL`) に `{policy_id, payload_hex, aux_hex}` を送信し、Plonk 証明・コミットメントを含む JSON を受領して `PolicyCapsule` に変換。`policy-plonk` と `policy-client` を併用する場合、ローカルの Plonk プロバーが同等の証明（ブロックリストとの非一致）を生成する。
   - PA は Plonk 回路で証明を生成し、`proof` を返却。エラー時は「non-compliant」のみ返す。

3. **データ送信**
   - ソースは `PolicyCapsule` を構築し、ペイロード先頭に付加。
   - `hornet::source::build_data_packet` で AHDR/CHDR を組み立てて送出。

4. **中継ノード処理**
   - `process_data_forward` でオニオン層を剥がした後、カプセルを抽出。
   - `policy_id` から検証鍵を取得し、Plonk 検証 `verify(proof, [commitment, aux])` を実行。
   - 成功: カプセル部分を削除し、残りのペイロードを次ホップへ。
   - 失敗: `Error::PolicyViolation` を返してパケットを破棄。ログには `policy_id` と結果のみ記録。

5. **宛先**
   - 最終ノードでアプリケーションペイロードだけが残り、通常の HORNET データフローに従って Delivery。

## API 仕様 (PA)
```
POST /plonk/prove
Headers:
  Authorization: Bearer <token>
Body (JSON or CBOR):
{
  "policy_id": "base64",
  "commit": "base64",
  "aux": "base64",
  "payload_hint": "ciphertext hash"
}
Response:
{
  "policy_id": "...",
  "proof": "base64",
  "commit_confirm": "base64",
  "aux_hash": "base64",
  "expiry": <u64>
}
```
- 成功時のみ証明を返す。失敗時は HTTP 4xx と "non_compliant"。
- レート制限・監査ログでポリシー推測を抑止。

## エラーハンドリング
- `Error::PolicyViolation`: カプセル不在、ID 不一致、検証失敗等を示す。
- `Error::Expired`: `PolicyMetadata.expiry` 超過。
- PI 収集: `policy_id`, `peer`, `timestamp` を記録。理由はログに残さない。

## セキュリティ要件
- Plonk 証明はユニバーサル SRS を使用（Trusted Setup は一度きり）。
- ポリシー更新時は `policy_id` をローテーションし、旧 ID への証明発行を停止。
- クライアントは API 認証必須。未認証クライアントには証明が提供されないため通信できない。
- ノード実装はカプセル検証を無効化できないようにすることで、証明未添付パケットを強制的に遮断。

## 実装ロードマップ
1. `PolicyCapsule`/`PolicyMetadata` の型とシリアライザーを `policy` モジュールに実装。
2. AHDR への TLV 埋め込み・ノード側レジストリ実装。
3. `process_data_forward` へカプセル抽出＋検証フックを追加。
4. Plonk 検証器（`std` 依存の場合は別プロセス or FFI）と ProofService API 連携。
5. テスト: カプセル parsing、検証成功/失敗、期限管理。

## 想定ユースケース
- 違法・詐欺サイトの秘匿フィルタリング
- B2B ポータルや業務 API の限定公開
- リモート規制遵守（TLS トランスクリプト検査など）

## 今後の課題
- `no_std` 環境で動く Plonk 検証器の選定またはアーキテクチャ調整。
- 証明 API の SLA/NFR（遅延、可用性）の定義。
- 複数ポリシーを同時強制する際のカプセル連結方式。
- プライバシー攻撃（failure オラクル）対策としてのレート制限・監査。
### ディレクトリアナウンスメント API
- REST メッセージ例:
  ```json
  {
    "version": 1,
    "issued_at": 1710000000,
    "policies": [ { ...PolicyMetadata... }, ... ],
    "signature": "<HMAC-SHA256 hex>"
  }
  ```
- `signature` は共有鍵 `secret` を用いた `HMAC-SHA256( json_without_signature )`。クライアントは `from_signed_json(body, secret)` で検証し、`DirectoryAnnouncement` として取り出す。
- `to_signed_json(announcement, secret, issued_at)` を用いれば配布側で同じフォーマットを生成できる。
