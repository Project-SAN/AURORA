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

## 付録: プライバシー保持型リモート証明プロトコル案

### 目的と前提
現行の `POST /prove` はクライアントが抽出したペイロード（例: 検索語や Host ヘッダ）を平文のまま PA に送信し、PA がブロックリスト照合と証明生成を行う。これでは PA 運用者が問い合わせ内容を直接観測できるため、以下を満たす改訂案を提示する。

1. クライアントは **検索語やドメインの平文を PA に渡さない**。
2. PA は **正しくブロックリスト非該当性を証明する責務** を保持する。
3. 中継ノードは従来通り `PolicyCapsule` の検証だけでポリシー強制ができる。
4. 追加の暗号処理はクライアント側で完結し、ブラウザ拡張など軽量実装でも成立する。

本案では TEE（例: Intel SGX/TDX）によるリモートアテステーションと VOPRF（Verifiable Oblivious PRF）を組み合わせ、PA 運用者から利用者のターゲット情報を秘匿する。

### 新規構成要素
- **アテステーション付き TEE**: `prove` エンドポイントは enclaved サービスとして動作し、運用者から隔離されたメモリで処理する。クライアントはアテステーション証明書を検証し、正しいバイナリが動作していると確信した場合のみ以降の暗号ハンドシェイクを継続する。
- **VOPRF キー対**: PA は秘密鍵 `k` を用いてドメイン/検索語 `x` を `y = F_k(x)` に射影する。VOPRF の盲検出性により、PA は `x` を特定できない。
- **ハッシュ済みブロックリスト**: Blocklist の各要素 `b_i` について `F_k(b_i)` を事前計算し、Merkle ツリーでコミットしておく。以後の検証は `y` がツリーに含まれないことを証明する手続きに置き換える。
- **ペイロード拘束用コミットメント**: クライアントは HTTP リクエストヘッダから抽出したターゲット値 `x` を Poseidon 等でコミットし、同時に `y = F_k(x)` を得る。TEE 内の証明回路は「`y` はブロックリストに含まれず、かつコミットされた payload から復元できる `x` と一致する」ことを示す。

### 変更後ワークフロー
1. **ディレクトリアクセス**
   - `GET /@hornet/directory` → 以下を返却:
     - `policy_id`
     - `prove_url` / `verify_url`
     - `voprf` 公開パラメータ（Elliptic curve, generator, 評価ポイント）
     - `tee_quote`（アテステーションレポート）と `binary_measurement`
     - `merkle_root`（`F_k(blocklist)` のルート）
   - クライアントは TEE ベリファイ、バイナリ測定値検証、公開鍵検証を行い、信頼境界を確立。

2. **VOPRF 評価**
   - クライアント: 抽出したターゲット `x` から盲検 `α = Blind(x)` を生成し、`POST /@hornet/oprf` に送信。
   - TEE 内のサービス: `β = Evaluate_k(α)` を返却。
   - クライアント: `y = Finalize(x, β)` を取得。PA は `x` の平文を知り得ない。

3. **プライバシー保護証明リクエスト**
   - クライアントは以下の JSON を `POST /@hornet/prove_privacy` へ送信:
     ```json
     {
       "policy_id": "<hex>",
       "payload_commitment": "<poseidon(x || nonce)>",
       "payload_hint": "<ハッシュ済みHTTPヘッダの付随情報>",
       "oprf_output": "<hex(y)>",
       "nonce_commitment": "<blake3(nonce)>"
     }
     ```
   - ペイロード本体や `x` は送信しない。`nonce` は辞書攻撃対策のブラインド用乱数。

4. **TEE 内証明生成**
   - TEE は `y` とハッシュ済みブロックリストから非包含証明を生成。
   - ゼロ知識回路は以下を証明:
     1. `oprf_output == F_k(x)`（TEE 内で再評価）
     2. `payload_commitment` が `x` と一致する（`nonce` を内部で再現）
     3. `y` が Merkle ツリーに含まれない（非包含パスの検証）
   - 出力: `proof`, `commitment`, `aux`（従来互換）に加え `oprf_output` と `nonce_commitment` を kapsule に連結。

5. **カプセル検証**
   - ノードは拡張された `PolicyCapsule` を受け取り、以下を検証:
     - `proof` が改訂回路の公開入力（`oprf_output`, `payload_commitment`, `nonce_commitment`, `merkle_root`）を満たす。
     - `payload_commitment` が実際の HTTP ペイロード先頭から計算した値と一致する。
     - 必要に応じて `nonce_commitment` とクライアントの `nonce` を突合（例: ペイロードヘッダに `x, nonce` を暗号化して送付）。
   - `proof` が通ればクライアントのターゲットはブロックリスト非該当であり、かつ PA 運用者には `x` が露出しない。

### API 拡張案
| メソッド | パス | 説明 |
|----------|------|------|
| `GET` | `/@hornet/directory` | 改訂メタデータと TEE アテステーションを返す |
| `POST` | `/@hornet/oprf` | 盲検された入力の VOPRF 評価を返す（TEE 内処理） |
| `POST` | `/@hornet/prove_privacy` | ペイロード非公開のまま証明を生成 |
| `POST` | `/@hornet/verify` | カプセル構造拡張に合わせ、公開入力の検証のみを行う（制御プレーン共通） |

### セキュリティと運用上の注意
- **アテステーション検証**: クライアントは TEE レポートが最新 CA で署名されていること、測定値がホワイトリストに載っていることを確認する。失敗時は接続拒否。
- **辞書攻撃対策**: OPRF の盲検と `nonce` 付きコミットメントを併用することで、PA 運用者が人気検索語の事前計算をしても照合できない。
- **証明検証キーの配布**: 既存の `verify` 実装は公開入力の追加に対応する必要があるが、回路構造自体は従来の Plonk 検証を再利用できる。
- **フェールセーフ**: いずれかのステップ（アテステーション検証/VOPRF/証明）が失敗した場合、拡張は接続をブロックし、利用者へ警告する。

### 実装ロードマップ（案）
1. VOPRF 実装とブロックリスト再構築（`F_k(b_i)` ベースの Merkle ツリー）。
2. TEE 対応プロセスの整備とリモートアテステーション検証コードの公開。
3. 新 `prove_privacy` 回路の実装（Commitment 一貫性＋非包含検証）。
4. `PolicyCapsule` と検証器のフォーマット拡張。
5. ブラウザ拡張へディレクトリ取得 / VOPRF / 証明要求の新フローを組み込み、旧仕様との後方互換モードを併設。

本案を採用すれば、PA 運用者は盲検された入力しか扱わず、アテステーション済み TEE 以外では機密データにアクセスできない。利用者は既存と同じ HTTP ナビゲーション体験のまま、検索語や訪問先を開示せずに検証付きアクセス制御を享受できる。
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
