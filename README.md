# AURORA (Attested Unlinkable Routing with Overlay Relay Assurance)

AURORA is the renamed, experimental Rust implementation of a verifiable onion-routing protocol that fuses zkMB-style policy capsules with HORNET-inspired packet formats. The crate name remains `hornet` for now, but the protocol and project branding are AURORA.

## Project Layout

- `src/` – core AURORA transport, policy client, and demo sender implementation
- `docs/zkmb-hornet-protocol.md` – detailed protocol draft (legacy filename) covering actors, data formats, and verifier expectations
- `src/policy/` – policy capsule types, Merkle blocklist utilities, JSON loader, and proof-client wiring
- `kernel/` – UEFI-based experimental kernel + userland runtime (no_std, virtio-net, smoltcp)

## Kernel / Userland (experimental)

UEFI 起動の実験カーネルでは、ブート時に UEFI `GetTime` を取得して Unix epoch 秒に変換し、以降は tick から積算して返す簡易時刻 syscall を提供します。

- `SYS_TIME_EPOCH` (syscall番号 16): epoch 秒（UTC）を返します  
  - `GetTime` が取得できない/無効な場合は **`u64::MAX`** を返します
  - UEFI が `time_zone` 未指定 (`None`) の場合は **UTC扱い**にしています

## AURORA Overview

AURORA embeds a `PolicyCapsule` at the beginning of each payload. A sender obtains the capsule from a Policy Authority (PA) without revealing the underlying policy by proving **non-membership** against a Merkle-committed blocklist. Forwarding nodes validate the capsule with the `PolicyMetadata` that travels in the anonymous header (TLV type `0xA1`). If verification fails, the node drops the packet with `Error::PolicyViolation`.

See `docs/zkmb-hornet-protocol.md` for the full flow (setup → proving → forwarding) and the PA REST contract.

## Demo Sender

The binary in `src/main.rs` spins up a two-hop UDP circuit, requests a policy capsule, and injects it into the payload before transmission. It is primarily a **sender demo**; nodes use the library APIs directly and do not expose CLI tunables yet.

### Prerequisites

- Rust toolchain (`cargo build` / `cargo run`)
- Optional features:
  - `policy-client` – enable HTTP proof client and Merkle witness pre-processing
  - `policy-plonk` – enable local Plonk prover (falls back to HTTP API when unavailable)

### Running the Demo

```bash
cargo run --features policy-client
```

- If `POLICY_BLOCKLIST_JSON` is **unset**, the demo writes a temporary JSON blocklist containing `blocked.example` and points the preprocessor to it.
- Set `POLICY_BLOCKLIST_JSON=/path/to/blocklist.json` to override with your own Merkle blocklist input (see `Blocklist::from_json` schema in `src/policy/blocklist.rs`).
- Set `POLICY_PROOF_URL=https://authority.example/plonk/prove` to forward proof requests to a live Policy Authority. Without it, the sender falls back to the legacy path and transmits without a remote proof.

### Typical Workflow

1. Prepare or point to a blocklist JSON that lists disallowed domains/IP ranges.
2. Export `POLICY_PROOF_URL` so the sender knows where to POST proofs.
3. Run the demo with `policy-client` enabled – the preprocessor extracts the target (e.g., HTTP Host), computes Merkle neighbour paths from the blocklist, and submits everything to the PA.
4. Forwarding nodes verify the capsule using the metadata propagated during setup.

## クライアント主導の証明送信デモ

最新の PoC ではクライアントがローカルでゼロ知識証明を生成し、`/verify` エンドポイントへ送信してポリシー適合性を確認できます。

1. 別ターミナルで PA を起動:
   ```bash
   cargo run
   ```
2. クライアントから証明を生成して送信（例では `safe.example` へのアクセスを想定）:
   ```bash
   cargo run --bin zkmb_client -- safe.example
   ```

`POLICY_BLOCKLIST_JSON` で使用するブロックリスト JSON を指定できます。PA の URL を変更したい場合は `POLICY_AUTHORITY_URL` をエクスポートしてください（デフォルトは `http://127.0.0.1:8080`）。ブロックリストに含まれるホストを指定すると、クライアント側で証明生成が失敗しポリシー違反として扱われます。

## AURORA Router Runtime (実験的)

`hornet_router` バイナリ（名称は互換のため暫定）はライブラリ内のルータ機能をテストするための最小実装です。ディレクトリアナウンスを適用した後、TCP 上でパケットを受信し `RouterRuntime` を通じて検証→転送を行います。

### 前提と制限
- `std` feature を有効にしてビルドします（`cargo run --features "std" --bin hornet_router`）。
- ディレクトリアナウンスは `setup::directory::to_signed_json` が出力する JSON を想定しており、署名検証には共有シークレットが必要です。
- 受信パケットは独自フレーム形式で `TcpPacketListener` が読み取ります。`LoopbackForward` ではなく `TcpForward` が実ホストへ送信します。
- `RoutingSegment` は暫定的に ASCII 文字列 (`"host:port"`) として扱う簡易実装です。正式な TLV → next-hop 変換は今後実装予定です。

### ディレクトリファイルを用意する
```
use hornet::setup::directory::{DirectoryAnnouncement, to_signed_json};
use hornet::policy::PolicyMetadata;

let mut announcement = DirectoryAnnouncement::new();
announcement.push_policy(PolicyMetadata { ... }); // 署名対象
let json = to_signed_json(&announcement, b"shared-secret", 1_700_000_000).unwrap();
std::fs::write("directory.json", json).unwrap();
```

`hornet_router` は起動時に `directory.json` を読み取り、署名を検証したうえで `Router` に登録します。共有シークレットは `RouterConfig::new("https://example.com", "shared-secret")` で指定します。

### パケットフレーム形式
`TcpPacketListener` は以下のレイアウトでフレームを期待します。

| Field | サイズ | 説明 |
|-------|--------|------|
| direction | 1 byte | `0` = forward, `1` = backward |
| packet_type | 1 byte | `0` = setup, `1` = data |
| hops | 1 byte | CHDR.hops |
| reserved | 1 byte | 現状未使用 (送信時は `0`) |
| CHDR specific | 16 bytes | データフレーム nonce など |
| AHDR length | u32 LE | AHDR バイト列の長さ |
| payload length | u32 LE | ペイロード長 |
| AHDR bytes | 可変 | `Ahdr.bytes` |
| payload bytes | 可変 | `payload` |

Forward 際には、同じ形式で `direction=0`（forward）として次ホップに送信します。`RoutingSegment` は `routing::RouteElem` TLV シリアライズを想定しており、`TcpForward` は先頭の `RouteElem::NextHop` / `ExitTcp` から IP+ポートを引き当てて接続先を決定します（IPv4/IPv6 双方対応）。

### 実行例
1. ディレクトリ JSON を準備し、共有シークレットを `RouterConfig` に合わせる。
2. `router_state.json`（デフォルト）に保存されている `PolicyMetadata`/`Sv` があれば自動で復元される。初回起動時は空ファイルで問題ない。
3. リスナを起動:
   ```bash
   cargo run --features "std" --bin hornet_router
   ```
4. 別プロセスから上記フレーム形式で TCP (`127.0.0.1:7000`) にパケットを送信すると、`RouterRuntime` がポリシー検証を行い `RoutingSegment` 内の `RouteElem` で指定された次ホップへ転送します。

> **注意:** このルータは研究用途のプレビルドです。永続化・本格的なルーティングテーブル・セットアップパケット処理は未実装であり、ネットワーク仕様も今後の改修で変更される可能性があります。

## Further Reading

- `docs/zkmb-hornet-protocol.md` – end-to-end overview of AURORA (legacy filename), including TLV formats, API schema, and roadmap items.
- `src/policy/blocklist.rs` – JSON schema, canonical leaf encoding, and Merkle proof helpers used by the client.
- `src/policy/client.rs` – proof preprocessor, HTTP client, and non-membership witness serialization.
