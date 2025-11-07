# HORNET

HORNET is an experimental Rust implementation of the High-speed Onion Routing at the Network Layer protocol, extended with **ZKMB-HORNET** support for zero-knowledge policy capsules.

## Project Layout

- `src/` – core HORNET transport, policy client, and demo sender implementation
- `docs/zkmb-hornet-protocol.md` – detailed protocol draft covering actors, data formats, and verifier expectations
- `src/policy/` – policy capsule types, Merkle blocklist utilities, JSON loader, and proof-client wiring

## ZKMB-HORNET Overview

ZKMB-HORNET embeds a `PolicyCapsule` at the beginning of each payload. A sender obtains the capsule from a Policy Authority (PA) without revealing the underlying policy by proving **non-membership** against a Merkle-committed blocklist. Forwarding nodes validate the capsule with the `PolicyMetadata` that travels in the anonymous header (TLV type `0xA1`). If verification fails, the node drops the packet with `Error::PolicyViolation`.

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

## Further Reading

- `docs/zkmb-hornet-protocol.md` – end-to-end overview of ZKMB-HORNET, including TLV formats, API schema, and roadmap items.
- `src/policy/blocklist.rs` – JSON schema, canonical leaf encoding, and Merkle proof helpers used by the client.
- `src/policy/client.rs` – proof preprocessor, HTTP client, and non-membership witness serialization.
