# Demo Router Assumptions

The current `hornet_router` binary implements a simplified setup/key handling flow for demonstration purposes:

- Setup packets reuse the same TCP framing as data packets (`PacketType = 0x01`).
- The setup payload layout is fixed:
  1. bytes 0..15   – new `Sv` (coarse-grained session secret)
  2. bytes 16..31  – optional `Si` (per-hop key). If fewer than 32 bytes are present, the `Si` update is skipped.
- On receipt, the router updates its in-memory `Sv`, persists `{policies, Sv, Si}` to `router_state.json`, and applies the new secret to subsequent data packets.
- No Sphinx header processing or FS derivation is performed in this demo. Integrating real `setup::node_process_with_policy` is tracked as a future task (see `docs/zkmb-hornet-protocol.md` – Outstanding Engineering Tasks).

> **Important:** This is intentionally minimal and not wire-compatible with full HORNET setup packets. Containerlab scenarios should send the above layout when simulating setup flows.
