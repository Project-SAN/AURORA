# Router Setup Integration Plan

## Current gaps
- `bin/hornet_router` treats incoming setup frames as plain `{Sv, Si?}` blobs (`handle_setup_packet`) and never invokes `setup::node_process_with_policy`, so policy TLVs carried in AHDR are ignored.
- `router::storage::StoredState` only persists policies + `Sv` (+ optional `Si`), leaving `Fs`, CHDR metadata (EXP), and per-hop symmetric context undefined after restart.
- There is no on-wire representation for `setup::SetupPacket` (Sphinx header + FS payload + policy TLVs), which prevents routers from decoding real setup packets built by sources.

## Proposed phases
1. **Audit & data-model prep – _done_**
   - Identified the router state we must retain and introduced `RouterSecrets` + JSON persistence that now carries `{Sv, node_secret, policies, routes}`.

2. **Wire format + decoding – _done_**
   - Added `sphinx::encode_header/decode_header`, `packet::Payload::from_bytes`, and `setup::wire::{encode,decode}` with tests so setup frames can move between transport and in-memory types.

3. **Router integration – _in progress_**
   - `Router` now stores directory routes, `handle_setup_packet` decodes real Sphinx frames, installs metadata via `RegistrySetupPipeline`, and persists the refreshed registry/secrets.
   - Follow-ups: forward the mutated setup packet to the next hop, rotate secrets instead of static defaults, and cover restart flows once encrypted transport + route updates land.
