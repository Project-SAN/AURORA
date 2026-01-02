# Zombie-based ZKMB-HORNET Protocol (Draft)

## Purpose
This document rewrites the AURORA/HORNET ZKMB protocol using **Zombie: Middleboxes that Don’t Snoop (NSDI 2024)** as the primary reference. Zombie itself builds on **Zero-Knowledge Middleboxes (ZKMBs, USENIX Security 2022)** and refines the architecture with precomputation, asynchronous verification, and batching. This draft adapts Zombie’s protocol phases to the current AURORA codebase, and explicitly notes where the implementation diverges from Zombie’s TLS-focused design.

## High-level Mapping (Zombie → AURORA)
Zombie is defined around TLS 1.3 and a single middlebox. AURORA is onion routing with per-hop enforcement. The mapping is:
- **Zombie client** → AURORA sender + policy client (`src/bin/hornet_sender.rs`, `src/policy/client.rs`)
- **Zombie middlebox** → AURORA forwarding node (`src/node/forward.rs`, `src/router/*`)
- **Zombie policy distribution** → AURORA directory/setup TLV (`src/setup/directory.rs`, `src/setup.rs`)
- **Zombie proof verifier** → `PolicyRegistry` + `CapsuleValidator` (`src/core/policy/registry.rs`, `src/adapters/plonk/validator.rs`)
- **Zombie proof service / authority** → `PolicyAuthorityState` + HTTP API (`src/api/prove.rs`, `src/main.rs`)
- **Zombie TLS key-commitment** → *No direct equivalent* in AURORA (see “Architectural differences”)

## Actors
- **Policy Authority (PA)**: Defines policy circuits and produces `PolicyMetadata` (verifier data). In AURORA this is the `/prove` service and policy registry in `src/api/prove.rs`.
- **Source Client**: Extracts policy-relevant data from plaintext and obtains a `PolicyCapsule` proof before sending (or in a future asynchronous mode, soon after sending).
- **Forwarding Nodes (Middleboxes)**: Verify capsules on the data plane; drop on failure.
- **Destination**: Receives payload after the capsule is stripped by the last hop.

## Zombie Protocol Phases (Adapted)
Zombie organizes ZKMBs into three phases. We keep the same terminology and align each phase to AURORA.

### 1) Policy setup (Zombie: SP distribution)
**Zombie**: The middlebox sends the policy computation SP to clients when they join the network. This lets clients form proofs bound to the policy.

**AURORA adaptation**:
- The source fetches a directory announcement containing `PolicyMetadata`.
- Metadata is embedded in the AHDR as a TLV (`POLICY_METADATA_TLV`), and forwarding nodes register `policy_id → verifier` during setup.

Relevant code:
- `src/setup/directory.rs` (directory announcement, TLV encode/decode)
- `src/setup.rs` (attach/install policy TLVs)
- `src/core/policy/metadata.rs` (binary format)

### 2) Session/key setup (Zombie: SE.1 commit)
**Zombie**: The client commits to a TLS session key `K` and proves correctness of that commitment, enabling later proofs about ciphertext.

**AURORA divergence**:
- There is **no TLS key-commitment phase** in AURORA.
- Instead, the `PolicyCapsule` is attached directly to each payload, and verification is done per-packet without referencing a TLS handshake transcript.
- Any “session” assumptions must be encoded as public inputs inside the capsule, if needed.

### 3) Per-packet enforcement (Zombie: SE.2 + SP)
**Zombie**: For each ciphertext `C_i`, the client sends `C_i` and a proof `π_i` that the plaintext both decrypts under `K` and satisfies policy `SP`.

**AURORA adaptation**:
- The sender prepends a `PolicyCapsule` to the payload.
- Forwarding nodes parse the capsule, look up `policy_id`, and verify it with the installed verifier.
- On success, the capsule bytes are stripped and the remaining payload continues.

Relevant code:
- `src/core/policy/capsule.rs` (decode/peel)
- `src/core/policy/registry.rs` (enforce)
- `src/node/forward.rs` (data-plane policy check)

## Data Structures (AURORA wire format)
AURORA keeps compact on-wire structures; these are the current formats.

### PolicyMetadata TLV (AHDR)
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
- `policy_id`: identifies a policy circuit and version.
- `verifier_blob`: backend-specific verifier bytes (currently Plonk).

### PolicyCapsule (payload prefix)
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
- The capsule is followed immediately by application payload bytes.
- `commitment` and `aux_data` are public inputs used by the verifier.

## Zombie Enhancements and AURORA Status
Zombie introduces three performance techniques. The AURORA codebase does **not** implement these yet; they are included here as design targets.

### Precomputation
**Zombie**: Split encryption proof into `SE.2a` (pad/commitment) and `SE.2b` (message-dependent), allowing the expensive part to be computed during idle time.

**AURORA status**: Not implemented.
- Potential adaptation: precompute a commitment/proof on a fixed-size payload prefix (or encrypted payload structure), then combine with per-message proof.

### Asynchronous verification
**Zombie**: Middlebox forwards ciphertext immediately and verifies the proof later; invalid proofs trigger policy actions.

**AURORA status**: Not implemented.
- Would require buffering and replay/penalty logic in routers (`src/router/*`) and changes to forward pipeline semantics.

### Batching
**Zombie**: Client batches multiple proofs into a single proof, amortizing verifier cost.

**AURORA status**: Not implemented.
- Would require protocol changes to allow capsules to reference a batch proof and to map packets to batch members.

## Policy Classes: Regex-based policies
Zombie contributes a compiler pipeline for regular-expression policies over payloads (e.g., DLP). This is a major feature vs. the earlier ZKMB work.

**AURORA status**:
- The current implementation focuses on blocklist-style policies and hostname extraction (see `src/policy/blocklist.rs`, `src/policy/extract.rs`).
- Regex-based policies are not implemented; adding them would require a policy compiler stage and a proof backend that matches Zombie’s regex arithmetization.

## Protocol Flow (AURORA, today)
1. **Directory fetch**: client receives `PolicyMetadata` from the directory announcement.
2. **Setup**: metadata TLV is embedded in AHDR; nodes install verifier blobs while decrypting AHDR.
3. **Proof generation**: client extracts policy-relevant data and obtains a `PolicyCapsule` (local Plonk or via PA HTTP).
4. **Data**: client prepends the capsule to payload and sends the packet.
5. **Forwarding**: nodes verify capsule; on failure return `Error::PolicyViolation` and drop.

## PA API (current implementation)
AURORA exposes HTTP endpoints under the `api` feature. The key flow is:
- `POST /prove`: client sends `{policy_id, payload_hex, aux_hex}` and receives `{policy_id, proof, commitment, aux}` (exact JSON shape in `src/api/prove.rs`).
 - `POST /prove_batch`: client sends `{items: [{policy_id, payload_hex, aux_hex}, ...]}` and receives an array of proofs.
 - `POST /precompute`: client sends the same payload as `/prove` and receives a `precompute_id` that can be used later.
 - `POST /prove_precomputed`: client sends `{policy_id, precompute_id}` and receives the stored proof.

## Architectural Differences from Zombie
These differences are intentional and should be kept in mind when implementing Zombie-inspired features:
- **Transport**: Zombie targets TLS 1.3 and leverages TLS internals; AURORA is onion routing and does not track TLS sessions.
- **Per-hop enforcement**: Zombie has a single middlebox; AURORA verifies at each forwarding node.
- **Key commitment**: Zombie binds proofs to TLS key material; AURORA binds proofs to payload/aux inputs only.
- **Asynchrony**: Zombie’s async mode assumes local middlebox control; AURORA would need node coordination and storage guarantees.

## Open Tasks (Zombie-aligned roadmap)
1. Define how to represent Zombie-style key commitments in AURORA (if needed at all).
2. Extend `PolicyCapsule` to support asynchronous/batched proofs (new fields, or a companion control plane).
3. Design a regex policy compiler pipeline (likely in `src/policy/` with a new backend).
4. Add router buffering/state to support asynchronous verification safely.

## References
- Collin Zhang et al., **Zombie: Middleboxes that Don’t Snoop**, NSDI 2024.
- Paul Grubbs et al., **Zero-Knowledge Middleboxes**, USENIX Security 2022.
