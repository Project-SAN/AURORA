# ZKMB-HORNET Protocol Specification (Draft)

## Overview
ZKMB-HORNET extends HORNET routing with third-party-issued zero-knowledge proof capsules so that policy enforcement happens without disclosing the underlying policy to relays. The source attaches a `PolicyCapsule` that proves policy compliance, and each forwarding node verifies the capsule using `PolicyMetadata` delivered during setup. Packets that violate the policy are dropped without revealing the secret rules.

## Actors
- **Policy Authority (PA)**: Compiles the policy circuit to a Plonk-like SNARK and exposes an API for proof generation and metadata distribution.
- **Source Client**: Extracts policy-relevant data from plaintext traffic, obtains a proof capsule from the PA (or a local prover), and prepends it to outgoing payloads.
- **Forwarding Nodes**: HORNET relays that receive `PolicyMetadata` during setup and verify capsules on the data plane.
- **Destination**: The final hop that receives the decrypted payload after the capsule has been stripped.

## Data Structures
### PolicyMetadata TLV
Encoded inside the AHDR as TLV type `0xA1`.
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
- `policy_id`: identifies the circuit and version.
- `verifier_blob`: raw bytes from `dusk-plonk`’s `composer::Verifier::to_bytes()` (verification key, openings, public input layout, transcript type).
- `expiry`: UNIX timestamp (seconds). Nodes should request re-setup when expired.

### PolicyCapsule Payload
Prepend this structure to the application payload:
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
- `proof`: Plonk proof (hundreds of bytes to 1 KB).
- `commitment`: commitment of the plaintext or TLS transcript (Poseidon/BLAKE3, etc.).
- `aux_data`: additional public inputs, e.g., session IDs or time nonces.
The capsule is followed immediately by the actual application payload.

## Protocol Flow
1. **Setup**
   - The source fetches routing data and `PolicyMetadata` from the directory.
   - During AHDR construction, it embeds the metadata TLV. Each node parses the TLV while decrypting AHDR, then registers `policy_id → verifier`.

2. **Proof Generation**
   - The source extracts the policy-relevant field (e.g., HTTP Host) from the payload, hashes it, and feeds it into the circuit.
   - The client calls the proof API (`POLICY_PROOF_URL`) with `{policy_id, payload_hex, aux_hex}` and receives proof/commitment JSON, or locally runs the same Plonk prover (`policy-plonk` + `policy-client`).
   - The PA returns the Plonk proof; on error it responds with HTTP 4xx and `non_compliant`.

3. **Data Transmission**
   - The source builds the `PolicyCapsule` and prepends it to the payload.
   - `hornet::source::build_data_packet` assembles AHDR/CHDR and dispatches the onion packet.

4. **Forwarding Node**
   - `process_data_forward` removes an onion layer, decodes the capsule, and looks up the verifier via `policy_id`.
   - It runs `verify(proof, [commitment, aux])`.
   - Success: drop the capsule bytes and forward the remaining payload.
   - Failure: return `Error::PolicyViolation`, drop the packet, and log only `policy_id` + result.

5. **Destination**
   - The last hop receives only the application payload and handles it per normal HORNET delivery rules.

## PA API
```
POST /plonk/prove
Headers:
  Authorization: Bearer <token>
Body (JSON/CBOR):
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
- Proofs are only returned on success; failures use HTTP 4xx with `non_compliant`.
- Apply rate limiting and auditing to prevent policy probing.

## Error Handling
- `Error::PolicyViolation`: missing capsule, policy mismatch, or proof failure.
- `Error::Expired`: metadata expired.
- PI collection: log `policy_id`, peer, timestamp only (no plaintext reason).

## Security Requirements
- Plonk proofs rely on a universal SRS (single trusted setup).
- Rotate `policy_id` when updating circuits; stop issuing proofs for old IDs.
- Clients must authenticate to the API; unauthenticated clients cannot send traffic.
- Nodes must not allow capsule verification to be disabled; packets without proofs must be dropped.

## Implementation Roadmap
1. Implement `PolicyCapsule`/`PolicyMetadata` types + codecs.
2. Embed metadata TLVs into AHDR; implement node registry.
3. Hook capsule extraction/verification into `process_data_forward`.
4. Integrate Plonk verifier (possibly via FFI) and proof service API.
5. Testing: capsule parsing, success/failure paths, expiry handling.

## Use Cases
- Privacy-preserving filtering of illegal/phishing content.
- Controlled access to B2B portals or enterprise APIs.
- Remote compliance (e.g., TLS transcript inspections).

## Open Questions
- Viable Plonk verifier for `no_std`.
- API SLAs/NFRs (latency, availability).
- Capsule chaining for multiple simultaneous policies.
- Rate limiting / auditing to withstand failure-oracle attacks.

## Implementation Architecture (hornet crate)
The Rust implementation follows a functional domain modeling style and is split into three layers—`core`, `application`, and `adapters`. This keeps the reusable library surface (`no_std + alloc`) independent from I/O-heavy components such as Actix or Plonk backends.

### Core layer (`src/core`)
- Pure domain layer that depends only on `alloc`. It owns `PolicyCapsule`, `PolicyMetadata`, TLV codecs, and `PolicyRegistry`.
- `PolicyRegistry` keeps the `policy_id → PolicyMetadata` map and delegates validation to the `CapsuleValidator` trait. `enforce(payload, validator)` returns `(PolicyCapsule, consumed_len)` while preserving determinism.
- All functions are side-effect free and return `crate::types::Error::{Length, PolicyViolation}` for callers to handle.

### Application layer (`src/application`)
- **SetupPipeline** orchestrates how metadata TLVs are installed. `RegistrySetupPipeline` reuses `policy::plonk::ensure_registry()` to hydrate verifier blobs, and `setup::node_process_with_policy()` accepts any pipeline implementation.
- **ProofPipeline** transforms `ProveInput { policy_id, payload, aux }` into a `PolicyCapsule`, surfacing `ProofError::{PolicyNotFound, Extraction, Prover}`. `PolicyAuthorityState` (Plonk policy + extractor) implements the trait and is injected as `Arc<dyn ProofPipeline + Send + Sync>`.
- **ForwardPipeline** abstracts enforcement on the data plane. `RegistryForwardPipeline` delegates to `PolicyRegistry::enforce()` and returns `Option<(PolicyCapsule, usize)>`, allowing capsule-free flows to pass through unchanged.

### Adapters layer (`src/adapters`)
- **plonk::validator** provides `PlonkCapsuleValidator`, caching per-policy `PlonkVerifier` instances (in a `BTreeMap`) and checking proof/commitment lengths (`Proof::SIZE`, `BlsScalar::SIZE`).
- **actix** wires HTTP handlers (feature `api`). `POST /prove` decodes `payload_hex` into `ProveInput` and calls the injected `ProofPipeline`; `POST /verify` derives metadata, populates a fresh `PolicyRegistry`, and validates capsules via `PlonkCapsuleValidator`.
- **CLI/bin** (`src/main.rs`) shares `PolicyAuthorityState` via `Arc`, registering both `web::Data<PolicyAuthorityState>` (directory access) and `web::Data<Arc<ProofPipelineHandle>>` (proof generation) so binaries and libraries use the same pipeline.

### Node/Runtime
- `NodeCtx` carries an optional `PolicyRuntime { registry, validator, forward }`; both forward/backward paths call `ForwardPipeline::enforce()` and fall back to `PolicyCapsule::decode()` when no registry is configured.
- `setup::install_policy_metadata()` parses TLVs and pushes them through `SetupPipeline`, keeping the TLV format reusable even if the verifier backend changes.
- Validators only need to implement `CapsuleValidator`, making them pluggable across setup/proof/forward flows.
- Experimental router runtime (`src/router`) now includes:
  - `router::runtime::RouterRuntime`: wires policy state + time provider + replay/forward factories into packet processing loops.
  - `router::io::TcpPacketListener` / `TcpForward`: reference TCP transport that consumes/produces fixed-length frames and resolves next hops from `routing::RouteElem` TLVs.
  - `router::storage::FileRouterStorage`: persists `PolicyMetadata` and node secrets (`Sv`) as JSON so routers can restore policy state on restart.
  - `router::sync::client`: pluggable directory client (`ureq` HTTP or local file) that fetches signed announcements and applies them to the `Router`.

### Testing and mocks
- Shared mocks live under `tests/suppert/`. `tests/pipeline.rs` uses them to exercise setup/install and forward enforcement flows independently of Actix/Plonk internals.
- End-to-end tests in `src/api/prove.rs` rely on the same dependency injection (WebData + `ProofPipeline`) as production.

## Appendix: Privacy-Preserving Remote Proof Protocol
The current `POST /prove` endpoint requires the client to submit plaintext targets (search terms, HTTP Host headers) to the PA, exposing them to operators. The revised proposal satisfies:
1. Clients never reveal plaintext targets to the PA.
2. The PA remains responsible for proving non-membership against the blocklist.
3. Forwarding nodes continue to enforce policies via `PolicyCapsule` verification only.
4. Extra crypto is confined to the client side, enabling lightweight implementations (e.g., browser extensions).

TEE-based attestation and Verifiable Oblivious PRF (VOPRF) are combined so that operators cannot observe targets while the PA proves policy compliance.

### New Components
- **Attested TEE**: The `/prove` endpoint runs inside an enclave; clients verify quotes/binary measurements before proceeding.
- **VOPRF key pair**: The PA evaluates `y = F_k(x)` without learning the input.
- **Hashed blocklist**: Precompute `F_k(b_i)` for each blocklist entry and commit via a Merkle tree.
- **Payload commitments**: Clients commit to payload-derived values (Poseidon/BLAKE3) and include a nonce.

### Revised workflow
1. **Directory access**
   - `GET /@hornet/directory` returns `{policy_id, prove_url, verify_url, voprf params, tee_quote, binary_measurement, merkle_root}`.
   - Clients verify the TEE quote, measurement, and public parameters before trust is established.

2. **VOPRF evaluation**
   - Client blinds `x` to obtain `α = Blind(x)` and sends it to `POST /@hornet/oprf`.
   - TEE returns `β = Evaluate_k(α)`.
   - Client derives `y = Finalize(x, β)`; the PA never learns `x`.

3. **Privacy-preserving proof request**
   - Client sends:
     ```json
     {
       "policy_id": "<hex>",
       "payload_commitment": "<poseidon(x || nonce)>",
       "payload_hint": "<hashed HTTP metadata>",
       "oprf_output": "<hex(y)>",
       "nonce_commitment": "<blake3(nonce)>"
     }
     ```
   - Plaintext payload and `x` are never transmitted; the nonce thwarts dictionary attacks.

4. **TEE proof generation**
   - The enclave proves:
     1. `oprf_output == F_k(x)` (re-evaluated inside the TEE).
     2. `payload_commitment` matches `x` reconstructed from payload/nonce.
     3. `y` is not in the Merkle-committed blocklist.
   - Outputs: `proof`, `commitment`, `aux`, and the new public inputs (`oprf_output`, `nonce_commitment`) concatenated into the capsule.

5. **Capsule verification**
   - Nodes verify the extended capsule by checking the proof against the new public inputs and recomputing `payload_commitment` from the packet.
   - Optionally, they compare `nonce_commitment` with encrypted payload hints.
   - Success guarantees the target is not blocklisted, without exposing `x` to PA operators.

### Additional endpoints
| Method | Path                  | Description                                           |
|--------|----------------------|-------------------------------------------------------|
| GET    | `/@hornet/directory` | Returns metadata plus TEE attestation artifacts        |
| POST   | `/@hornet/oprf`      | Evaluates blinded inputs inside the TEE               |
| POST   | `/@hornet/prove_privacy` | Issues proofs without revealing payload plaintext |
| POST   | `/@hornet/verify`    | Verifies capsules given the new public inputs         |

### Operational notes
- **Attestation**: Clients must validate the quote signer and whitelist binary measurements; otherwise they abort.
- **Dictionary resistance**: Blind OPRF plus nonce commitments prevent the PA from precomputing popular targets.
- **Verifier updates**: The existing verification path is extended with the additional public inputs but still relies on Plonk.
- **Fail-safe**: Errors at any step (attestation, OPRF, proof) cause the connection to abort and notify the user.

### Suggested roadmap
1. Implement VOPRF and rebuild the blocklist as `F_k(b_i)` Merkle roots.
2. Ship TEE binaries with attestation verification tooling.
3. Extend the Plonk circuit for commitment consistency + non-inclusion proofs.
4. Extend `PolicyCapsule` and verifier formats with the new public inputs.
5. Update clients/browser extensions to follow the new flow while keeping a backward-compatible mode.

### Outstanding Engineering Tasks
The current Rust prototype ships an experimental router runtime (directory sync + TCP forwarding + persistence). To reach a production-ready HORNET router, the following work remains:

1. **Setup Packet Handling & Key Management**
   - Implement full `setup::node_process_with_policy` integration inside the router so setup packets update `Si/Fs/CHDR` state, and persist those secrets (not just `Sv`) via `router::storage`.
   - Restore the complete setup state (policy registry + node keys) on restart.
2. **Secure Networking**
   - Replace the current plaintext TCP frame with an authenticated/ encrypted transport (e.g., TLS or Noise) and support multiple concurrent connections with backpressure.
   - Add node-to-node handshake/identity verification to prevent spoofing or replay.
3. **Observability & Control Plane**
   - Scheduled directory sync with exponential backoff, structured logging, and metrics (policy violations, replay drops, forward success rates).
   - CLI/configuration for network bindings, storage paths, and security parameters.
4. **Routing Integration**
   - Use real routing descriptors (multiple `RouteElem`s per segment), maintain per-hop position, and update routing tables dynamically rather than assuming a single next-hop segment.
5. **Testing**
   - End-to-end integration tests covering setup→data flow across multiple nodes, persistence across restarts, and error conditions (expired metadata, invalid proofs, replay attacks).

These tasks are tracked in the Rust repo and should be completed before treating the router as production-ready.
