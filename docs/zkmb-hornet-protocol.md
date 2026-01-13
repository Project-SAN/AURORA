# ZKMB‑HORNET Protocol (Poseidon KeyBinding, Exit Response) — Spec v2

This document is the **current protocol spec** for the AURORA/HORNET ZKMB system, rewritten to
match the implementation as of **2026‑01‑03**. It replaces the previous Zombie‑oriented draft.
Where applicable, it references Zombie/ZKMB as background, but the normative behavior is defined
here.

## 1. Goals and Design Summary

This protocol combines:
- **Per‑hop policy enforcement** (ZKMB‑style capsule verification at each router).
- **Onion routing (HORNET‑style AHDR/FS)** for forward and backward paths.
- **Key‑binding** via a ZK circuit, but **not tied to TLS**.  
  The default binding hash is **Poseidon** for ZK efficiency.
- **Exit behavior**: the exit hop **decrypts the forward payload**, **delivers it to a TCP service**,
  and **returns the response via the backward path**.

Key differences from Zombie/ZKMB:
- The network is **multi‑hop**; verification is **per hop**, not a single middlebox.
- There is no TLS transcript. **Key binding is protocol‑local** (Poseidon over salt+secret).
- The policy capsule is attached per packet.

## 2. Actors

- **PA (Policy Authority)**: publishes policy metadata (verifier blobs).
- **Source (Client)**: constructs capsules and forward/backward path headers.
- **Routers**: verify and forward; exit additionally **terminates** TCP and emits responses.
- **Destination**: a TCP service (HTTP in the reference workflow).

## 3. Cryptographic Primitives

### 3.1 Poseidon KeyBinding Hash (default)

The KeyBinding circuit and host computation use:

```
H_key = Poseidon( domain_tag, salt, secret )
```

- Poseidon arity: 2 inputs (salt, secret), width 3.
- Domain tag: `2^arity - 1` (standard Poseidon domain tag).
- Round constants: **Grain LFSR** per Poseidon spec (field size = 256 bits).
- MDS: deterministic Cauchy‑matrix construction.

Mode selection:
- Default: Poseidon (`HORNET_KEYBINDING_HASH=poseidon` or unset).
- Legacy: HKDF‑SHA256 (`HORNET_KEYBINDING_HASH=hkdf`).

### 3.2 HORNET AHDR / FS

Per hop, a node:
1) opens FS to obtain `(s_i, r_i, exp_i)`,
2) validates MAC,
3) strips AHDR to the next hop.

This is unchanged from the existing `packet/ahdr.rs` and `packet/core.rs` implementation.

### 3.3 Onion Payload Encryption

Forward direction:
```
source: build onion layers for payload tail
router: remove one layer (per hop)
```

Backward direction:
```
exit: adds onion layer for response
routers: add onion layer per hop (backward processing)
source: removes layers to recover response
```

Backward initial IV is derived as:
```
IV_back = PRG1(s_exit)
```
where `s_exit` is the per‑hop secret from the exit’s AHDR open.

## 4. Packet Structure and Wire Format

This section defines the packet/frame layout used between routers and
the payload structure used inside forward/backward packets.

### 4.1 TCP Frame (router‑to‑router)

```
struct Frame {
    u8  direction;   // 0 = Forward, 1 = Backward
    u8  pkt_type;    // 1 = Setup, 2 = Data
    u8  hops;        // path length
    u8  reserved;    // must be 0
    u8  specific[16]; // CHDR.specific (IV0 or EXP)
    u32 ahdr_len;    // LE
    u32 payload_len; // LE
    u8  ahdr[ahdr_len];
    u8  payload[payload_len];
}
```

This matches `encode_frame_bytes()` / `read_incoming_packet()` in `src/router/io.rs`.

### 4.2 CHDR (shared header)

```
struct Chdr {
    u8  pkt_type;    // Setup or Data
    u8  hops;        // number of hops in path
    u8  specific[16]; // Data: IV0, Setup: EXP (coarse)
}
```

### 4.3 AHDR (anonymous header)

AHDR is a fixed size of `rmax * C_BLOCK` bytes:

```
AHDR = FS_0 || gamma_0 || beta_0
```

Each hop peels one block (Algorithm 3 in `src/packet/ahdr.rs`).

#### Size constants

From `src/types.rs`:

```
FS_LEN = 32         // bytes
K_MAC  = 16         // bytes
C_BLOCK = 48        // FS_LEN + K_MAC
R_MAX  = 7          // default maximum path length
```

Thus:
```
AHDR_LEN = rmax * C_BLOCK
```

`rmax` must satisfy `1 <= hops <= rmax <= R_MAX` on both forward and backward paths.

### 4.4 Forward Payload

```
payload = PolicyCapsule || encrypted_tail
```

The encrypted tail is onion‑encrypted and peeled one layer per hop.

### 4.5 Backward Payload

```
payload = response_bytes
```

The exit constructs this payload from TCP response bytes and sends it
back through the backward AHDR.

#### Size limits and truncation

There is no explicit framing for response size beyond the frame header.
In the current implementation, the exit reads **until EOF or timeout** and
returns whatever bytes were read.

Operational constraints:
- Very large responses can inflate backward payloads and increase latency.
- Implementations SHOULD cap the response size (e.g., 64 KiB) and truncate
  any extra bytes.
- If truncation is applied, it MUST occur after TCP read and before backward
  onion processing.

### 4.6 Setup Payload

Setup packets reuse the same frame format. The payload is the setup
wire format in `src/setup/wire.rs` and carries directory metadata and
policy verifiers.

### 4.1 AHDR‑embedded PolicyMetadata TLV

```
u8  tlv_type   = 0xA1
u16 tlv_len    = |payload|
payload = PolicyMetadataPayload {
    policy_id: [u8; 32],
    version: u16,
    expiry: u32,
    flags: u16,
    verifier_blob_len: u32,
    verifier_blob: [u8; verifier_blob_len],
}
```

Each router installs the verifier during setup.

### 4.2 PolicyCapsule (payload prefix)

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

The capsule is followed by the encrypted tail.

#### Capsule version and part ordering

`capsule_version` is currently `0x01`.

Proof parts MUST appear in the following order:
```
1) KeyBinding proof (if required by policy flags)
2) Policy proof (always)
```

Future versions MAY add additional proof parts, but MUST preserve the
ordering of existing parts for backward compatibility.

#### Proof parts and verification order

The capsule can carry multiple proof parts. The current implementation
expects the following semantics:

1) **KeyBinding proof**
   - Purpose: bind `secret` to public `hkey` via Poseidon (or HKDF in legacy mode).
   - Public inputs: `salt`, `hkey` (both scalars).
   - Commitment field: `hkey` bytes (LE encoding of the scalar).

2) **Policy proof**
   - Purpose: prove the extracted target is not in the blocklist.
   - Public inputs: `target_scalar` (blocklist leaf scalar) and blocklist root.
   - Commitment field: `target_commitment` derived from the payload (see below).

Routers verify:
```
KeyBinding (if present)  -> Policy
```

Policy proof **must** be present for data packets with a policy capsule.
KeyBinding proof is required when `POLICY_FLAG_PCD` is set in metadata.

Auxiliary data (`aux_data`) carries policy‑specific public inputs
required by the verifier (e.g., Merkle root or non‑membership proof parts).

#### Public input encoding (Policy)

Blocklist leaf bytes are canonicalized and mapped to a scalar:
```
target_scalar = H_512(leaf_bytes) mod Fr
```
This is implemented by `scalar_from_leaf()` in `src/policy/blocklist.rs`.

The policy commitment placed in the capsule is:
```
target_commitment = H_512(payload_bytes) mod Fr
```
implemented by `payload_commitment()` in `src/policy/plonk.rs`.

The proof’s public input vector is:
```
[ target_scalar ]
```
and the verifier uses `aux_data` to obtain the blocklist root (and any
non‑membership path if required by the circuit).

#### CapsuleExtension TLV (aux_data)

`aux_data` uses the extension TLV format defined in `src/core/policy/extensions.rs`:

```
aux_data =
  "ZEXT" || version(1) || count(1) || [ext_0 ... ext_{count-1}]

ext_i =
  tag(1) || len(2, BE) || value(len)
```

Tags (current):
```
1  Mode(u8)
2  Sequence(u64, BE)
3  BatchId(u64, BE)
4  PrecomputeId(bytes)
5  PayloadHash([u8;32])
6  PrecomputeProof(bytes)
7  PcdState([u8;32])
8  PcdKeyHash([u8;32])
9  PcdRoot([u8;32])
10 PcdTargetHash([u8;32])
11 PcdSeq(u64, BE)
12 PcdProof(bytes)
13 SessionNonce([u8;32])
14 RouteId([u8;32])
```

KeyBinding proof parts MUST include:
```
SessionNonce (tag 13)
RouteId      (tag 14)
PcdKeyHash   (tag 8)   // hkey bytes
```

Policy proof parts SHOULD include:
```
Sequence (tag 2)
```

Other tags are reserved for PCD / precompute modes and are ignored if not used.

### 4.3 Forward Encrypted Tail (exit‑aware)

After the capsule:

```
canonical_leaf || ahdr_b_len || ahdr_b || app_request
```

- `canonical_leaf`: blocklist canonical bytes (tagged encoding, see §6).
- `ahdr_b_len`: u32 (LE) length of backward AHDR.
- `ahdr_b`: AHDR bytes for the backward path (rmax * c bytes).
- `app_request`: application payload (HTTP bytes in demo).

Routers remove onion layers until the exit sees this cleartext tail.

### 4.4 Backward Payload (exit‑constructed)

Backward payload is the response body as returned by the exit’s TCP connection.

## 5. Protocol Flow

### 5.1 Setup

1) **Directory fetch**: client receives `PolicyMetadata`.
2) **Setup packets** carry the TLV; each router registers the verifier.

### 5.2 KeyBinding Proof (Poseidon)

Inputs:
```
salt = H(policy_id, htarget, session_nonce, route_id)   // scalar
secret = sender secret (32 bytes)                       // witness
hkey = Poseidon(salt, secret)                           // public
```

Circuit enforces `Poseidon(salt, secret) == hkey`.

Public inputs:
- `salt` (as scalar)
- `hkey` (as scalar)

The resulting KeyBinding proof is included as a separate proof part inside the capsule.

#### Salt construction (KeyBinding)

`salt` is a **scalar** derived from:
```
policy_id || htarget || session_nonce || route_id
```

where:
- `policy_id`: 32 bytes from `PolicyMetadata`
- `htarget`: 32‑byte hash of the canonical leaf bytes
- `session_nonce`: 32 bytes (per session)
- `route_id`: 32 bytes derived from (entry, exit, target)

The implementation computes:
```
salt = H_512(policy_id || htarget || session_nonce || route_id) mod Fr
```

No TLV is used for these fields; the concatenation order is fixed.

#### session_nonce and route_id generation

`session_nonce`:
- 32 random bytes generated per session by the client.
- In the reference client, generated via a CSPRNG (`rand::RngCore`).

`route_id`:
- 32‑byte SHA‑256 hash over the forward route and target tuple:
  ```
  H( router_0.name || router_0.bind
   || router_1.name || router_1.bind
   || ...
   || ip_version || ip_bytes || target_port )
  ```
- `ip_version` is `0x04` or `0x06`.
- `target_port` is big‑endian.

This definition matches `compute_route_id()` in `src/bin/hornet_data_sender.rs`.

#### Public input encoding (KeyBinding)

Both `salt` and `hkey` are encoded as **little‑endian 32‑byte scalars**.
The circuit enforces the byte‑to‑scalar relation and exposes each scalar as a public input.

For Poseidon mode:
```
salt_scalar = from_bytes_le(salt_bytes)
secret_scalar = from_bytes_le(secret_bytes)
hkey_scalar = Poseidon(salt_scalar, secret_scalar)
```

For HKDF legacy mode:
```
salt_scalar = from_bytes_le(salt_bytes)
hkey_bytes = HKDF_SHA256(salt_bytes, secret_bytes)
hkey_scalar = from_bytes_le(hkey_bytes)
```

### 5.3 Forward Packet Construction (client)

1) Build **forward AHDR** for entry→middle→exit.
2) Build **backward AHDR** for exit→middle→entry→client.
3) Create plaintext tail:
   ```
   canonical_leaf || ahdr_b_len || ahdr_b || app_request
   ```
4) Build onion payload layers (forward direction).
5) Prepend PolicyCapsule.
6) Send to entry.

### 5.4 Per‑hop Forwarding

Each router:
1) Opens AHDR and validates MAC.
2) Verifies `PolicyCapsule` (drops on failure).
3) Removes one onion layer.
4) Forwards to next hop.

### 5.5 Exit Behavior (NEW)

When the exit detects that the next hop is `ExitTcp`:
1) **Parse the decrypted tail** to extract:
   - canonical leaf
   - `ahdr_b_len`
   - `ahdr_b`
   - `app_request`
2) **Send `app_request` to `(addr, port)` via TCP**.
3) Read the response bytes.
4) Construct backward packet:
   - `chdr.hops = forward hops`
   - `chdr.typ = Data`
   - `chdr.specific = PRG1(s_exit)` (derived from exit secret)
   - `ahdr = ahdr_b`
   - `payload = response bytes`
5) Call backward pipeline to add onion layers and forward.

### 5.6 Backward Path

Routers:
1) Open AHDR.
2) Add onion layer.
3) Forward to previous hop.

Client:
1) Removes onion layers using backward keys.
2) Outputs response bytes to the user.

## 6. Canonical Leaf Encoding (Blocklist)

Canonical leaf bytes are carried **in cleartext inside the decrypted tail**.

Encoding:

- Exact: `TAG_EXACT || len || bytes`
- Prefix: `TAG_PREFIX || len || bytes`
- CIDR: `TAG_CIDR || ip_version || prefix || network_bytes`
- Range: `TAG_RANGE || lenA || bytesA || lenB || bytesB`

Tags:
```
0x01 exact
0x02 prefix
0x03 cidr
0x04 range
```

Exit uses this to parse the first element and find the backward AHDR offset.

## 7. Error Handling

### Forward Path
- Invalid MAC / replay / policy violation → **drop**.

### Exit
- If tail parsing fails → **drop**.
- TCP connect error → **drop**.

### Backward
- Invalid MAC / replay → **drop**.

## 8. Configuration Knobs

Environment variables:

- `HORNET_KEYBINDING_HASH=poseidon|hkdf`  
  Poseidon is the default.

- `HORNET_KEYBINDING_LOG2` / `HORNET_KEYBINDING_CAPACITY`  
  Override PLONK capacity for keybinding circuit compilation.

## 9. Implementation Mapping

Key locations:
- KeyBinding circuit: `src/policy/plonk.rs`
- Poseidon core: `src/policy/poseidon.rs`
- Poseidon circuit: `src/policy/poseidon_circuit.rs`
- Forward pipeline: `src/node/forward.rs`
- Backward pipeline: `src/node/backward.rs`
- TCP I/O: `src/router/io.rs`
- Client build: `src/bin/hornet_data_sender.rs`

## 10. Known Limitations

- Exit reads raw TCP bytes and returns raw response bytes; **no HTTP parsing**.
- No batching or async verification.
- No TLS transcript binding.

## 11. Roadmap (future work)

1) Optional **HTTP parsing** at exit (streaming, content‑length).
2) Async verification with drop/penalty.
3) Batch proof support.
4) Full PCD chaining for multi‑hop proofs.

## 12. References (Background)

- Zombie: Middleboxes that Don’t Snoop (NSDI 2024)
- Zero‑Knowledge Middleboxes (USENIX Security 2022)
