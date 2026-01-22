use crate::policy::{PolicyCapsule, PolicyId, PolicyMetadata, PolicyRegistry, VerifierEntry};
use crate::policy::blocklist::{LeafBytes, MAX_BLOCKLIST_ENTRIES};
#[cfg(feature = "regex-policy")]
use crate::policy::blocklist::ValueBytes;
use crate::policy::poseidon::poseidon_hash2;
use crate::policy::poseidon_circuit::poseidon_hash2_circuit;
use crate::policy::bytes::Byte;
use crate::core::policy::{ProofKind, ProofPart};
use crate::core::policy::metadata::POLICY_FLAG_PCD;
use crate::types::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use dusk_bytes::Serializable;
use dusk_plonk::prelude::{
    BlsScalar, Circuit, Compiler, Composer, Constraint, Error as PlonkError, Prover,
    PublicParameters,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256, Sha512};
use spin::Mutex;

#[derive(Clone, Default)]
struct BlocklistCircuit {
    target: BlsScalar,
    inverses: Vec<BlsScalar>,
    block_hashes: Vec<BlsScalar>,
}

impl BlocklistCircuit {
    fn new(target: BlsScalar, inverses: Vec<BlsScalar>, block_hashes: Vec<BlsScalar>) -> Self {
        Self {
            target,
            inverses,
            block_hashes,
        }
    }
}

impl Circuit for BlocklistCircuit {
    fn circuit<C>(&self, composer: &mut C) -> core::result::Result<(), PlonkError>
    where
        C: Composer,
    {
        let witness_target = composer.append_witness(self.target);
        for (blocked, inverse) in self.block_hashes.iter().zip(self.inverses.iter()) {
            let inverse_witness = composer.append_witness(*inverse);
            let diff = composer.gate_add(
                Constraint::new()
                    .left(1)
                    .a(witness_target)
                    .constant(-*blocked),
            );
            let product = composer.gate_mul(Constraint::new().mult(1).a(diff).b(inverse_witness));
            composer.assert_equal_constant(product, BlsScalar::one(), None);
        }
        composer.assert_equal_constant(witness_target, BlsScalar::zero(), Some(self.target));
        Ok(())
    }
}

#[derive(Clone, Default)]
struct KeyBindingCircuit {
    secret: [u8; 32],
    salt_bytes: [u8; 32],
    salt: BlsScalar,
    hkey: BlsScalar,
}

impl KeyBindingCircuit {
    fn new(
        secret: [u8; 32],
        salt_bytes: [u8; 32],
        salt: BlsScalar,
        hkey: BlsScalar,
    ) -> Self {
        Self {
            secret,
            salt_bytes,
            salt,
            hkey,
        }
    }
}

impl Circuit for KeyBindingCircuit {
    fn circuit<C>(&self, composer: &mut C) -> core::result::Result<(), PlonkError>
    where
        C: Composer,
    {
        let mut secret = [Byte { value: 0, witness: C::ZERO }; 32];
        let mut salt = [Byte { value: 0, witness: C::ZERO }; 32];
        for i in 0..32 {
            secret[i] = Byte::witness(composer, self.secret[i]);
            salt[i] = Byte::witness(composer, self.salt_bytes[i]);
        }
        poseidon_hash2_circuit(composer, salt, secret, self.salt, self.hkey);
        Ok(())
    }
}

#[derive(Clone)]
pub struct PlonkPolicy {
    prover: Prover,
    verifier_bytes: Vec<u8>,
    keybinding_prover: Arc<Mutex<Option<Prover>>>,
    keybinding_verifier_bytes: Arc<Mutex<Option<Vec<u8>>>>,
    policy_id: PolicyId,
    block_hashes: Vec<BlsScalar>,
    flags: u16,
}

impl PlonkPolicy {
    pub fn new(label: &[u8]) -> Result<Self> {
        Self::new_with_blocklist(label, &[])
    }

    pub fn new_with_blocklist(label: &[u8], blocklist: &[LeafBytes]) -> Result<Self> {
        let blocklist = crate::policy::Blocklist::from_canonical_bytes(blocklist.to_vec())?;
        Self::new_from_blocklist(label, &blocklist)
    }

    pub fn new_from_blocklist(label: &[u8], blocklist: &crate::policy::Blocklist) -> Result<Self> {
        let mut block_hashes_buf = [BlsScalar::zero(); MAX_BLOCKLIST_ENTRIES];
        let block_hashes_len = blocklist.hashes_as_scalars_into(&mut block_hashes_buf)?;
        let block_hashes = block_hashes_buf[..block_hashes_len].to_vec();
        let dummy_inverses = vec![BlsScalar::one(); block_hashes.len()];
        let circuit =
            BlocklistCircuit::new(BlsScalar::zero(), dummy_inverses, block_hashes.clone());
        let capacities = blocklist_capacities(block_hashes.len());
        let mut compiled: Option<(Prover, Vec<u8>)> = None;
        for capacity in capacities {
            let mut rng = ChaCha20Rng::from_seed(hash_to_seed(label));
            let pp = match PublicParameters::setup(capacity, &mut rng) {
                Ok(pp) => pp,
                Err(_err) => {
                    #[cfg(feature = "std")]
                    eprintln!("blocklist setup failed (capacity={}): {:?}", capacity, _err);
                    continue;
                }
            };
            match Compiler::compile_with_circuit(&pp, label, &circuit) {
                Ok((prover, verifier)) => {
                    compiled = Some((prover, verifier.to_bytes()));
                    break;
                }
                Err(_err) => {
                    #[cfg(feature = "std")]
                    eprintln!("blocklist compile failed (capacity={}): {:?}", capacity, _err);
                }
            }
        }
        let (prover, verifier_bytes) = compiled.ok_or(Error::Crypto)?;

        let policy_id = compute_policy_id(&verifier_bytes);
        register_verifier(
            policy_id,
            &[
                VerifierEntry {
                    kind: ProofKind::Consistency as u8,
                    verifier_blob: verifier_bytes.clone(),
                },
                VerifierEntry {
                    kind: ProofKind::Policy as u8,
                    verifier_blob: verifier_bytes.clone(),
                },
            ],
        );
        Ok(Self {
            prover,
            verifier_bytes,
            keybinding_prover: Arc::new(Mutex::new(None)),
            keybinding_verifier_bytes: Arc::new(Mutex::new(None)),
            policy_id,
            block_hashes,
            flags: 0,
        })
    }

    #[cfg(feature = "regex-policy")]
    pub fn new_from_regex_literals(label: &[u8], patterns: &[alloc::string::String]) -> Result<Self> {
        use crate::policy::blocklist::BlocklistEntry;
        use crate::policy::regex::exact_literals;
        use crate::core::policy::metadata::POLICY_FLAG_REGEX;

        let literals = exact_literals(patterns)?;
        let entries: Vec<BlocklistEntry> = literals
            .into_iter()
            .map(|literal| ValueBytes::new(literal.as_bytes()).map(BlocklistEntry::Exact))
            .collect::<crate::types::Result<_>>()?;
        let blocklist = crate::policy::Blocklist::new(entries)?;
        let mut policy = Self::new_from_blocklist(label, &blocklist)?;
        policy.flags |= POLICY_FLAG_REGEX;
        Ok(policy)
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub fn metadata(&self, expiry: u32, flags: u16) -> PolicyMetadata {
        if self.keybinding_verifier_bytes.lock().is_none() {
            if let Some(bytes) = load_keybinding_verifier() {
                *self.keybinding_verifier_bytes.lock() = Some(bytes.clone());
                insert_verifier_entry(
                    self.policy_id,
                    VerifierEntry {
                        kind: ProofKind::KeyBinding as u8,
                        verifier_blob: bytes,
                    },
                );
            } else {
                let _ = self.ensure_keybinding();
            }
        }
        let mut verifiers = Vec::new();
        if let Some(bytes) = self.keybinding_verifier_bytes.lock().clone() {
            verifiers.push(VerifierEntry {
                kind: ProofKind::KeyBinding as u8,
                verifier_blob: bytes,
            });
        }
        verifiers.push(VerifierEntry {
            kind: ProofKind::Consistency as u8,
            verifier_blob: self.verifier_bytes.clone(),
        });
        verifiers.push(VerifierEntry {
            kind: ProofKind::Policy as u8,
            verifier_blob: self.verifier_bytes.clone(),
        });
        PolicyMetadata {
            policy_id: self.policy_id,
            version: 1,
            expiry,
            flags: flags | self.flags | POLICY_FLAG_PCD,
            verifiers,
        }
    }

    pub fn prove_payload(&self, payload: &[u8]) -> Result<PolicyCapsule> {
        self.prove_payload_with_keybinding(payload, None)
    }

    pub fn prove_payload_with_keybinding(
        &self,
        payload: &[u8],
        keybinding: Option<KeyBindingInputs>,
    ) -> Result<PolicyCapsule> {
        let (payload_scalar, commitment_bytes) = payload_commitment(payload);
        let mut inverses = Vec::with_capacity(self.block_hashes.len());
        for blocked in &self.block_hashes {
            let diff = payload_scalar - blocked;
            let inv = diff.invert().ok_or(Error::PolicyViolation)?;
            inverses.push(inv);
        }
        let circuit = BlocklistCircuit::new(payload_scalar, inverses, self.block_hashes.clone());
        let mut rng = ChaCha20Rng::from_seed(hash_to_seed(payload));
        let (proof, public_inputs) = self
            .prover
            .prove(&mut rng, &circuit)
            .map_err(|_| Error::Crypto)?;
        if public_inputs.len() != 1 || public_inputs[0] != payload_scalar {
            return Err(Error::Crypto);
        }
        let proof_bytes = proof.to_bytes();
        let part = ProofPart {
            kind: ProofKind::Policy,
            proof: proof_bytes,
            commitment: commitment_bytes,
            aux_len: 0,
            aux: [0u8; crate::core::policy::AUX_MAX],
        };
        let key_part = if let Some(input) = keybinding {
            self.ensure_keybinding()?;
            let salt =
                keybinding_salt(&self.policy_id, &input.htarget, &input.session_nonce, &input.route_id);
            let salt_bytes = salt.to_bytes();
            let hkey = keybinding_hash_scalar(salt, &input.sender_secret);
            let circuit = KeyBindingCircuit::new(
                input.sender_secret,
                salt_bytes,
                salt,
                hkey,
            );
            let mut rng = ChaCha20Rng::from_seed(hash_to_seed(&input.sender_secret));
            let prover = self
                .keybinding_prover
                .lock()
                .as_ref()
                .cloned()
                .ok_or(Error::Crypto)?;
            let (proof, public_inputs) = prover
                .prove(&mut rng, &circuit)
                .map_err(|_err| {
                    #[cfg(feature = "std")]
                    eprintln!("keybinding prove error: {:?}", _err);
                    Error::Crypto
                })?;
            #[cfg(feature = "std")]
            eprintln!(
                "keybinding proof public_inputs: {:?}",
                public_inputs
                    .iter()
                    .map(|v| v.to_bytes())
                    .collect::<Vec<_>>()
            );
            if public_inputs.len() != 2 || public_inputs[0] != salt || public_inputs[1] != hkey {
                return Err(Error::Crypto);
            }
            Some(ProofPart {
                kind: ProofKind::KeyBinding,
                proof: proof.to_bytes(),
                commitment: hkey.to_bytes(),
                aux_len: 0,
                aux: [0u8; crate::core::policy::AUX_MAX],
            })
        } else {
            None
        };
        let consistency_part = ProofPart {
            kind: ProofKind::Consistency,
            proof: proof_bytes,
            commitment: commitment_bytes,
            aux_len: 0,
            aux: [0u8; crate::core::policy::AUX_MAX],
        };
        let mut parts = [ProofPart::default(), ProofPart::default(), ProofPart::default(), ProofPart::default()];
        let mut count = 0usize;
        if let Some(key_part) = key_part {
            parts[count] = key_part;
            count += 1;
        }
        parts[count] = consistency_part;
        count += 1;
        parts[count] = part;
        count += 1;
        Ok(PolicyCapsule {
            policy_id: self.policy_id,
            version: 1,
            part_count: count as u8,
            parts,
        })
    }

    fn ensure_keybinding(&self) -> Result<()> {
        if self.keybinding_verifier_bytes.lock().is_some() {
            return Ok(());
        }
        let (prover, verifier_bytes) = keybinding_prover_and_verifier()?;
        *self.keybinding_prover.lock() = Some(prover);
        *self.keybinding_verifier_bytes.lock() = Some(verifier_bytes.clone());
        insert_verifier_entry(
            self.policy_id,
            VerifierEntry {
                kind: ProofKind::KeyBinding as u8,
                verifier_blob: verifier_bytes,
            },
        );
        Ok(())
    }
}

fn payload_commitment(payload: &[u8]) -> (BlsScalar, [u8; crate::core::policy::COMMIT_LEN]) {
    let scalar = hash_to_scalar(payload);
    let bytes = scalar.to_bytes();
    (scalar, bytes)
}

/// Compute the commitment bytes associated with a payload.
/// Routers or APIs can reuse this to validate that a capsule matches the payload they received.
pub fn payload_commitment_bytes(payload: &[u8]) -> [u8; crate::core::policy::COMMIT_LEN] {
    payload_commitment(payload).1
}

fn hash_to_scalar(data: &[u8]) -> BlsScalar {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let wide = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&wide);
    BlsScalar::from_bytes_wide(&bytes)
}

pub fn keybinding_salt(
    policy_id: &PolicyId,
    htarget: &[u8; 32],
    session_nonce: &[u8; 32],
    route_id: &[u8; 32],
) -> BlsScalar {
    let mut hasher = Sha512::new();
    hasher.update(policy_id);
    hasher.update(htarget);
    hasher.update(session_nonce);
    hasher.update(route_id);
    let wide = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&wide);
    BlsScalar::from_bytes_wide(&bytes)
}

fn keybinding_hash_scalar(salt: BlsScalar, ikm: &[u8; 32]) -> BlsScalar {
    let secret = bytes_to_scalar_le(ikm);
    poseidon_hash2([salt, secret])
}

fn bytes_to_scalar_le(bytes: &[u8; 32]) -> BlsScalar {
    let mut acc = BlsScalar::zero();
    let base = BlsScalar::from(256u64);
    let mut factor = BlsScalar::one();
    for byte in bytes {
        acc += BlsScalar::from(*byte as u64) * factor;
        factor *= base;
    }
    acc
}

#[derive(Clone, Copy, Debug)]
pub struct KeyBindingInputs {
    pub sender_secret: [u8; 32],
    pub htarget: [u8; 32],
    pub session_nonce: [u8; 32],
    pub route_id: [u8; 32],
}

fn compute_policy_id(bytes: &[u8]) -> PolicyId {
    let mut id = [0u8; 32];
    let hash = Sha256::digest(bytes);
    id.copy_from_slice(&hash);
    id
}

fn hash_to_seed(data: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let hash = Sha256::digest(data);
    seed.copy_from_slice(&hash);
    seed
}

pub trait VerifierCache: Send + Sync {
    fn load_keybinding_verifier(&self) -> Option<Vec<u8>>;
    fn save_keybinding_verifier(&self, bytes: &[u8]);
}

static VERIFIER_CACHE: Mutex<Option<Arc<dyn VerifierCache>>> = Mutex::new(None);
static KEYBINDING_CAP_OVERRIDE: Mutex<Option<Vec<usize>>> = Mutex::new(None);
static BLOCKLIST_CAP_OVERRIDE: Mutex<Option<Vec<usize>>> = Mutex::new(None);
static POLICY_STORE: Mutex<BTreeMap<PolicyId, Arc<PlonkPolicy>>> = Mutex::new(BTreeMap::new());
static VERIFIER_STORE: Mutex<BTreeMap<PolicyId, Vec<VerifierEntry>>> = Mutex::new(BTreeMap::new());
static KEYBINDING_CACHE: Mutex<Option<(Prover, Vec<u8>)>> = Mutex::new(None);

pub fn set_keybinding_verifier_cache(cache: Arc<dyn VerifierCache>) {
    *VERIFIER_CACHE.lock() = Some(cache);
}

pub fn set_keybinding_capacities(capacities: Vec<usize>) {
    *KEYBINDING_CAP_OVERRIDE.lock() = Some(capacities);
}

pub fn set_blocklist_capacities(capacities: Vec<usize>) {
    *BLOCKLIST_CAP_OVERRIDE.lock() = Some(capacities);
}

fn keybinding_prover_and_verifier() -> Result<(Prover, Vec<u8>)> {
    if let Some((prover, verifier)) = KEYBINDING_CACHE.lock().as_ref() {
        return Ok((prover.clone(), verifier.clone()));
    }
    let label: &[u8] = b"hornet-keybinding-poseidon";
    let keybinding_circuit = KeyBindingCircuit::new(
        [0u8; 32],
        [0u8; 32],
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    let capacities = keybinding_capacities();
    #[cfg(feature = "std")]
    eprintln!("keybinding capacities: {:?}", capacities);
    let mut compiled: Option<(Prover, Vec<u8>)> = None;
    for capacity in capacities {
        let mut rng = ChaCha20Rng::from_seed(hash_to_seed(label));
        let pp = match PublicParameters::setup(capacity, &mut rng) {
            Ok(pp) => pp,
            Err(_err) => {
                #[cfg(feature = "std")]
                eprintln!("keybinding setup failed (capacity={}): {:?}", capacity, _err);
                continue;
            }
        };
        match Compiler::compile_with_circuit(&pp, label, &keybinding_circuit) {
            Ok((prover, verifier)) => {
                compiled = Some((prover, verifier.to_bytes()));
                break;
            }
            Err(_err) => {
                #[cfg(feature = "std")]
                eprintln!("keybinding compile failed (capacity={}): {:?}", capacity, _err);
            }
        }
    }
    let (prover, verifier_bytes) = match compiled {
        Some(value) => value,
        None => {
            #[cfg(feature = "std")]
            eprintln!("keybinding compile failed for all capacities");
            return Err(Error::Crypto);
        }
    };
    save_keybinding_verifier(&verifier_bytes);
    *KEYBINDING_CACHE.lock() = Some((prover.clone(), verifier_bytes.clone()));
    Ok((prover, verifier_bytes))
}

fn keybinding_capacities() -> Vec<usize> {
    if let Some(capacities) = KEYBINDING_CAP_OVERRIDE.lock().as_ref() {
        return capacities.clone();
    }
    vec![1 << 15, 1 << 16]
}

fn blocklist_capacities(len: usize) -> Vec<usize> {
    if let Some(capacities) = BLOCKLIST_CAP_OVERRIDE.lock().as_ref() {
        return capacities.clone();
    }
    let mut capacities = Vec::new();
    let mut cap = 1usize << 8;
    let target = len.saturating_mul(8).max(256);
    while cap < target {
        cap <<= 1;
    }
    for _ in 0..4 {
        capacities.push(cap);
        cap <<= 1;
    }
    capacities
}

fn load_keybinding_verifier() -> Option<Vec<u8>> {
    let cache = VERIFIER_CACHE.lock().clone();
    cache.and_then(|cache| cache.load_keybinding_verifier())
}

fn save_keybinding_verifier(bytes: &[u8]) {
    let cache = VERIFIER_CACHE.lock().clone();
    if let Some(cache) = cache {
        cache.save_keybinding_verifier(bytes);
    }
}


fn register_verifier(id: PolicyId, entries: &[VerifierEntry]) {
    VERIFIER_STORE.lock().insert(id, entries.to_vec());
}

fn insert_verifier_entry(id: PolicyId, entry: VerifierEntry) {
    let mut store = VERIFIER_STORE.lock();
    let entries = store.entry(id).or_insert_with(Vec::new);
    if let Some(existing) = entries.iter_mut().find(|stored| stored.kind == entry.kind) {
        existing.verifier_blob = entry.verifier_blob;
    } else {
        entries.push(entry);
    }
}

pub fn register_policy(policy: Arc<PlonkPolicy>) {
    POLICY_STORE
        .lock()
        .insert(*policy.policy_id(), Arc::clone(&policy));
}

pub fn get_policy(id: &PolicyId) -> Option<Arc<PlonkPolicy>> {
    POLICY_STORE.lock().get(id).cloned()
}

pub fn ensure_registry(registry: &mut PolicyRegistry, metadata: &PolicyMetadata) -> Result<()> {
    if registry.get(&metadata.policy_id).is_some() {
        return Ok(());
    }
    if let Some(entries) = VERIFIER_STORE.lock().get(&metadata.policy_id).cloned() {
        let mut cloned = metadata.clone();
        for entry in cloned.verifiers.iter_mut() {
            if let Some(found) = entries.iter().find(|stored| stored.kind == entry.kind) {
                entry.verifier_blob = found.verifier_blob.clone();
            }
        }
        registry.register(cloned)
    } else {
        registry.register(metadata.clone())
    }
}

pub fn prove_for_payload(policy_id: &PolicyId, payload: &[u8]) -> Result<PolicyCapsule> {
    if let Some(policy) = get_policy(policy_id) {
        policy.prove_payload(payload)
    } else {
        Err(Error::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::plonk::validator::PlonkCapsuleValidator;
    use crate::policy::blocklist::{BlocklistEntry, ValueBytes};
    use alloc::vec;

    #[test]
    fn proof_roundtrip() {
        let blocked_leaf =
            BlocklistEntry::Exact(ValueBytes::new(b"blocked.example").unwrap()).leaf_bytes();
        let blocklist = vec![blocked_leaf.clone()];
        let policy =
            Arc::new(PlonkPolicy::new_with_blocklist(b"test-policy", &blocklist).expect("policy"));
        register_policy(policy.clone());
        let metadata = policy.metadata(42, 0);
        let mut registry = PolicyRegistry::new();
        ensure_registry(&mut registry, &metadata).expect("registry");
        let validator = PlonkCapsuleValidator::new();

        let safe_leaf = BlocklistEntry::Exact(ValueBytes::new(b"safe.example").unwrap()).leaf_bytes();
        let capsule = policy.prove_payload(safe_leaf.as_slice()).expect("prove payload");
        assert_eq!(capsule.policy_id, metadata.policy_id);
        let mut cap_buf = [0u8; crate::core::policy::MAX_CAPSULE_LEN];
        let cap_len = capsule.encode_into(&mut cap_buf).expect("encode");
        let mut buffer = Vec::with_capacity(cap_len + "safe.example".len());
        buffer.extend_from_slice(&cap_buf[..cap_len]);
        buffer.extend_from_slice(b"safe.example");
        let (_capsule, consumed) = registry.enforce(&mut buffer, &validator).expect("enforce");
        assert_eq!(consumed, cap_len);

        assert!(matches!(
            policy.prove_payload(blocked_leaf.as_slice()),
            Err(Error::PolicyViolation)
        ));
    }
}
