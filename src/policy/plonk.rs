use crate::policy::{PolicyCapsule, PolicyId, PolicyMetadata, PolicyRegistry};
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
struct TargetCircuit {
    target: BlsScalar,
}

impl TargetCircuit {
    fn new(target: BlsScalar) -> Self {
        Self { target }
    }
}

impl Circuit for TargetCircuit {
    fn circuit<C>(&self, composer: &mut C) -> core::result::Result<(), PlonkError>
    where
        C: Composer,
    {
        let witness_target = composer.append_witness(self.target);
        composer.assert_equal_constant(witness_target, BlsScalar::zero(), Some(self.target));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRole {
    Open,
    Parse,
    Check,
}

#[derive(Clone)]
pub struct PlonkPolicy {
    prover: Prover,
    verifier_bytes: Vec<u8>,
    policy_id: PolicyId,
    block_hashes: Vec<BlsScalar>,
    role: PolicyRole,
}

impl PlonkPolicy {
    pub fn new(label: &[u8]) -> Result<Self> {
        Self::new_with_blocklist(label, &[])
    }

    pub fn new_with_blocklist(label: &[u8], blocklist: &[Vec<u8>]) -> Result<Self> {
        let blocklist = crate::policy::Blocklist::from_canonical_bytes(blocklist.to_vec());
        Self::new_from_blocklist(label, &blocklist)
    }

    pub fn new_from_blocklist(label: &[u8], blocklist: &crate::policy::Blocklist) -> Result<Self> {
        Self::new_from_blocklist_with_role(label, blocklist, PolicyRole::Check)
    }

    pub fn new_from_blocklist_with_role(
        label: &[u8],
        blocklist: &crate::policy::Blocklist,
        role: PolicyRole,
    ) -> Result<Self> {
        let mut rng = ChaCha20Rng::from_seed(hash_to_seed(label));
        let capacity = 1 << 8;
        let pp = PublicParameters::setup(capacity, &mut rng).map_err(|_| Error::Crypto)?;
        let block_hashes = blocklist.hashes_as_scalars();
        let (prover, verifier) = match role {
            PolicyRole::Open | PolicyRole::Parse => {
                let circuit = TargetCircuit::new(BlsScalar::zero());
                Compiler::compile_with_circuit(&pp, label, &circuit).map_err(|_| Error::Crypto)?
            }
            PolicyRole::Check => {
                let dummy_inverses = vec![BlsScalar::one(); block_hashes.len()];
                let circuit =
                    BlocklistCircuit::new(BlsScalar::zero(), dummy_inverses, block_hashes.clone());
                Compiler::compile_with_circuit(&pp, label, &circuit).map_err(|_| Error::Crypto)?
            }
        };
        let verifier_bytes = verifier.to_bytes();
        let policy_id = compute_policy_id(&verifier_bytes);
        register_verifier(policy_id, &verifier_bytes);
        Ok(Self {
            prover,
            verifier_bytes,
            policy_id,
            block_hashes,
            role,
        })
    }

    pub fn from_prover_bytes(
        policy_id: PolicyId,
        prover_bytes: &[u8],
        block_hashes: Vec<[u8; 32]>,
    ) -> Result<Self> {
        let prover = Prover::try_from_bytes(prover_bytes).map_err(|_| Error::Crypto)?;
        let mut hashes = Vec::with_capacity(block_hashes.len());
        for bytes in block_hashes {
            let scalar = BlsScalar::from_bytes(&bytes).map_err(|_| Error::Crypto)?;
            hashes.push(scalar);
        }
        Ok(Self {
            prover,
            verifier_bytes: Vec::new(),
            policy_id,
            block_hashes: hashes,
            role: PolicyRole::Check,
        })
    }

    pub fn from_prover_bytes_with_role(
        policy_id: PolicyId,
        prover_bytes: &[u8],
        block_hashes: Vec<[u8; 32]>,
        role: PolicyRole,
    ) -> Result<Self> {
        let mut policy = Self::from_prover_bytes(policy_id, prover_bytes, block_hashes)?;
        policy.role = role;
        Ok(policy)
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub fn prover_bytes(&self) -> Vec<u8> {
        self.prover.to_bytes()
    }

    pub fn block_hashes_bytes(&self) -> Vec<[u8; 32]> {
        self.block_hashes
            .iter()
            .map(|hash| hash.to_bytes())
            .collect()
    }

    pub fn metadata(&self, expiry: u32, flags: u16) -> PolicyMetadata {
        PolicyMetadata {
            policy_id: self.policy_id,
            version: 1,
            expiry,
            flags,
            verifier_blob: self.verifier_bytes.clone(),
        }
    }

    pub fn prove_payload(&self, payload: &[u8]) -> Result<PolicyCapsule> {
        let (payload_scalar, commitment_bytes) = payload_commitment(payload);
        let mut rng = ChaCha20Rng::from_seed(hash_to_seed(payload));
        let (proof, public_inputs) = match self.role {
            PolicyRole::Open | PolicyRole::Parse => {
                let circuit = TargetCircuit::new(payload_scalar);
                self.prover.prove(&mut rng, &circuit).map_err(|_| Error::Crypto)?
            }
            PolicyRole::Check => {
                let mut inverses = Vec::with_capacity(self.block_hashes.len());
                for blocked in &self.block_hashes {
                    let diff = payload_scalar - blocked;
                    let inv = diff.invert().ok_or(Error::PolicyViolation)?;
                    inverses.push(inv);
                }
                let circuit =
                    BlocklistCircuit::new(payload_scalar, inverses, self.block_hashes.clone());
                self.prover.prove(&mut rng, &circuit).map_err(|_| Error::Crypto)?
            }
        };
        if public_inputs.len() != 1 || public_inputs[0] != payload_scalar {
            return Err(Error::Crypto);
        }
        let proof_bytes = proof.to_bytes().to_vec();
        Ok(PolicyCapsule {
            policy_id: self.policy_id,
            version: 1,
            proof: proof_bytes,
            commitment: commitment_bytes,
            aux: Vec::new(),
        })
    }
}

fn payload_commitment(payload: &[u8]) -> (BlsScalar, Vec<u8>) {
    let scalar = hash_to_scalar(payload);
    let bytes = scalar.to_bytes().to_vec();
    (scalar, bytes)
}

/// Compute the commitment bytes associated with a payload.
/// Routers or APIs can reuse this to validate that a capsule matches the payload they received.
pub fn payload_commitment_bytes(payload: &[u8]) -> Vec<u8> {
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

static POLICY_STORE: Mutex<BTreeMap<PolicyId, Arc<PlonkPolicy>>> = Mutex::new(BTreeMap::new());
static VERIFIER_STORE: Mutex<BTreeMap<PolicyId, Vec<u8>>> = Mutex::new(BTreeMap::new());

fn register_verifier(id: PolicyId, bytes: &[u8]) {
    VERIFIER_STORE.lock().insert(id, bytes.to_vec());
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
    if let Some(bytes) = VERIFIER_STORE.lock().get(&metadata.policy_id).cloned() {
        let mut cloned = metadata.clone();
        cloned.verifier_blob = bytes;
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
    use crate::policy::blocklist::BlocklistEntry;
    use alloc::vec;

    #[test]
    fn proof_roundtrip() {
        let blocked_leaf = BlocklistEntry::Exact("blocked.example".into()).leaf_bytes();
        let blocklist = vec![blocked_leaf.clone()];
        let policy =
            Arc::new(PlonkPolicy::new_with_blocklist(b"test-policy", &blocklist).expect("policy"));
        register_policy(policy.clone());
        let metadata = policy.metadata(42, 0);
        let mut registry = PolicyRegistry::new();
        ensure_registry(&mut registry, &metadata).expect("registry");
        let validator = PlonkCapsuleValidator::new();

        let safe_leaf = BlocklistEntry::Exact("safe.example".into()).leaf_bytes();
        let capsule = policy.prove_payload(&safe_leaf).expect("prove payload");
        assert_eq!(capsule.policy_id, metadata.policy_id);
        let mut buffer = capsule.encode();
        buffer.extend_from_slice(b"safe.example");
        let (_capsule, consumed) = registry.enforce(&mut buffer, &validator).expect("enforce");
        assert_eq!(consumed, capsule.encode().len());

        assert!(matches!(
            policy.prove_payload(&blocked_leaf),
            Err(Error::PolicyViolation)
        ));
    }
}
