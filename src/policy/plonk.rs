#![cfg(feature = "policy-plonk")]

use crate::policy::{PolicyCapsule, PolicyId, PolicyMetadata, PolicyRegistry};
use crate::types::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use dusk_bytes::Serializable;
use dusk_plonk::prelude::{
    BlsScalar, Circuit, Compiler, Composer, Error as PlonkError, Prover, PublicParameters,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256, Sha512};
use spin::Mutex;

#[derive(Clone, Default)]
struct EqualityCircuit {
    witness: BlsScalar,
    commitment: BlsScalar,
}

impl EqualityCircuit {
    fn new(witness: BlsScalar, commitment: BlsScalar) -> Self {
        Self {
            witness,
            commitment,
        }
    }
}

impl Circuit for EqualityCircuit {
    fn circuit<C>(&self, composer: &mut C) -> core::result::Result<(), PlonkError>
    where
        C: Composer,
    {
        let witness = composer.append_witness(self.witness);
        composer.assert_equal_constant(witness, BlsScalar::zero(), Some(self.commitment));
        Ok(())
    }
}

#[derive(Clone)]
pub struct PlonkPolicy {
    prover: Prover,
    verifier_bytes: Vec<u8>,
    policy_id: PolicyId,
}

impl PlonkPolicy {
    pub fn new(label: &[u8]) -> Result<Self> {
        let mut rng = ChaCha20Rng::from_seed(hash_to_seed(label));
        let capacity = 1 << 8;
        let pp = PublicParameters::setup(capacity, &mut rng).map_err(|_| Error::Crypto)?;
        let circuit = EqualityCircuit::default();
        let (prover, verifier) =
            Compiler::compile_with_circuit(&pp, label, &circuit).map_err(|_| Error::Crypto)?;
        let verifier_bytes = verifier.to_bytes();
        let policy_id = compute_policy_id(&verifier_bytes);
        register_verifier(policy_id, &verifier_bytes);
        Ok(Self {
            prover,
            verifier_bytes,
            policy_id,
        })
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
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
        let circuit = EqualityCircuit::new(payload_scalar, payload_scalar);
        let mut rng = ChaCha20Rng::from_seed(hash_to_seed(payload));
        let (proof, _public_inputs) = self
            .prover
            .prove(&mut rng, &circuit)
            .map_err(|_| Error::Crypto)?;
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
    let mut hasher = Sha512::new();
    hasher.update(payload);
    let wide = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&wide);
    let scalar = BlsScalar::from_bytes_wide(&bytes);
    let bytes = scalar.to_bytes().to_vec();
    (scalar, bytes)
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

    #[test]
    fn proof_roundtrip() {
        let policy = Arc::new(PlonkPolicy::new(b"test-policy").expect("policy"));
        register_policy(policy.clone());
        let metadata = policy.metadata(42, 0);
        let mut registry = PolicyRegistry::new();
        ensure_registry(&mut registry, &metadata).expect("registry");
        let capsule = policy.prove_payload(b"payload").expect("prove payload");
        assert_eq!(capsule.policy_id, metadata.policy_id);

        let mut buffer = capsule.encode();
        buffer.extend_from_slice(b"payload");
        registry.enforce(&mut buffer).expect("enforce");
    }
}
