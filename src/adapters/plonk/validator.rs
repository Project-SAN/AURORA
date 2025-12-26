use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::core::policy::{CapsuleValidator, PolicyCapsule, PolicyId, PolicyMetadata};
use crate::types::{Error, Result};
use crate::policy::plonk::{POLICY_FLAG_ROLE_OPEN, POLICY_FLAG_ROLE_PARSE};
use dusk_bytes::Serializable;
use dusk_plonk::{composer::Verifier as PlonkVerifier, prelude::BlsScalar, proof_system::Proof};
use spin::Mutex;

pub struct PlonkCapsuleValidator {
    cache: Mutex<BTreeMap<PolicyId, Arc<PlonkVerifier>>>,
}

impl PlonkCapsuleValidator {
    pub const fn new() -> Self {
        Self {
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn load_verifier(&self, metadata: &PolicyMetadata) -> Result<Option<Arc<PlonkVerifier>>> {
        if metadata.verifier_blob.is_empty() {
            return Ok(None);
        }
        let mut cache = self.cache.lock();
        if let Some(verifier) = cache.get(&metadata.policy_id) {
            return Ok(Some(verifier.clone()));
        }
        let verifier = PlonkVerifier::try_from_bytes(metadata.verifier_blob.as_slice())
            .map_err(|_| Error::PolicyViolation)?;
        let verifier = Arc::new(verifier);
        cache.insert(metadata.policy_id, verifier.clone());
        Ok(Some(verifier))
    }

    fn validate_proof(verifier: &PlonkVerifier, capsule: &PolicyCapsule) -> Result<()> {
        if capsule.proof.len() != Proof::SIZE {
            return Err(Error::PolicyViolation);
        }
        let mut proof_bytes = [0u8; Proof::SIZE];
        proof_bytes.copy_from_slice(&capsule.proof);
        let proof = Proof::from_bytes(&proof_bytes).map_err(|_| Error::PolicyViolation)?;

        if capsule.commitment.len() != BlsScalar::SIZE {
            return Err(Error::PolicyViolation);
        }
        let mut commit_bytes = [0u8; BlsScalar::SIZE];
        commit_bytes.copy_from_slice(&capsule.commitment);
        let target_hash =
            BlsScalar::from_bytes(&commit_bytes).map_err(|_| Error::PolicyViolation)?;

        verifier
            .verify(&proof, core::slice::from_ref(&target_hash))
            .map_err(|_| Error::PolicyViolation)
    }
}

impl CapsuleValidator for PlonkCapsuleValidator {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()> {
        if (metadata.flags & (POLICY_FLAG_ROLE_OPEN | POLICY_FLAG_ROLE_PARSE)) != 0 {
            return Ok(());
        }
        let Some(verifier) = self.load_verifier(metadata)? else {
            return Ok(());
        };
        Self::validate_proof(&verifier, capsule)
    }
}
