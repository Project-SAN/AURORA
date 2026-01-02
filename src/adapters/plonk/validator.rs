use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::core::policy::{CapsuleValidator, PolicyCapsule, PolicyId, PolicyMetadata};
use crate::types::{Error, Result};
use dusk_bytes::Serializable;
use dusk_plonk::{composer::Verifier as PlonkVerifier, prelude::BlsScalar, proof_system::Proof};
use spin::Mutex;

pub struct PlonkCapsuleValidator {
    cache: Mutex<BTreeMap<(PolicyId, u8), Arc<PlonkVerifier>>>,
}

impl PlonkCapsuleValidator {
    pub const fn new() -> Self {
        Self {
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn load_verifier(
        &self,
        metadata: &PolicyMetadata,
        kind: u8,
    ) -> Result<Option<Arc<PlonkVerifier>>> {
        let Some(entry) = metadata.verifiers.iter().find(|entry| entry.kind == kind) else {
            return Ok(None);
        };
        if entry.verifier_blob.is_empty() {
            return Ok(None);
        }
        let mut cache = self.cache.lock();
        if let Some(verifier) = cache.get(&(metadata.policy_id, kind)) {
            return Ok(Some(verifier.clone()));
        }
        let verifier = PlonkVerifier::try_from_bytes(entry.verifier_blob.as_slice())
            .map_err(|_| Error::PolicyViolation)?;
        let verifier = Arc::new(verifier);
        cache.insert((metadata.policy_id, kind), verifier.clone());
        Ok(Some(verifier))
    }

    fn validate_proof_bytes(
        verifier: &PlonkVerifier,
        proof_bytes: &[u8],
        commitment: &[u8],
    ) -> Result<()> {
        if proof_bytes.len() != Proof::SIZE {
            return Err(Error::PolicyViolation);
        }
        let mut proof_buf = [0u8; Proof::SIZE];
        proof_buf.copy_from_slice(proof_bytes);
        let proof = Proof::from_bytes(&proof_buf).map_err(|_| Error::PolicyViolation)?;

        if commitment.len() != BlsScalar::SIZE {
            return Err(Error::PolicyViolation);
        }
        let mut commit_bytes = [0u8; BlsScalar::SIZE];
        commit_bytes.copy_from_slice(commitment);
        let target_hash =
            BlsScalar::from_bytes(&commit_bytes).map_err(|_| Error::PolicyViolation)?;

        verifier
            .verify(&proof, core::slice::from_ref(&target_hash))
            .map_err(|_| Error::PolicyViolation)
    }
}

impl CapsuleValidator for PlonkCapsuleValidator {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()> {
        for part in &capsule.parts {
            let Some(verifier) = self.load_verifier(metadata, part.kind as u8)? else {
                continue;
            };
            Self::validate_proof_bytes(&verifier, &part.proof, &part.commitment)?;
            if let Ok(Some(exts)) = capsule.extensions_for(part.kind) {
                for ext in exts {
                    if let crate::core::policy::CapsuleExtension::PrecomputeProof(bytes) = ext {
                        Self::validate_proof_bytes(
                            &verifier,
                            bytes.as_slice(),
                            &part.commitment,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}
