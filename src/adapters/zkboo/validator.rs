use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::core::policy::{CapsuleValidator, PolicyCapsule, PolicyMetadata, PolicyRole, ProofKind};
use crate::crypto::zkp::{Circuit, Proof, VerifierConfig, ZkBooEngine};
use crate::types::{Error, Result};
use spin::Mutex;

pub struct ZkBooCapsuleValidator {
    cache: Mutex<BTreeMap<[u8; 32], Arc<Circuit>>>,
}

impl ZkBooCapsuleValidator {
    pub const fn new() -> Self {
        Self {
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn load_circuit(&self, metadata: &PolicyMetadata) -> Result<Option<Arc<Circuit>>> {
        let Some(entry) = metadata
            .verifiers
            .iter()
            .find(|entry| entry.kind == ProofKind::Policy as u8)
        else {
            return Ok(None);
        };
        if entry.verifier_blob.is_empty() {
            return Ok(None);
        }
        let mut cache = self.cache.lock();
        if let Some(circuit) = cache.get(&metadata.policy_id) {
            return Ok(Some(circuit.clone()));
        }
        let circuit = Circuit::decode(entry.verifier_blob.as_slice())?;
        let circuit = Arc::new(circuit);
        cache.insert(metadata.policy_id, circuit.clone());
        Ok(Some(circuit))
    }
}

impl Default for ZkBooCapsuleValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsuleValidator for ZkBooCapsuleValidator {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()> {
        self.validate_with_role(capsule, metadata, PolicyRole::All)
    }

    fn validate_with_role(
        &self,
        capsule: &PolicyCapsule,
        metadata: &PolicyMetadata,
        role: PolicyRole,
    ) -> Result<()> {
        if !metadata.supports_zkboo() {
            // ZKBoo-only build: reject non-ZKBoo policies explicitly.
            return Err(Error::PolicyViolation);
        }
        let part = capsule
            .part(ProofKind::Policy)
            .ok_or(Error::PolicyViolation)?;
        if !role.allows(part.kind) {
            return Ok(());
        }
        let Some(circuit) = self.load_circuit(metadata)? else {
            return Err(Error::PolicyViolation);
        };
        let proof = Proof::from_part(part).map_err(|_| Error::PolicyViolation)?;
        let outputs = [1u8];
        let engine = ZkBooEngine;
        engine
            .verify_circuit(
                circuit.as_ref(),
                &outputs,
                &proof,
                VerifierConfig {
                    rounds: proof.rounds,
                },
            )
            .map_err(|_| Error::PolicyViolation)
    }
}
