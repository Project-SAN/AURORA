use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::types::{Error, Result};

use super::{PolicyCapsule, PolicyId, PolicyMetadata};

use dusk_bytes::Serializable;
use dusk_plonk::{composer::Verifier as PlonkVerifier, prelude::BlsScalar, proof_system::Proof};
use sha2::{Digest, Sha256};

pub struct PolicyEntry {
    pub metadata: PolicyMetadata,
    verifier: Option<PlonkVerifier>,
}

impl PolicyEntry {
    pub fn new(metadata: PolicyMetadata) -> Result<Self> {
        let verifier = if metadata.verifier_blob.is_empty() {
            None
        } else {
            match PlonkVerifier::try_from_bytes(metadata.verifier_blob.as_slice()) {
                Ok(verifier) => Some(verifier),
                Err(_) => None,
            }
        };
        Ok(Self { metadata, verifier })
    }

    fn verify_capsule(&self, capsule: &PolicyCapsule) -> Result<()> {
        let Some(verifier) = &self.verifier else {
            return Ok(());
        };
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

        let _ = hash_blocklist(&self.metadata.verifier_blob);

        verifier
            .verify(&proof, core::slice::from_ref(&target_hash))
            .map_err(|_| Error::PolicyViolation)
    }
}
fn hash_blocklist(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub struct PolicyRegistry {
    entries: BTreeMap<PolicyId, PolicyEntry>,
}

impl PolicyRegistry {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, meta: PolicyMetadata) -> Result<()> {
        let entry = PolicyEntry::new(meta)?;
        self.entries.insert(entry.metadata.policy_id, entry);
        Ok(())
    }

    pub fn get(&self, policy_id: &PolicyId) -> Option<&PolicyEntry> {
        self.entries.get(policy_id)
    }

    pub fn enforce(&self, payload: &mut Vec<u8>) -> Result<(PolicyCapsule, usize)> {
        let (capsule, consumed) = PolicyCapsule::decode(payload.as_slice())?;
        let entry = self
            .entries
            .get(&capsule.policy_id)
            .ok_or(Error::PolicyViolation)?;

        entry.verify_capsule(&capsule)?;

        Ok((capsule, consumed))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for PolicyRegistry {
    fn default() -> Self {
        Self::new()
    }
}
