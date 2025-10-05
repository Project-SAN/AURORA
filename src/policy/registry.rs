use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::types::{Error, Result};

use super::{PolicyCapsule, PolicyId, PolicyMetadata};

#[cfg(feature = "policy-plonk")]
use dusk_bytes::Serializable;
#[cfg(feature = "policy-plonk")]
use dusk_plonk::{composer::Verifier as PlonkVerifier, prelude::BlsScalar, proof_system::Proof};

pub struct PolicyEntry {
    pub metadata: PolicyMetadata,
    #[cfg(feature = "policy-plonk")]
    verifier: PlonkVerifier,
}

impl PolicyEntry {
    pub fn new(metadata: PolicyMetadata) -> Result<Self> {
        #[cfg(feature = "policy-plonk")]
        let verifier = {
            PlonkVerifier::try_from_bytes(metadata.verifier_blob.as_slice())
                .map_err(|_| Error::Crypto)?
        };

        #[cfg(feature = "policy-plonk")]
        return Ok(Self { metadata, verifier });

        #[cfg(not(feature = "policy-plonk"))]
        {
            Ok(Self { metadata })
        }
    }

    #[cfg(feature = "policy-plonk")]
    fn verify_capsule(&self, capsule: &PolicyCapsule) -> Result<()> {
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
        let public_input =
            BlsScalar::from_bytes(&commit_bytes).map_err(|_| Error::PolicyViolation)?;

        self.verifier
            .verify(&proof, core::slice::from_ref(&public_input))
            .map_err(|_| Error::PolicyViolation)
    }
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

    pub fn enforce(&self, payload: &mut Vec<u8>) -> Result<PolicyCapsule> {
        let capsule = PolicyCapsule::peel_from(payload)?;
        let entry = self
            .entries
            .get(&capsule.policy_id)
            .ok_or(Error::PolicyViolation)?;

        #[cfg(feature = "policy-plonk")]
        entry.verify_capsule(&capsule)?;

        #[cfg(not(feature = "policy-plonk"))]
        let _ = entry;

        Ok(capsule)
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
