use alloc::vec;
use alloc::vec::Vec;

use crate::core::policy::{PolicyCapsule, PolicyId, PolicyMetadata, ProofKind, ProofPart};
use crate::core::policy::metadata::POLICY_FLAG_ZKBOO;
use crate::crypto::zkp::{Circuit, ProverConfig, ZkBooEngine};
use crate::types::{Error, Result};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// Encode a ZKBoo policy circuit into a verifier blob suitable for PolicyMetadata.
pub fn encode_verifier_blob(circuit: &Circuit) -> Vec<u8> {
    circuit.encode()
}

pub struct ZkBooPolicy {
    circuit: Circuit,
    policy_id: PolicyId,
}

impl ZkBooPolicy {
    pub fn new(circuit: Circuit) -> Self {
        let bytes = circuit.encode();
        let policy_id = compute_policy_id(&bytes);
        Self { circuit, policy_id }
    }

    pub fn with_policy_id(circuit: Circuit, policy_id: PolicyId) -> Self {
        Self { circuit, policy_id }
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub fn circuit(&self) -> &Circuit {
        &self.circuit
    }

    pub fn metadata(&self, expiry: u32, flags: u16) -> PolicyMetadata {
        PolicyMetadata {
            policy_id: self.policy_id,
            version: 1,
            expiry,
            flags: flags | POLICY_FLAG_ZKBOO,
            verifiers: vec![crate::core::policy::VerifierEntry {
                kind: ProofKind::Policy as u8,
                verifier_blob: self.circuit.encode(),
            }],
        }
    }

    pub fn prove_with_rng<R: RngCore + CryptoRng>(
        &self,
        input_bits: &[u8],
        rounds: u16,
        rng: &mut R,
    ) -> Result<PolicyCapsule> {
        let outputs = self.circuit.eval(input_bits)?;
        if outputs.len() != 1 || outputs[0] != 1 {
            return Err(Error::PolicyViolation);
        }
        let engine = ZkBooEngine;
        let proof = engine.prove_circuit_with_rng(
            &self.circuit,
            input_bits,
            &outputs,
            ProverConfig { rounds },
            rng,
        )?;
        let part = proof.to_part(ProofKind::Policy)?;
        let mut parts = [ProofPart::default(), ProofPart::default(), ProofPart::default(), ProofPart::default()];
        parts[0] = part;
        Ok(PolicyCapsule {
            policy_id: self.policy_id,
            version: crate::core::policy::POLICY_CAPSULE_VERSION,
            part_count: 1,
            parts,
        })
    }
}

fn compute_policy_id(bytes: &[u8]) -> PolicyId {
    let mut id = [0u8; 32];
    let hash = Sha256::digest(bytes);
    id.copy_from_slice(&hash);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::zkboo::validator::ZkBooCapsuleValidator;
    use crate::core::policy::CapsuleValidator;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn metadata_sets_flag_and_verifier() {
        let mut circuit = Circuit::new(2);
        let out = circuit.add_and(0, 1);
        circuit.set_outputs(&[out]);
        let policy = ZkBooPolicy::new(circuit);
        let metadata = policy.metadata(0, 0);
        assert!(metadata.supports_zkboo());
        assert_eq!(metadata.verifiers.len(), 1);
        assert_eq!(metadata.verifiers[0].kind, ProofKind::Policy as u8);
        assert!(!metadata.verifiers[0].verifier_blob.is_empty());
    }

    #[test]
    fn prove_and_validate_capsule() {
        let mut circuit = Circuit::new(2);
        let out = circuit.add_and(0, 1);
        circuit.set_outputs(&[out]);
        let policy = ZkBooPolicy::new(circuit);
        let metadata = policy.metadata(0, 0);
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let capsule = policy
            .prove_with_rng(&[1, 1], 4, &mut rng)
            .expect("prove");
        let validator = ZkBooCapsuleValidator::new();
        validator
            .validate(&capsule, &metadata)
            .expect("validate");
    }
}
