use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::core::policy::{CapsuleValidator, PolicyCapsule, PolicyId, PolicyMetadata, ProofKind};
use crate::types::{Error, Result};
use dusk_bytes::Serializable;
use dusk_plonk::{composer::Verifier as PlonkVerifier, prelude::BlsScalar, proof_system::Proof};
use sha2::{Digest, Sha512};
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
        public_inputs: &[BlsScalar],
    ) -> Result<()> {
        if proof_bytes.len() != Proof::SIZE {
            return Err(Error::PolicyViolation);
        }
        let mut proof_buf = [0u8; Proof::SIZE];
        proof_buf.copy_from_slice(proof_bytes);
        let proof = Proof::from_bytes(&proof_buf).map_err(|_| Error::PolicyViolation)?;

        verifier
            .verify(&proof, public_inputs)
            .map_err(|_| Error::PolicyViolation)
    }
}

impl CapsuleValidator for PlonkCapsuleValidator {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()> {
        for part in &capsule.parts {
            let Some(verifier) = self.load_verifier(metadata, part.kind as u8)? else {
                continue;
            };
            if part.kind == ProofKind::KeyBinding {
                if let Some(inputs) = keybinding_public_inputs(capsule) {
                    Self::validate_proof_bytes(&verifier, &part.proof, &inputs)?;
                } else {
                    let hkey = parse_commitment_scalar(&part.commitment)?;
                    Self::validate_proof_bytes(&verifier, &part.proof, &[BlsScalar::zero(), hkey])?;
                }
            } else {
                let inputs = parse_commitment_scalar(&part.commitment)?;
                Self::validate_proof_bytes(&verifier, &part.proof, &[inputs])?;
            }
            if let Ok(Some(exts)) = capsule.extensions_for(part.kind) {
                for ext in exts {
                    if let crate::core::policy::CapsuleExtension::PrecomputeProof(bytes) = ext {
                        let inputs = parse_commitment_scalar(&part.commitment)?;
                        Self::validate_proof_bytes(&verifier, bytes.as_slice(), &[inputs])?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn parse_commitment_scalar(commitment: &[u8]) -> Result<BlsScalar> {
    if commitment.len() != BlsScalar::SIZE {
        return Err(Error::PolicyViolation);
    }
    let mut commit_bytes = [0u8; BlsScalar::SIZE];
    commit_bytes.copy_from_slice(commitment);
    BlsScalar::from_bytes(&commit_bytes).map_err(|_| Error::PolicyViolation)
}

fn keybinding_public_inputs(capsule: &PolicyCapsule) -> Option<Vec<BlsScalar>> {
    let key_exts = capsule.extensions_for(ProofKind::KeyBinding).ok()??;
    let mut session_nonce = None;
    let mut route_id = None;
    for ext in key_exts {
        match ext {
            crate::core::policy::CapsuleExtension::SessionNonce(value) => {
                session_nonce = Some(value)
            }
            crate::core::policy::CapsuleExtension::RouteId(value) => route_id = Some(value),
            _ => {}
        }
    }
    let cons_exts = capsule.extensions_for(ProofKind::Consistency).ok()??;
    let mut htarget = None;
    for ext in cons_exts {
        if let crate::core::policy::CapsuleExtension::PcdTargetHash(value) = ext {
            htarget = Some(value);
            break;
        }
    }
    let (session_nonce, route_id, htarget) =
        (session_nonce?, route_id?, htarget?);
    let key_part = capsule.part(ProofKind::KeyBinding)?;
    let hkey = parse_commitment_scalar(&key_part.commitment).ok()?;
    let salt = keybinding_salt(&capsule.policy_id, &htarget, &session_nonce, &route_id);
    Some(vec![salt, hkey])
}

fn keybinding_salt(
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
