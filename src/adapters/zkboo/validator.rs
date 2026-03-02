use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::core::policy::{
    find_extension, CapsuleValidator, PolicyCapsule, PolicyMetadata, PolicyRole, ProofKind,
    EXT_TAG_PAYLOAD_HASH, EXT_TAG_PCD_KEY_HASH,
};
use crate::crypto::zkp::{Circuit, Engine, Proof, VerifierConfig};
use crate::types::{Error, Result};
use spin::Mutex;

pub struct ZkBooCapsuleValidator {
    cache: Mutex<BTreeMap<([u8; 32], u8), Arc<Circuit>>>,
}

impl ZkBooCapsuleValidator {
    pub const fn new() -> Self {
        Self {
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn load_circuit(
        &self,
        metadata: &PolicyMetadata,
        kind: ProofKind,
    ) -> Result<Option<Arc<Circuit>>> {
        let Some(entry) = metadata
            .verifiers
            .iter()
            .find(|entry| entry.kind == kind as u8)
        else {
            return Ok(None);
        };
        if entry.verifier_blob.is_empty() {
            return Ok(None);
        }
        let mut cache = self.cache.lock();
        let key = (metadata.policy_id, kind as u8);
        if let Some(circuit) = cache.get(&key) {
            return Ok(Some(circuit.clone()));
        }
        let circuit = Circuit::decode(entry.verifier_blob.as_slice())?;
        let circuit = Arc::new(circuit);
        cache.insert(key, circuit.clone());
        Ok(Some(circuit))
    }

    fn output_bits_for_part(&self, part_kind: ProofKind, part_aux: &[u8]) -> Result<Vec<u8>> {
        match part_kind {
            ProofKind::KeyBinding => {
                let hkey = find_32(part_aux, EXT_TAG_PCD_KEY_HASH)?;
                Ok(bytes_to_bits_lsb_first(&hkey))
            }
            ProofKind::Consistency => {
                let hkey = find_32(part_aux, EXT_TAG_PCD_KEY_HASH)?;
                let payload = find_32(part_aux, EXT_TAG_PAYLOAD_HASH)?;
                let mut out = Vec::with_capacity(32 * 8 * 2);
                out.extend_from_slice(&bytes_to_bits_lsb_first(&hkey));
                out.extend_from_slice(&bytes_to_bits_lsb_first(&payload));
                Ok(out)
            }
            ProofKind::Policy => {
                let payload = match find_extension(part_aux, EXT_TAG_PAYLOAD_HASH)? {
                    Some(bytes) => {
                        if bytes.len() != 32 {
                            return Err(Error::PolicyViolation);
                        }
                        let mut out = [0u8; 32];
                        out.copy_from_slice(bytes);
                        Some(out)
                    }
                    None => None,
                };
                match payload {
                    Some(payload) => {
                        let mut out = Vec::with_capacity(32 * 8 + 1);
                        out.extend_from_slice(&bytes_to_bits_lsb_first(&payload));
                        out.push(1); // allow bit must be 1
                        Ok(out)
                    }
                    // Backward-compatible mode: legacy ZKBoo circuits use a single output bit == 1.
                    None => Ok(Vec::from([1u8])),
                }
            }
        }
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
        let expected_kind = match role {
            PolicyRole::Entry => ProofKind::KeyBinding,
            PolicyRole::Middle => ProofKind::Consistency,
            PolicyRole::Exit | PolicyRole::All => ProofKind::Policy,
        };
        let part = capsule.part(expected_kind).ok_or(Error::PolicyViolation)?;
        let Some(circuit) = self.load_circuit(metadata, expected_kind)? else {
            return Err(Error::PolicyViolation);
        };
        let proof = Proof::from_part(part).map_err(|_| Error::PolicyViolation)?;
        let outputs = self.output_bits_for_part(expected_kind, part.aux())?;
        if outputs.len() != circuit.outputs.len() {
            return Err(Error::PolicyViolation);
        }
        let engine = Engine;
        engine
            .verify(
                circuit.as_ref(),
                &outputs,
                &proof,
                VerifierConfig {
                    rounds: proof.rounds,
                },
            )
            .map_err(|_| Error::PolicyViolation)?;

        // Cross-part linkage checks for the 3-part ZKBoo capsule:
        // KeyBinding(hkey) <-> Consistency(hkey, payload_hash) <-> Policy(payload_hash, allow=1)
        match role {
            PolicyRole::Middle => {
                let cons_hkey = find_32(part.aux(), EXT_TAG_PCD_KEY_HASH)?;
                let cons_payload = find_32(part.aux(), EXT_TAG_PAYLOAD_HASH)?;
                let kb = capsule
                    .part(ProofKind::KeyBinding)
                    .ok_or(Error::PolicyViolation)?;
                let pol = capsule
                    .part(ProofKind::Policy)
                    .ok_or(Error::PolicyViolation)?;
                let kb_hkey = find_32(kb.aux(), EXT_TAG_PCD_KEY_HASH)?;
                let pol_payload = find_32(pol.aux(), EXT_TAG_PAYLOAD_HASH)?;
                if kb_hkey != cons_hkey || pol_payload != cons_payload {
                    return Err(Error::PolicyViolation);
                }
            }
            PolicyRole::Exit => {
                // Exit verifies Policy; additionally require that the payload_hash matches
                // the one carried by the Consistency part (verified earlier in the path).
                if let Some(cons) = capsule.part(ProofKind::Consistency) {
                    let pol_payload = find_32(part.aux(), EXT_TAG_PAYLOAD_HASH)?;
                    let cons_payload = find_32(cons.aux(), EXT_TAG_PAYLOAD_HASH)?;
                    if pol_payload != cons_payload {
                        return Err(Error::PolicyViolation);
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }
}

fn find_32(aux: &[u8], tag: u8) -> Result<[u8; 32]> {
    let Some(bytes) = find_extension(aux, tag)? else {
        return Err(Error::PolicyViolation);
    };
    if bytes.len() != 32 {
        return Err(Error::PolicyViolation);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn bytes_to_bits_lsb_first(bytes: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes.iter() {
        for bit in 0..8u8 {
            out.push(((b >> bit) & 1) as u8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::{encode_extensions_into, CapsuleExtensionRef, EXT_TAG_SEQUENCE};
    use crate::crypto::ascon::{mix_fold, MIX_DOMAIN_KEYBIND};
    use crate::crypto::zkp::ascon_circuit;
    use crate::policy::zkboo::ZkBooProofService;
    use alloc::vec;

    #[test]
    fn keybinding_proof_validates_for_entry_role() {
        let circuit = ascon_circuit::build_keybinding_circuit(32);
        let policy_id = [0x42u8; 32];
        let rounds = 8u16;

        let secret: Vec<u8> = (0u8..32u8).collect();
        let hkey = mix_fold(MIX_DOMAIN_KEYBIND, &secret);
        let sequence = 0x0102_0304_0506_0708u64.to_be_bytes();

        let mut aux_buf = [0u8; crate::core::policy::AUX_MAX];
        let aux_len = encode_extensions_into(
            &[
                CapsuleExtensionRef {
                    tag: EXT_TAG_SEQUENCE,
                    data: &sequence,
                },
                CapsuleExtensionRef {
                    tag: EXT_TAG_PCD_KEY_HASH,
                    data: &hkey,
                },
            ],
            &mut aux_buf,
        )
        .expect("aux");
        let aux = aux_buf[..aux_len].to_vec();

        let metadata = PolicyMetadata {
            policy_id,
            version: 1,
            expiry: 0,
            flags: crate::core::policy::metadata::POLICY_FLAG_ZKBOO,
            verifiers: vec![crate::core::policy::VerifierEntry {
                kind: ProofKind::KeyBinding as u8,
                verifier_blob: circuit.encode(),
            }],
        };

        let service = ZkBooProofService::new_with_policy_id(circuit, policy_id, rounds);
        let cap = service
            .prove_payload_lsb_first(&secret, &aux)
            .expect("prove");
        let mut part = cap.parts[0].clone();
        part.kind = ProofKind::KeyBinding;
        part.set_aux(&aux).expect("set aux");

        let capsule = PolicyCapsule {
            policy_id,
            version: crate::core::policy::POLICY_CAPSULE_VERSION,
            part_count: 1,
            parts: [
                part,
                crate::core::policy::ProofPart::default(),
                crate::core::policy::ProofPart::default(),
                crate::core::policy::ProofPart::default(),
            ],
        };

        let validator = ZkBooCapsuleValidator::new();
        validator
            .validate_with_role(&capsule, &metadata, PolicyRole::Entry)
            .expect("validate");
    }
}
