use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::application::forward::ForwardPipeline;
use crate::core::policy::{
    encode_extensions_into, find_extension, CapsuleExtensionRef, PolicyCapsule, PolicyRegistry,
    PolicyRole, ProofKind, AUX_MAX, EXT_TAG_PCD_KEY_HASH, EXT_TAG_PCD_PROOF, EXT_TAG_PCD_ROOT,
    EXT_TAG_PCD_SEQ, EXT_TAG_PCD_STATE, EXT_TAG_PCD_TARGET_HASH,
};
use crate::pcd::{PcdBackend, PcdState};
use crate::policy::CapsuleValidator;
use crate::types::{Error, Result};

pub struct PcdForwardPipeline {
    backend: Box<dyn PcdBackend>,
}

impl PcdForwardPipeline {
    pub fn new() -> Self {
        Self {
            backend: Box::new(crate::pcd::HashPcdBackend),
        }
    }

    pub fn with_backend(backend: Box<dyn PcdBackend>) -> Self {
        Self { backend }
    }
}

impl ForwardPipeline for PcdForwardPipeline {
    fn enforce(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &dyn CapsuleValidator,
        role: PolicyRole,
    ) -> Result<Option<(PolicyCapsule, usize)>> {
        if registry.is_empty() {
            return Ok(None);
        }
        let (mut capsule, consumed) = PolicyCapsule::decode(payload.as_slice())?;
        let metadata = registry
            .get(&capsule.policy_id)
            .ok_or(Error::PolicyViolation)?;
        for required in role.required_kinds() {
            if capsule.part(*required).is_none() {
                return Err(Error::PolicyViolation);
            }
        }
        validator.validate_with_role(&capsule, metadata, role)?;
        if !metadata.supports_pcd() {
            return Ok(Some((capsule, consumed)));
        }
        let part_count = capsule.part_count as usize;
        let cons_index = capsule.parts[..part_count]
            .iter()
            .position(|part| part.kind == ProofKind::Consistency)
            .ok_or(Error::PolicyViolation)?;
        let key_index = capsule.parts[..part_count]
            .iter()
            .position(|part| part.kind == ProofKind::KeyBinding);

        let mut cons_aux_buf = [0u8; AUX_MAX];
        let cons_aux_len = capsule.parts[cons_index].aux_len as usize;
        cons_aux_buf[..cons_aux_len].copy_from_slice(capsule.parts[cons_index].aux());
        let cons_aux = &cons_aux_buf[..cons_aux_len];

        let mut key_aux_buf = [0u8; AUX_MAX];
        let key_aux = if let Some(key_idx) = key_index {
            let key_len = capsule.parts[key_idx].aux_len as usize;
            key_aux_buf[..key_len].copy_from_slice(capsule.parts[key_idx].aux());
            &key_aux_buf[..key_len]
        } else {
            &[][..]
        };

        let part = &mut capsule.parts[cons_index];
        let mut hkey = None;
        if let Some(value) = find_ext_32(key_aux, EXT_TAG_PCD_KEY_HASH) {
            hkey = Some(value);
        }
        if let Some(value) = find_ext_32(cons_aux, EXT_TAG_PCD_KEY_HASH) {
            if let Some(expected) = hkey {
                if value != expected {
                    return Err(Error::PolicyViolation);
                }
            } else {
                hkey = Some(value);
            }
        }
        let root = find_ext_32(cons_aux, EXT_TAG_PCD_ROOT);
        let htarget = find_ext_32(cons_aux, EXT_TAG_PCD_TARGET_HASH);
        let seq = find_ext_u64(cons_aux, EXT_TAG_PCD_SEQ);
        let prev_hash = find_ext_32(cons_aux, EXT_TAG_PCD_STATE);
        let proof = find_extension(cons_aux, EXT_TAG_PCD_PROOF).ok().flatten();
        let state = PcdState {
            hkey: hkey.ok_or(Error::PolicyViolation)?,
            seq: seq.ok_or(Error::PolicyViolation)?,
            root: root.ok_or(Error::PolicyViolation)?,
            htarget: htarget.ok_or(Error::PolicyViolation)?,
        };
        if let Some(expected) = prev_hash {
            if self.backend.hash(&state) != expected {
                return Err(Error::PolicyViolation);
            }
        }
        let proof = proof.ok_or(Error::PolicyViolation)?;
        self.backend.verify_step(&state, proof)?;
        let next = self.backend.step(&state);
        let next_hash = self.backend.hash(&next);
        let next_proof = self.backend.prove_step(&state, &proof)?;
        let seq_buf = next.seq.to_be_bytes();
        let exts = [
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_KEY_HASH,
                data: &next.hkey,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_ROOT,
                data: &next.root,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_TARGET_HASH,
                data: &next.htarget,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_SEQ,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_STATE,
                data: &next_hash,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_PROOF,
                data: &next_proof,
            },
        ];
        let mut aux_buf = [0u8; AUX_MAX];
        let aux_len = encode_extensions_into(&exts, &mut aux_buf)?;
        part.set_aux(&aux_buf[..aux_len])?;

        let mut encoded = [0u8; crate::core::policy::MAX_CAPSULE_LEN];
        let encoded_len = capsule.encode_into(&mut encoded)?;
        if encoded_len != consumed {
            return Err(Error::Length);
        }
        payload[..consumed].copy_from_slice(&encoded[..encoded_len]);
        Ok(Some((capsule, consumed)))
    }
}

fn find_ext_32(aux: &[u8], tag: u8) -> Option<[u8; 32]> {
    let bytes = find_extension(aux, tag).ok()??;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Some(out)
}

fn find_ext_u64(aux: &[u8], tag: u8) -> Option<u64> {
    let bytes = find_extension(aux, tag).ok()??;
    if bytes.len() != 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Some(u64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::{
        encode_extensions_into, find_extension, CapsuleExtensionRef, PolicyCapsule, ProofPart,
        AUX_MAX, COMMIT_LEN, MAX_CAPSULE_LEN, MAX_PARTS, PROOF_LEN, EXT_TAG_PCD_KEY_HASH,
        EXT_TAG_PCD_PROOF, EXT_TAG_PCD_ROOT, EXT_TAG_PCD_SEQ, EXT_TAG_PCD_STATE,
        EXT_TAG_PCD_TARGET_HASH,
    };
    use crate::core::policy::{PolicyMetadata, PolicyRegistry, VerifierEntry};
    use crate::core::policy::metadata::POLICY_FLAG_PCD;

    struct NoopValidator;

    impl crate::core::policy::CapsuleValidator for NoopValidator {
        fn validate(
            &self,
            _capsule: &PolicyCapsule,
            _metadata: &PolicyMetadata,
        ) -> crate::types::Result<()> {
            Ok(())
        }
    }

    fn make_aux(exts: &[CapsuleExtensionRef<'_>]) -> Vec<u8> {
        let mut buf = [0u8; AUX_MAX];
        let len = encode_extensions_into(exts, &mut buf).expect("encode exts");
        buf[..len].to_vec()
    }

    fn make_part(kind: ProofKind, aux: &[u8]) -> ProofPart {
        let mut part = ProofPart {
            kind,
            proof: [0u8; PROOF_LEN],
            commitment: [0u8; COMMIT_LEN],
            aux_len: 0,
            aux: [0u8; AUX_MAX],
        };
        part.set_aux(aux).expect("set aux");
        part
    }

    fn make_capsule(policy_id: [u8; 32], version: u8, parts: &[ProofPart]) -> PolicyCapsule {
        let mut arr = [ProofPart::default(), ProofPart::default(), ProofPart::default(), ProofPart::default()];
        let mut count = 0usize;
        for part in parts {
            arr[count] = *part;
            count += 1;
        }
        PolicyCapsule {
            policy_id,
            version,
            part_count: count.min(MAX_PARTS) as u8,
            parts: arr,
        }
    }

    fn encode_capsule(capsule: &PolicyCapsule) -> Vec<u8> {
        let mut buf = [0u8; MAX_CAPSULE_LEN];
        let len = capsule.encode_into(&mut buf).expect("encode capsule");
        buf[..len].to_vec()
    }

    #[test]
    fn pcd_forward_pipeline_updates_state() {
        let mut registry = PolicyRegistry::new();
        let policy_id = [0xAB; 32];
        let metadata = PolicyMetadata {
            policy_id,
            version: 1,
            expiry: 0,
            flags: POLICY_FLAG_PCD,
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Consistency as u8,
                verifier_blob: vec![],
            }],
        };
        registry.register(metadata).expect("register");

        let init_state = PcdState {
            hkey: [1u8; 32],
            seq: 1,
            root: [2u8; 32],
            htarget: [3u8; 32],
        };
        let init_hash = init_state.hash();
        let seq_buf = init_state.seq.to_be_bytes();
        let consistency_aux = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_KEY_HASH,
                data: &init_state.hkey,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_ROOT,
                data: &init_state.root,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_TARGET_HASH,
                data: &init_state.htarget,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_SEQ,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_STATE,
                data: &init_hash,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_PROOF,
                data: &[],
            },
        ]);
        let capsule = make_capsule(
            policy_id,
            1,
            &[
                make_part(ProofKind::Consistency, &consistency_aux),
                make_part(ProofKind::Policy, &[]),
            ],
        );
        let mut payload = encode_capsule(&capsule);

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let (updated, _consumed) = pipeline
            .enforce(&registry, &mut payload, &validator, PolicyRole::All)
            .expect("enforce")
            .expect("capsule");

        let cons_part = updated.part(ProofKind::Consistency).expect("cons part");
        let seq_bytes = find_extension(cons_part.aux(), EXT_TAG_PCD_SEQ)
            .expect("seq ext")
            .expect("seq bytes");
        let mut seq_buf = [0u8; 8];
        seq_buf.copy_from_slice(seq_bytes);
        let seq = u64::from_be_bytes(seq_buf);
        assert_eq!(seq, 2);
        let next_state = init_state.next_seq();
        let state_bytes = find_extension(cons_part.aux(), EXT_TAG_PCD_STATE)
            .expect("state ext")
            .expect("state bytes");
        let mut state_hash = [0u8; 32];
        state_hash.copy_from_slice(state_bytes);
        assert_eq!(state_hash, next_state.hash());
    }

    #[test]
    fn pcd_forward_pipeline_rejects_bad_state_hash() {
        let mut registry = PolicyRegistry::new();
        let policy_id = [0xCD; 32];
        let metadata = PolicyMetadata {
            policy_id,
            version: 1,
            expiry: 0,
            flags: POLICY_FLAG_PCD,
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Consistency as u8,
                verifier_blob: vec![],
            }],
        };
        registry.register(metadata).expect("register");

        let init_state = PcdState {
            hkey: [9u8; 32],
            seq: 1,
            root: [8u8; 32],
            htarget: [7u8; 32],
        };
        let bad_hash = [0xAA; 32];
        let seq_buf = init_state.seq.to_be_bytes();
        let consistency_aux = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_KEY_HASH,
                data: &init_state.hkey,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_ROOT,
                data: &init_state.root,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_TARGET_HASH,
                data: &init_state.htarget,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_SEQ,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_STATE,
                data: &bad_hash,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_PROOF,
                data: &[],
            },
        ]);
        let capsule = make_capsule(
            policy_id,
            1,
            &[
                make_part(ProofKind::Consistency, &consistency_aux),
                make_part(ProofKind::Policy, &[]),
            ],
        );
        let mut payload = encode_capsule(&capsule);

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let result = pipeline.enforce(
            &registry,
            &mut payload,
            &validator,
            PolicyRole::All,
        );
        assert!(matches!(result, Err(Error::PolicyViolation)));
    }

    #[test]
    fn pcd_forward_pipeline_rejects_bad_proof() {
        let mut registry = PolicyRegistry::new();
        let policy_id = [0xEF; 32];
        let metadata = PolicyMetadata {
            policy_id,
            version: 1,
            expiry: 0,
            flags: POLICY_FLAG_PCD,
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Consistency as u8,
                verifier_blob: vec![],
            }],
        };
        registry.register(metadata).expect("register");

        let init_state = PcdState {
            hkey: [4u8; 32],
            seq: 1,
            root: [5u8; 32],
            htarget: [6u8; 32],
        };
        let init_hash = init_state.hash();
        let seq_buf = init_state.seq.to_be_bytes();
        let proof_bytes = [0x99u8];
        let consistency_aux = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_KEY_HASH,
                data: &init_state.hkey,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_ROOT,
                data: &init_state.root,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_TARGET_HASH,
                data: &init_state.htarget,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_SEQ,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_STATE,
                data: &init_hash,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_PROOF,
                data: &proof_bytes,
            },
        ]);
        let capsule = make_capsule(
            policy_id,
            1,
            &[
                make_part(ProofKind::Consistency, &consistency_aux),
                make_part(ProofKind::Policy, &[]),
            ],
        );
        let mut payload = encode_capsule(&capsule);

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let result = pipeline.enforce(
            &registry,
            &mut payload,
            &validator,
            PolicyRole::All,
        );
        assert!(matches!(result, Err(Error::PolicyViolation)));
    }

    #[test]
    fn pcd_forward_pipeline_uses_keybinding_hkey() {
        let mut registry = PolicyRegistry::new();
        let policy_id = [0x42; 32];
        let metadata = PolicyMetadata {
            policy_id,
            version: 1,
            expiry: 0,
            flags: POLICY_FLAG_PCD,
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Consistency as u8,
                verifier_blob: vec![],
            }],
        };
        registry.register(metadata).expect("register");

        let key_hkey = [0x11; 32];
        let init_state = PcdState {
            hkey: key_hkey,
            seq: 1,
            root: [0x33; 32],
            htarget: [0x44; 32],
        };
        let init_hash = init_state.hash();
        let keybinding_aux = make_aux(&[CapsuleExtensionRef {
            tag: EXT_TAG_PCD_KEY_HASH,
            data: &key_hkey,
        }]);
        let seq_buf = init_state.seq.to_be_bytes();
        let consistency_aux = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_KEY_HASH,
                data: &key_hkey,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_ROOT,
                data: &init_state.root,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_TARGET_HASH,
                data: &init_state.htarget,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_SEQ,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_STATE,
                data: &init_hash,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_PROOF,
                data: &[],
            },
        ]);
        let capsule = make_capsule(
            policy_id,
            1,
            &[
                make_part(ProofKind::KeyBinding, &keybinding_aux),
                make_part(ProofKind::Consistency, &consistency_aux),
                make_part(ProofKind::Policy, &[]),
            ],
        );
        let mut payload = encode_capsule(&capsule);
        let (decoded, _) = PolicyCapsule::decode(&payload).expect("decode");
        assert!(find_extension(
            decoded.part(ProofKind::KeyBinding).unwrap().aux(),
            EXT_TAG_PCD_KEY_HASH
        )
        .unwrap()
        .is_some());
        assert!(find_extension(
            decoded.part(ProofKind::Consistency).unwrap().aux(),
            EXT_TAG_PCD_KEY_HASH
        )
        .unwrap()
        .is_some());

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let result = pipeline.enforce(
            &registry,
            &mut payload,
            &validator,
            PolicyRole::All,
        );
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    }

    #[test]
    fn pcd_forward_pipeline_rejects_mismatched_hkey() {
        let mut registry = PolicyRegistry::new();
        let policy_id = [0x55; 32];
        let metadata = PolicyMetadata {
            policy_id,
            version: 1,
            expiry: 0,
            flags: POLICY_FLAG_PCD,
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Consistency as u8,
                verifier_blob: vec![],
            }],
        };
        registry.register(metadata).expect("register");

        let key_hkey = [0x10; 32];
        let consistency_hkey = [0x20; 32];
        let init_state = PcdState {
            hkey: key_hkey,
            seq: 1,
            root: [0x33; 32],
            htarget: [0x44; 32],
        };
        let init_hash = init_state.hash();
        let keybinding_aux = make_aux(&[CapsuleExtensionRef {
            tag: EXT_TAG_PCD_KEY_HASH,
            data: &key_hkey,
        }]);
        let seq_buf = init_state.seq.to_be_bytes();
        let consistency_aux = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_KEY_HASH,
                data: &consistency_hkey,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_ROOT,
                data: &init_state.root,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_TARGET_HASH,
                data: &init_state.htarget,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_SEQ,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_STATE,
                data: &init_hash,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_PROOF,
                data: &[],
            },
        ]);
        let capsule = make_capsule(
            policy_id,
            1,
            &[
                make_part(ProofKind::KeyBinding, &keybinding_aux),
                make_part(ProofKind::Consistency, &consistency_aux),
                make_part(ProofKind::Policy, &[]),
            ],
        );
        let mut payload = encode_capsule(&capsule);

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let result = pipeline.enforce(
            &registry,
            &mut payload,
            &validator,
            PolicyRole::All,
        );
        assert!(matches!(result, Err(Error::PolicyViolation)));
    }
}
