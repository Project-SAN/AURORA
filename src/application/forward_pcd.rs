use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::application::forward::ForwardPipeline;
use crate::core::policy::{CapsuleExtension, PolicyCapsule, PolicyRegistry, ProofKind};
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
    ) -> Result<Option<(PolicyCapsule, usize)>> {
        if registry.is_empty() {
            return Ok(None);
        }
        let (mut capsule, consumed) = PolicyCapsule::decode(payload.as_slice())?;
        let metadata = registry
            .get(&capsule.policy_id)
            .ok_or(Error::PolicyViolation)?;
        validator.validate(&capsule, metadata)?;
        if !metadata.supports_pcd() {
            return Ok(Some((capsule, consumed)));
        }
        let exts = capsule
            .extensions_for(ProofKind::Consistency)?
            .ok_or(Error::PolicyViolation)?;
        let key_exts = capsule.extensions_for(ProofKind::KeyBinding)?.unwrap_or_default();
        let Some(part) = capsule
            .parts
            .iter_mut()
            .find(|part| part.kind == ProofKind::Consistency)
        else {
            return Err(Error::PolicyViolation);
        };
        let mut hkey = None;
        let mut root = None;
        let mut htarget = None;
        let mut seq = None;
        let mut prev_hash = None;
        let mut proof = None;
        for ext in key_exts {
            if let CapsuleExtension::PcdKeyHash(value) = ext {
                hkey = Some(value);
                break;
            }
        }
        for ext in exts {
            match ext {
                CapsuleExtension::PcdKeyHash(value) => {
                    if let Some(expected) = hkey {
                        if value != expected {
                            return Err(Error::PolicyViolation);
                        }
                    } else {
                        hkey = Some(value);
                    }
                }
                CapsuleExtension::PcdRoot(value) => root = Some(value),
                CapsuleExtension::PcdTargetHash(value) => htarget = Some(value),
                CapsuleExtension::PcdSeq(value) => seq = Some(value),
                CapsuleExtension::PcdState(value) => prev_hash = Some(value),
                CapsuleExtension::PcdProof(bytes) => proof = Some(bytes),
                _ => {}
            }
        }
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
        self.backend.verify_step(&state, &proof)?;
        let next = self.backend.step(&state);
        let next_hash = self.backend.hash(&next);
        let next_proof = self.backend.prove_step(&state, &proof)?;
        part.aux = crate::core::policy::encode_extensions(&[
            CapsuleExtension::PcdKeyHash(next.hkey),
            CapsuleExtension::PcdRoot(next.root),
            CapsuleExtension::PcdTargetHash(next.htarget),
            CapsuleExtension::PcdSeq(next.seq),
            CapsuleExtension::PcdState(next_hash),
            CapsuleExtension::PcdProof(next_proof),
        ]);

        let encoded = capsule.encode();
        if encoded.len() != consumed {
            return Err(Error::Length);
        }
        payload[..consumed].copy_from_slice(&encoded);
        Ok(Some((capsule, consumed)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::{encode_extensions, CapsuleExtension, PolicyCapsule, ProofPart};
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

        let consistency_aux = encode_extensions(&[
            CapsuleExtension::PcdKeyHash(init_state.hkey),
            CapsuleExtension::PcdRoot(init_state.root),
            CapsuleExtension::PcdTargetHash(init_state.htarget),
            CapsuleExtension::PcdSeq(init_state.seq),
            CapsuleExtension::PcdState(init_hash),
            CapsuleExtension::PcdProof(Vec::new()),
        ]);
        let capsule = PolicyCapsule {
            policy_id,
            version: 1,
            parts: vec![
                ProofPart {
                    kind: ProofKind::Consistency,
                    proof: vec![],
                    commitment: vec![],
                    aux: consistency_aux,
                },
                ProofPart {
                    kind: ProofKind::Policy,
                    proof: vec![],
                    commitment: vec![],
                    aux: vec![],
                },
            ],
        };
        let mut payload = capsule.encode();

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let (updated, _consumed) = pipeline
            .enforce(&registry, &mut payload, &validator)
            .expect("enforce")
            .expect("capsule");

        let exts = updated
            .extensions_for(ProofKind::Consistency)
            .expect("extensions")
            .expect("exts present");
        let mut seq = None;
        let mut state_hash = None;
        for ext in exts {
            match ext {
                CapsuleExtension::PcdSeq(value) => seq = Some(value),
                CapsuleExtension::PcdState(value) => state_hash = Some(value),
                _ => {}
            }
        }
        assert_eq!(seq, Some(2));
        let next_state = init_state.next_seq();
        assert_eq!(state_hash, Some(next_state.hash()));
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
        let consistency_aux = encode_extensions(&[
            CapsuleExtension::PcdKeyHash(init_state.hkey),
            CapsuleExtension::PcdRoot(init_state.root),
            CapsuleExtension::PcdTargetHash(init_state.htarget),
            CapsuleExtension::PcdSeq(init_state.seq),
            CapsuleExtension::PcdState(bad_hash),
            CapsuleExtension::PcdProof(Vec::new()),
        ]);
        let capsule = PolicyCapsule {
            policy_id,
            version: 1,
            parts: vec![
                ProofPart {
                    kind: ProofKind::Consistency,
                    proof: vec![],
                    commitment: vec![],
                    aux: consistency_aux,
                },
                ProofPart {
                    kind: ProofKind::Policy,
                    proof: vec![],
                    commitment: vec![],
                    aux: vec![],
                },
            ],
        };
        let mut payload = capsule.encode();

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let result = pipeline.enforce(&registry, &mut payload, &validator);
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
        let consistency_aux = encode_extensions(&[
            CapsuleExtension::PcdKeyHash(init_state.hkey),
            CapsuleExtension::PcdRoot(init_state.root),
            CapsuleExtension::PcdTargetHash(init_state.htarget),
            CapsuleExtension::PcdSeq(init_state.seq),
            CapsuleExtension::PcdState(init_hash),
            CapsuleExtension::PcdProof(vec![0x99]),
        ]);
        let capsule = PolicyCapsule {
            policy_id,
            version: 1,
            parts: vec![
                ProofPart {
                    kind: ProofKind::Consistency,
                    proof: vec![],
                    commitment: vec![],
                    aux: consistency_aux,
                },
                ProofPart {
                    kind: ProofKind::Policy,
                    proof: vec![],
                    commitment: vec![],
                    aux: vec![],
                },
            ],
        };
        let mut payload = capsule.encode();

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let result = pipeline.enforce(&registry, &mut payload, &validator);
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

        let keybinding_aux = encode_extensions(&[CapsuleExtension::PcdKeyHash(key_hkey)]);
        let consistency_aux = encode_extensions(&[
            CapsuleExtension::PcdKeyHash(key_hkey),
            CapsuleExtension::PcdRoot(init_state.root),
            CapsuleExtension::PcdTargetHash(init_state.htarget),
            CapsuleExtension::PcdSeq(init_state.seq),
            CapsuleExtension::PcdState(init_hash),
            CapsuleExtension::PcdProof(Vec::new()),
        ]);
        assert!(matches!(
            crate::core::policy::decode_extensions(&keybinding_aux),
            Ok(Some(_))
        ));
        assert!(matches!(
            crate::core::policy::decode_extensions(&consistency_aux),
            Ok(Some(_))
        ));
        let capsule = PolicyCapsule {
            policy_id,
            version: 1,
            parts: vec![
                ProofPart {
                    kind: ProofKind::KeyBinding,
                    proof: vec![],
                    commitment: vec![],
                    aux: keybinding_aux,
                },
                ProofPart {
                    kind: ProofKind::Consistency,
                    proof: vec![],
                    commitment: vec![],
                    aux: consistency_aux,
                },
                ProofPart {
                    kind: ProofKind::Policy,
                    proof: vec![],
                    commitment: vec![],
                    aux: vec![],
                },
            ],
        };
        let mut payload = capsule.encode();
        let (decoded, _) = PolicyCapsule::decode(&payload).expect("decode");
        assert!(decoded.extensions_for(ProofKind::KeyBinding).is_ok());
        assert!(decoded.extensions_for(ProofKind::Consistency).is_ok());

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let result = pipeline.enforce(&registry, &mut payload, &validator);
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

        let keybinding_aux = encode_extensions(&[CapsuleExtension::PcdKeyHash(key_hkey)]);
        let consistency_aux = encode_extensions(&[
            CapsuleExtension::PcdKeyHash(consistency_hkey),
            CapsuleExtension::PcdRoot(init_state.root),
            CapsuleExtension::PcdTargetHash(init_state.htarget),
            CapsuleExtension::PcdSeq(init_state.seq),
            CapsuleExtension::PcdState(init_hash),
            CapsuleExtension::PcdProof(Vec::new()),
        ]);
        let capsule = PolicyCapsule {
            policy_id,
            version: 1,
            parts: vec![
                ProofPart {
                    kind: ProofKind::KeyBinding,
                    proof: vec![],
                    commitment: vec![],
                    aux: keybinding_aux,
                },
                ProofPart {
                    kind: ProofKind::Consistency,
                    proof: vec![],
                    commitment: vec![],
                    aux: consistency_aux,
                },
                ProofPart {
                    kind: ProofKind::Policy,
                    proof: vec![],
                    commitment: vec![],
                    aux: vec![],
                },
            ],
        };
        let mut payload = capsule.encode();

        let pipeline = PcdForwardPipeline::new();
        let validator = NoopValidator;
        let result = pipeline.enforce(&registry, &mut payload, &validator);
        assert!(matches!(result, Err(Error::PolicyViolation)));
    }
}
