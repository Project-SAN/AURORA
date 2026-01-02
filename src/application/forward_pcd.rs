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
    pub const fn new() -> Self {
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
        let Some(part) = capsule
            .parts
            .iter_mut()
            .find(|part| part.kind == ProofKind::Consistency)
        else {
            return Err(Error::PolicyViolation);
        };
        let exts = capsule
            .extensions_for(ProofKind::Consistency)?
            .ok_or(Error::PolicyViolation)?;
        let mut hkey = None;
        let mut root = None;
        let mut htarget = None;
        let mut seq = None;
        let mut prev_hash = None;
        for ext in exts {
            match ext {
                CapsuleExtension::PcdKeyHash(value) => hkey = Some(value),
                CapsuleExtension::PcdRoot(value) => root = Some(value),
                CapsuleExtension::PcdTargetHash(value) => htarget = Some(value),
                CapsuleExtension::PcdSeq(value) => seq = Some(value),
                CapsuleExtension::PcdState(value) => prev_hash = Some(value),
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
        let next = self.backend.step(&state);
        let next_hash = self.backend.hash(&next);
        part.aux = crate::core::policy::encode_extensions(&[
            CapsuleExtension::PcdKeyHash(next.hkey),
            CapsuleExtension::PcdRoot(next.root),
            CapsuleExtension::PcdTargetHash(next.htarget),
            CapsuleExtension::PcdSeq(next.seq),
            CapsuleExtension::PcdState(next_hash),
        ]);

        let mut encoded = capsule.encode();
        if encoded.len() != consumed {
            return Err(Error::Length);
        }
        payload[..consumed].copy_from_slice(&encoded);
        Ok(Some((capsule, consumed)))
    }
}
