//! Forwarding verification pipeline traits.

use alloc::vec::Vec;

use crate::core::policy::{PolicyCapsule, PolicyRegistry};
use crate::policy::CapsuleValidator;
use crate::types::{Error, Result};

pub trait ForwardPipeline {
    fn enforce(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &dyn CapsuleValidator,
    ) -> Result<Option<(PolicyCapsule, usize)>>;

    fn enforce_batch(
        &self,
        registry: &PolicyRegistry,
        payloads: &mut [Vec<u8>],
        validator: &dyn CapsuleValidator,
    ) -> Result<Vec<Option<(PolicyCapsule, usize)>>> {
        let mut out = Vec::with_capacity(payloads.len());
        for payload in payloads.iter_mut() {
            out.push(self.enforce(registry, payload, validator)?);
        }
        Ok(out)
    }

    fn drain_pending(
        &self,
        _registry: &PolicyRegistry,
        _validator: &dyn CapsuleValidator,
    ) -> Result<Vec<PolicyCapsule>> {
        Ok(Vec::new())
    }

    fn block_policy(&self, _policy_id: &crate::policy::PolicyId) {}
}

#[derive(Clone, Copy, Default)]
pub struct RegistryForwardPipeline;

impl RegistryForwardPipeline {
    pub const fn new() -> Self {
        Self
    }
}

impl ForwardPipeline for RegistryForwardPipeline {
    fn enforce(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &dyn CapsuleValidator,
    ) -> Result<Option<(PolicyCapsule, usize)>> {
        if registry.is_empty() {
            return Ok(None);
        }
        registry
            .enforce(payload, validator)
            .map(Some)
            .map_err(|err| match err {
                Error::PolicyViolation => Error::PolicyViolation,
                other => other,
            })
    }
}
