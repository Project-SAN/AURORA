//! Forwarding verification pipeline traits.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::core::policy::{PolicyCapsule, PolicyId, PolicyRegistry, PolicyRole};
use crate::policy::CapsuleValidator;
use crate::types::{Error, Result};

pub trait ForwardPipeline {
    fn enforce(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &dyn CapsuleValidator,
        role: PolicyRole,
    ) -> Result<Option<(PolicyCapsule, usize)>>;

    fn enforce_batch(
        &self,
        registry: &PolicyRegistry,
        payloads: &mut [Vec<u8>],
        validator: &dyn CapsuleValidator,
        role: PolicyRole,
    ) -> Result<Vec<Option<(PolicyCapsule, usize)>>> {
        let mut out = Vec::with_capacity(payloads.len());
        for payload in payloads.iter_mut() {
            out.push(self.enforce(registry, payload, validator, role)?);
        }
        Ok(out)
    }

    fn drain_pending(
        &self,
        _registry: &PolicyRegistry,
        _validator: &dyn CapsuleValidator,
        _roles: &BTreeMap<PolicyId, PolicyRole>,
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
        role: PolicyRole,
    ) -> Result<Option<(PolicyCapsule, usize)>> {
        if registry.is_empty() {
            return Ok(None);
        }
        registry
            .enforce_with_role(payload, validator, role)
            .map(Some)
            .map_err(|err| match err {
                Error::PolicyViolation => Error::PolicyViolation,
                other => other,
            })
    }
}
