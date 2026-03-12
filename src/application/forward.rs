//! Forwarding verification pipeline traits.

use alloc::vec::Vec;

use crate::core::policy::{PolicyCapsule, PolicyRegistry, PolicyRole};
use crate::node::pipeline::ForwardPipeline;
use crate::policy::CapsuleValidator;
use crate::types::Error;

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
    ) -> core::result::Result<Option<(PolicyCapsule, usize)>, Error> {
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
