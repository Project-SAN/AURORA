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
                Error::PolicyViolation | Error::Length => Error::PolicyViolation,
                other => other,
            })
    }
}
