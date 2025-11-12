//! Forwarding verification pipeline traits.

use alloc::vec::Vec;

use crate::core::policy::{PolicyCapsule, PolicyRegistry};
use crate::policy::CapsuleValidator;
use crate::types::{Error, Result};

pub trait ForwardPipeline {
    fn enforce<V: CapsuleValidator + ?Sized>(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &V,
    ) -> Result<Option<(PolicyCapsule, usize)>>;
}

pub struct RegistryForwardPipeline;

impl RegistryForwardPipeline {
    pub const fn new() -> Self {
        Self
    }
}

impl ForwardPipeline for RegistryForwardPipeline {
    fn enforce<V: CapsuleValidator + ?Sized>(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &V,
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
