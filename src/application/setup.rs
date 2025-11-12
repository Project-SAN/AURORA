//! Setup flow interfaces.

use crate::core::policy::PolicyMetadata;
use crate::policy::PolicyRegistry;
use crate::types::Result;

pub trait SetupPipeline {
    fn install(&mut self, metadata: PolicyMetadata) -> Result<()>;
}

pub struct RegistrySetupPipeline<'a> {
    registry: &'a mut PolicyRegistry,
}

impl<'a> RegistrySetupPipeline<'a> {
    pub fn new(registry: &'a mut PolicyRegistry) -> Self {
        Self { registry }
    }
}

impl<'a> SetupPipeline for RegistrySetupPipeline<'a> {
    fn install(&mut self, metadata: PolicyMetadata) -> Result<()> {
        crate::policy::plonk::ensure_registry(self.registry, &metadata)
    }
}
