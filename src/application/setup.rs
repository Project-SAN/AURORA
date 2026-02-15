//! Setup flow interfaces.

use crate::core::policy::PolicyMetadata;
use crate::policy::PolicyRegistry;
use crate::setup::pipeline::SetupPipeline;
use crate::types::Result;

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
        // ZKBoo-only: registry stores metadata; no Plonk-specific verifier cache.
        self.registry.register(metadata)
    }
}
