use crate::adapters::plonk::validator::PlonkCapsuleValidator;
use crate::application::forward::RegistryForwardPipeline;
use crate::application::setup::{RegistrySetupPipeline, SetupPipeline};
use crate::node::PolicyRuntime;
use crate::policy::PolicyRegistry;
use crate::setup::directory::DirectoryAnnouncement;
use crate::types::Result;

/// High-level router facade that owns policy state and validation pipelines.
pub struct Router {
    registry: PolicyRegistry,
    validator: PlonkCapsuleValidator,
    forward_pipeline: RegistryForwardPipeline,
}

impl Router {
    pub fn new() -> Self {
        Self {
            registry: PolicyRegistry::new(),
            validator: PlonkCapsuleValidator::new(),
            forward_pipeline: RegistryForwardPipeline::new(),
        }
    }

    /// Install all policy metadata entries contained in a directory announcement.
    /// This is typically called after verifying the announcement signature.
    pub fn install_directory(&mut self, directory: &DirectoryAnnouncement) -> Result<()> {
        for policy in directory.policies() {
            let mut pipeline = RegistrySetupPipeline::new(&mut self.registry);
            pipeline.install(policy.clone())?;
        }
        Ok(())
    }

    /// Returns the current policy runtime (registry + validator + enforcement pipeline)
    /// if at least one policy has been installed.
    pub fn policy_runtime(&self) -> Option<PolicyRuntime<'_>> {
        if self.registry.is_empty() {
            return None;
        }
        Some(PolicyRuntime {
            registry: &self.registry,
            validator: &self.validator,
            forward: &self.forward_pipeline,
        })
    }

    pub fn registry(&self) -> &PolicyRegistry {
        &self.registry
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyMetadata;

    fn sample_metadata() -> PolicyMetadata {
        PolicyMetadata {
            policy_id: [0x11; 32],
            version: 1,
            expiry: 1_700_000_000,
            flags: 0,
            verifier_blob: alloc::vec![0xAA, 0xBB, 0xCC],
        }
    }

    #[test]
    fn router_installs_directory_and_exposes_runtime() {
        let policy = sample_metadata();
        let mut directory = DirectoryAnnouncement::new();
        directory.push_policy(policy.clone());

        let mut router = Router::new();
        assert!(router.policy_runtime().is_none());
        router
            .install_directory(&directory)
            .expect("install directory");
        assert!(router.policy_runtime().is_some());
        assert!(router.registry().get(&policy.policy_id).is_some());
    }
}
