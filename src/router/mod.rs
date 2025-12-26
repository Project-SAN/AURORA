use crate::application::forward::RegistryForwardPipeline;
use crate::application::setup::{RegistrySetupPipeline, SetupPipeline};
use crate::node::PolicyRuntime;
use crate::policy::{CapsuleValidator, PollingCapsuleValidator, PolicyRegistry};
use crate::adapters::plonk::validator::PlonkCapsuleValidator;
#[cfg(not(feature = "std"))]
use crate::adapters::plonk::validator::QueuedCapsuleValidator;
use crate::setup::directory::{from_signed_json, DirectoryAnnouncement, RouteAnnouncement};
use crate::types::{Ahdr, Chdr, Result};
use alloc::collections::BTreeMap;
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
use alloc::vec::Vec;

pub mod config;
#[cfg(feature = "std")]
pub mod config_std;
#[cfg(feature = "std")]
pub mod io;
pub mod runtime;
#[cfg(feature = "std")]
pub mod storage;
pub mod sync;

/// High-level router facade that owns policy state and validation pipelines.
pub struct Router {
    registry: PolicyRegistry,
    validator: ValidatorKind,
    forward_pipeline: RegistryForwardPipeline,
    routes: BTreeMap<[u8; 32], RouteAnnouncement>,
    expected_policy_id: Option<[u8; 32]>,
    router_name: Option<alloc::string::String>,
}

const EXPECTED_HOPS: u8 = 3;
const DEFAULT_VALIDATION_QUEUE: usize = 64;

enum ValidatorKind {
    Sync(Box<dyn CapsuleValidator>),
    Polling(Arc<dyn CapsuleValidator + PollingCapsuleValidator>),
}

impl ValidatorKind {
    fn validator(&self) -> &dyn CapsuleValidator {
        match self {
            Self::Sync(validator) => validator.as_ref(),
            Self::Polling(validator) => validator.as_ref(),
        }
    }

    fn poll(&self, budget: usize) -> usize {
        match self {
            Self::Sync(_) => 0,
            Self::Polling(validator) => validator.poll_validation(budget),
        }
    }
}

impl Router {
    pub fn new() -> Self {
        #[cfg(not(feature = "std"))]
        let validator = ValidatorKind::Polling(Arc::new(
            QueuedCapsuleValidator::<DEFAULT_VALIDATION_QUEUE>::new(),
        ));
        #[cfg(feature = "std")]
        let validator = ValidatorKind::Sync(Box::new(PlonkCapsuleValidator::new()));
        Self {
            registry: PolicyRegistry::new(),
            validator,
            forward_pipeline: RegistryForwardPipeline::new(),
            routes: BTreeMap::new(),
            expected_policy_id: None,
            router_name: None,
        }
    }

    /// Install all policy metadata entries contained in a directory announcement.
    /// This is typically called after verifying the announcement signature.
    pub fn install_directory(&mut self, directory: &DirectoryAnnouncement) -> Result<()> {
        self.install_policies(directory.policies())?;
        self.install_routes(directory.routes())?;
        if let Some(name) = self.router_name.as_deref() {
            if let Some(policy_id) = directory.hop_policy_for(name) {
                self.expected_policy_id = Some(policy_id);
            }
        }
        Ok(())
    }

    pub fn install_policies(&mut self, policies: &[crate::policy::PolicyMetadata]) -> Result<()> {
        for policy in policies {
            let mut pipeline = RegistrySetupPipeline::new(&mut self.registry);
            pipeline.install(policy.clone())?;
        }
        Ok(())
    }

    pub fn install_routes(&mut self, routes: &[RouteAnnouncement]) -> Result<()> {
        for route in routes {
            self.routes.insert(route.policy_id, route.clone());
        }
        Ok(())
    }

    /// Verifies a signed directory announcement (HMAC/HKDF per spec) and installs
    /// all contained policy metadata entries on success.
    pub fn install_signed_directory(&mut self, body: &str, secret: &[u8]) -> Result<()> {
        let directory = from_signed_json(body, secret)?;
        self.install_directory(&directory)
    }

    /// Returns the current policy runtime (registry + validator + enforcement pipeline)
    /// if at least one policy has been installed.
    pub fn policy_runtime(&self) -> Option<PolicyRuntime<'_>> {
        if self.registry.is_empty() {
            return None;
        }
        Some(PolicyRuntime {
            registry: &self.registry,
            validator: self.validator.validator(),
            forward: &self.forward_pipeline,
            expected_policy_id: self.expected_policy_id,
        })
    }

    pub fn set_expected_policy_id(&mut self, policy_id: Option<[u8; 32]>) {
        self.expected_policy_id = policy_id;
    }

    pub fn set_router_name(&mut self, name: Option<alloc::string::String>) {
        self.router_name = name;
    }

    pub fn set_validator(&mut self, validator: Box<dyn CapsuleValidator>) {
        self.validator = ValidatorKind::Sync(validator);
    }

    pub fn set_polling_validator(
        &mut self,
        validator: Arc<dyn CapsuleValidator + PollingCapsuleValidator>,
    ) {
        self.validator = ValidatorKind::Polling(validator);
    }

    pub fn poll_validation(&self, budget: usize) -> usize {
        self.validator.poll(budget)
    }

    pub fn registry(&self) -> &PolicyRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut PolicyRegistry {
        &mut self.registry
    }

    pub fn policies(&self) -> Vec<crate::policy::PolicyMetadata> {
        self.registry.policies()
    }

    pub fn routes(&self) -> Vec<RouteAnnouncement> {
        self.routes.values().cloned().collect()
    }

    pub fn route_for_policy(&self, policy: &[u8; 32]) -> Option<&RouteAnnouncement> {
        self.routes.get(policy)
    }

    pub fn process_forward_packet(
        &self,
        sv: crate::types::Sv,
        now: &dyn crate::time::TimeProvider,
        forward: &mut dyn crate::forward::Forward,
        replay: &mut dyn crate::node::ReplayFilter,
        chdr: &mut Chdr,
        ahdr: &mut Ahdr,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        if chdr.hops != EXPECTED_HOPS {
            return Err(crate::types::Error::PolicyViolation);
        }
        use crate::node;
        let policy = self.policy_runtime();
        let mut ctx = node::NodeCtx {
            sv,
            now,
            forward,
            replay,
            policy,
        };
        node::forward::process_data(&mut ctx, chdr, ahdr, payload)
    }

    pub fn process_backward_packet(
        &self,
        sv: crate::types::Sv,
        now: &dyn crate::time::TimeProvider,
        forward: &mut dyn crate::forward::Forward,
        replay: &mut dyn crate::node::ReplayFilter,
        chdr: &mut Chdr,
        ahdr: &mut Ahdr,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        if chdr.hops != EXPECTED_HOPS {
            return Err(crate::types::Error::PolicyViolation);
        }
        use crate::node;
        let policy = self.policy_runtime();
        let mut ctx = node::NodeCtx {
            sv,
            now,
            forward,
            replay,
            policy,
        };
        node::backward::process_data(&mut ctx, chdr, ahdr, payload)
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
    use crate::setup::directory::to_signed_json;

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

    #[test]
    fn install_signed_directory_validates_and_installs() {
        let policy = sample_metadata();
        let mut directory = DirectoryAnnouncement::new();
        directory.push_policy(policy.clone());
        let secret = b"shared-secret";
        let signed = to_signed_json(&directory, secret, 1_700_000_000).expect("sign");

        let mut router = Router::new();
        router
            .install_signed_directory(&signed, secret)
            .expect("install signed directory");
        assert!(router.registry().get(&policy.policy_id).is_some());
    }
}
