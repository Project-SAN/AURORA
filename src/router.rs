use crate::adapters::plonk::validator::PlonkCapsuleValidator;
use crate::application::forward::{ForwardPipeline, RegistryForwardPipeline};
use crate::application::setup::{RegistrySetupPipeline, SetupPipeline};
use crate::node::PolicyRuntime;
use crate::policy::{PolicyRegistry, PolicyRole};
use crate::setup::directory::{from_signed_json, DirectoryAnnouncement, RouteAnnouncement};
use crate::types::{Ahdr, Chdr, Result};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub mod config;
pub mod io;
pub mod penalty;
pub mod runtime;
pub mod storage;
pub mod sync;

/// High-level router facade that owns policy state and validation pipelines.
pub struct Router {
    registry: PolicyRegistry,
    validator: PlonkCapsuleValidator,
    forward_pipeline: Box<dyn ForwardPipeline>,
    routes: BTreeMap<[u8; 32], RouteAnnouncement>,
    policy_roles: BTreeMap<[u8; 32], PolicyRole>,
    node_id: Option<String>,
    penalty: penalty::PenaltyBox,
}

impl Router {
    pub fn new() -> Self {
        Self {
            registry: PolicyRegistry::new(),
            validator: PlonkCapsuleValidator::new(),
            forward_pipeline: Box::new(RegistryForwardPipeline::new()),
            routes: BTreeMap::new(),
            policy_roles: BTreeMap::new(),
            node_id: None,
            penalty: penalty::PenaltyBox::new(3),
        }
    }

    pub fn with_node_id(node_id: Option<String>) -> Self {
        Self {
            node_id,
            ..Self::new()
        }
    }

    pub fn with_forward_pipeline(pipeline: Box<dyn ForwardPipeline>) -> Self {
        Self {
            registry: PolicyRegistry::new(),
            validator: PlonkCapsuleValidator::new(),
            forward_pipeline: pipeline,
            routes: BTreeMap::new(),
            policy_roles: BTreeMap::new(),
            node_id: None,
            penalty: penalty::PenaltyBox::new(3),
        }
    }

    pub fn with_forward_pipeline_and_node_id(
        pipeline: Box<dyn ForwardPipeline>,
        node_id: Option<String>,
    ) -> Self {
        Self {
            registry: PolicyRegistry::new(),
            validator: PlonkCapsuleValidator::new(),
            forward_pipeline: pipeline,
            routes: BTreeMap::new(),
            policy_roles: BTreeMap::new(),
            node_id,
            penalty: penalty::PenaltyBox::new(3),
        }
    }

    pub fn set_node_id(&mut self, node_id: Option<String>) {
        self.node_id = node_id;
    }

    pub fn with_penalty_threshold(mut self, threshold: u32) -> Self {
        self.penalty = penalty::PenaltyBox::new(threshold.max(1));
        self
    }

    /// Install all policy metadata entries contained in a directory announcement.
    /// This is typically called after verifying the announcement signature.
    pub fn install_directory(&mut self, directory: &DirectoryAnnouncement) -> Result<()> {
        self.install_policies(directory.policies())?;
        self.install_routes(directory.routes())
    }

    pub fn install_policies(&mut self, policies: &[crate::policy::PolicyMetadata]) -> Result<()> {
        for policy in policies {
            let mut pipeline = RegistrySetupPipeline::new(&mut self.registry);
            pipeline.install(policy.clone())?;
        }
        Ok(())
    }

    pub fn install_routes(&mut self, routes: &[RouteAnnouncement]) -> Result<()> {
        self.refresh_policy_roles(routes);
        if let Some(node_id) = self.node_id.as_deref() {
            self.routes.clear();
            for route in routes {
                if route.interface.as_deref() == Some(node_id) {
                    self.routes.insert(route.policy_id, route.clone());
                }
            }
        } else {
            self.routes.clear();
            for route in routes {
                self.routes.insert(route.policy_id, route.clone());
            }
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
            validator: &self.validator,
            forward: self.forward_pipeline.as_ref(),
            roles: &self.policy_roles,
        })
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

    pub fn policy_role_for(&self, policy: &[u8; 32]) -> Option<PolicyRole> {
        self.policy_roles.get(policy).copied()
    }

    pub fn drain_pending(&self) -> Result<Vec<crate::policy::PolicyCapsule>> {
        let Some(policy) = self.policy_runtime() else {
            return Ok(Vec::new());
        };
        policy
            .forward
            .drain_pending(policy.registry, policy.validator, &self.policy_roles)
    }

    pub fn handle_async_violations(&mut self) -> Result<penalty::AsyncActions> {
        let violations = self.drain_pending()?;
        let mut resend = Vec::new();
        for capsule in &violations {
            if self.penalty.record_violation(&capsule.policy_id) {
                self.forward_pipeline.block_policy(&capsule.policy_id);
            }
            let mut sequence = None;
            if let Some(part) = capsule.part(crate::core::policy::ProofKind::Policy) {
                if let Ok(Some(bytes)) = crate::core::policy::find_extension(
                    part.aux(),
                    crate::core::policy::EXT_TAG_SEQUENCE,
                ) {
                    if bytes.len() == 8 {
                        let mut buf = [0u8; 8];
                        buf.copy_from_slice(bytes);
                        sequence = Some(u64::from_be_bytes(buf));
                    }
                }
            }
            resend.push(penalty::ResendRequest {
                policy_id: capsule.policy_id,
                sequence,
            });
        }
        Ok(penalty::AsyncActions {
            violations,
            resend,
            blocked: self.penalty.blocked_policies(),
        })
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

    fn refresh_policy_roles(&mut self, routes: &[RouteAnnouncement]) {
        self.policy_roles.clear();
        let Some(node_id) = self.node_id.as_deref() else {
            return;
        };
        let mut grouped: BTreeMap<[u8; 32], Vec<&RouteAnnouncement>> = BTreeMap::new();
        for route in routes {
            grouped.entry(route.policy_id).or_default().push(route);
        }
        for (policy_id, list) in grouped {
            if let Some(index) = list
                .iter()
                .position(|route| route.interface.as_deref() == Some(node_id))
            {
                let role = if index == 0 {
                    PolicyRole::Entry
                } else if index + 1 == list.len() {
                    PolicyRole::Exit
                } else {
                    PolicyRole::Middle
                };
                self.policy_roles.insert(policy_id, role);
            }
        }
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
            verifiers: alloc::vec![crate::policy::VerifierEntry {
                kind: crate::core::policy::ProofKind::Policy as u8,
                verifier_blob: alloc::vec![0xAA, 0xBB, 0xCC],
            }],
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
