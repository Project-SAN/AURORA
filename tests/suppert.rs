use std::cell::RefCell;
use std::rc::Rc;
use std::vec::Vec;

use hornet::core::policy::PolicyRole;
use hornet::core::policy::{PolicyCapsule, PolicyMetadata, PolicyRegistry};
use hornet::node::pipeline::ForwardPipeline;
use hornet::policy::CapsuleValidator;
use hornet::setup::pipeline::SetupPipeline;
use hornet::types::Result;

#[allow(dead_code)]
pub struct NoopSetup;

impl SetupPipeline for NoopSetup {
    fn install(&mut self, _metadata: PolicyMetadata) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct RecordingForward {
    state: Rc<RefCell<Option<PolicyCapsule>>>,
}

impl RecordingForward {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(None)),
        }
    }

    pub fn last_capsule(&self) -> Option<PolicyCapsule> {
        self.state.borrow().clone()
    }
}

impl ForwardPipeline for RecordingForward {
    fn enforce(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &dyn CapsuleValidator,
        role: PolicyRole,
    ) -> Result<Option<(PolicyCapsule, usize)>> {
        let (capsule, consumed) = registry.enforce_with_role(payload, validator, role)?;
        *self.state.borrow_mut() = Some(capsule.clone());
        Ok(Some((capsule, consumed)))
    }
}
