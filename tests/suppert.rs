use std::cell::RefCell;
use std::rc::Rc;
use std::vec::Vec;

use aurora::core::policy::PolicyRole;
use aurora::core::policy::{PolicyCapsule, PolicyRegistry};
use aurora::node::pipeline::ForwardPipeline;
use aurora::policy::CapsuleValidator;

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
    ) -> core::result::Result<Option<(PolicyCapsule, usize)>, aurora::types::Error> {
        let (capsule, consumed) = registry.enforce_with_role(payload, validator, role)?;
        *self.state.borrow_mut() = Some(capsule.clone());
        Ok(Some((capsule, consumed)))
    }
}
