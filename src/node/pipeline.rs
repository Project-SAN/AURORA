//! Forwarding verification pipeline traits.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::core::policy::{PolicyCapsule, PolicyId, PolicyRegistry, PolicyRole};
use crate::policy::CapsuleValidator;

pub trait ForwardPipeline {
    fn enforce(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &dyn CapsuleValidator,
        role: PolicyRole,
    ) -> core::result::Result<Option<(PolicyCapsule, usize)>, crate::types::Error>;

    fn enforce_batch(
        &self,
        registry: &PolicyRegistry,
        payloads: &mut [Vec<u8>],
        validator: &dyn CapsuleValidator,
        role: PolicyRole,
    ) -> core::result::Result<Vec<Option<(PolicyCapsule, usize)>>, crate::types::Error> {
        let mut out = Vec::with_capacity(payloads.len());
        for payload in payloads.iter_mut() {
            out.push(self.enforce(registry, payload, validator, role)?);
        }
        Ok(out)
    }

    fn drain_pending(
        &self,
        _registry: &PolicyRegistry,
        _validator: &dyn CapsuleValidator,
        _roles: &BTreeMap<PolicyId, PolicyRole>,
    ) -> core::result::Result<Vec<PolicyCapsule>, crate::types::Error> {
        Ok(Vec::new())
    }

    fn block_policy(&self, _policy_id: &crate::policy::PolicyId) {}
}
