use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::core::policy::{PolicyCapsule, PolicyId, PolicyMetadata};
use crate::types::{Error, Result};

pub trait CapsuleValidator {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()>;
}

pub trait PollingCapsuleValidator {
    /// Poll pending validations. Returns number of jobs processed.
    fn poll_validation(&self, budget: usize) -> usize;
}

pub struct PolicyRegistry {
    entries: BTreeMap<PolicyId, PolicyMetadata>,
}

impl PolicyRegistry {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, meta: PolicyMetadata) -> Result<()> {
        self.entries.insert(meta.policy_id, meta);
        Ok(())
    }

    pub fn get(&self, policy_id: &PolicyId) -> Option<&PolicyMetadata> {
        self.entries.get(policy_id)
    }

    pub fn enforce<V: CapsuleValidator + ?Sized>(
        &self,
        payload: &mut Vec<u8>,
        validator: &V,
    ) -> Result<(PolicyCapsule, usize)> {
        let (capsule, consumed) = PolicyCapsule::decode(payload.as_slice())?;
        let metadata = self
            .entries
            .get(&capsule.policy_id)
            .ok_or(Error::PolicyViolation)?;

        validator.validate(&capsule, metadata)?;

        Ok((capsule, consumed))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn policies(&self) -> Vec<PolicyMetadata> {
        self.entries.values().cloned().collect()
    }
}

impl Default for PolicyRegistry {
    fn default() -> Self {
        Self::new()
    }
}
