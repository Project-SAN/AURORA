use alloc::collections::{BTreeSet, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Mutex;

use crate::application::forward::ForwardPipeline;
use crate::core::policy::{PolicyCapsule, PolicyRegistry};
use crate::policy::CapsuleValidator;
use crate::types::{Error, Result};

#[derive(Clone)]
pub struct PendingEntry {
    pub capsule: PolicyCapsule,
}

#[derive(Clone)]
pub struct PendingQueue {
    inner: Arc<Mutex<VecDeque<PendingEntry>>>,
    max_len: usize,
}

impl PendingQueue {
    pub fn new(max_len: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            max_len,
        }
    }

    fn push(&self, entry: PendingEntry) -> Result<()> {
        let mut queue = self.inner.lock();
        if queue.len() >= self.max_len {
            return Err(Error::PolicyViolation);
        }
        queue.push_back(entry);
        Ok(())
    }

    fn drain(&self) -> Vec<PendingEntry> {
        let mut queue = self.inner.lock();
        queue.drain(..).collect()
    }
}

pub struct AsyncForwardPipeline {
    pending: PendingQueue,
    blocked: Arc<Mutex<BTreeSet<crate::policy::PolicyId>>>,
}

impl AsyncForwardPipeline {
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: PendingQueue::new(max_pending),
            blocked: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    pub fn pending_queue(&self) -> PendingQueue {
        self.pending.clone()
    }
}

impl ForwardPipeline for AsyncForwardPipeline {
    fn enforce(
        &self,
        registry: &PolicyRegistry,
        payload: &mut Vec<u8>,
        validator: &dyn CapsuleValidator,
    ) -> Result<Option<(PolicyCapsule, usize)>> {
        if registry.is_empty() {
            return Ok(None);
        }
        let (capsule, consumed) = PolicyCapsule::decode(payload.as_slice())?;
        if self.blocked.lock().contains(&capsule.policy_id) {
            return Err(Error::PolicyViolation);
        }
        let Some(metadata) = registry.get(&capsule.policy_id) else {
            return Err(Error::PolicyViolation);
        };
        if metadata.supports_async() {
            self.pending.push(PendingEntry { capsule: capsule.clone() })?;
            return Ok(Some((capsule, consumed)));
        }
        validator.validate(&capsule, metadata)?;
        Ok(Some((capsule, consumed)))
    }

    fn drain_pending(
        &self,
        registry: &PolicyRegistry,
        validator: &dyn CapsuleValidator,
    ) -> Result<Vec<PolicyCapsule>> {
        let entries = self.pending.drain();
        let mut violations = Vec::new();
        for entry in entries {
            let Some(metadata) = registry.get(&entry.capsule.policy_id) else {
                violations.push(entry.capsule);
                continue;
            };
            if validator.validate(&entry.capsule, metadata).is_err() {
                violations.push(entry.capsule);
            }
        }
        Ok(violations)
    }

    fn block_policy(&self, policy_id: &crate::policy::PolicyId) {
        self.blocked.lock().insert(*policy_id);
    }
}
