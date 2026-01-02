use alloc::collections::{BTreeMap, BTreeSet};

use crate::policy::PolicyId;

#[derive(Clone, Debug)]
pub struct PenaltyBox {
    threshold: u32,
    counts: BTreeMap<PolicyId, u32>,
    blocked: BTreeSet<PolicyId>,
}

impl PenaltyBox {
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            counts: BTreeMap::new(),
            blocked: BTreeSet::new(),
        }
    }

    pub fn record_violation(&mut self, policy_id: &PolicyId) -> bool {
        let count = self.counts.entry(*policy_id).or_insert(0);
        *count = count.saturating_add(1);
        if *count >= self.threshold {
            self.blocked.insert(*policy_id);
            return true;
        }
        false
    }

    pub fn is_blocked(&self, policy_id: &PolicyId) -> bool {
        self.blocked.contains(policy_id)
    }

    pub fn blocked_policies(&self) -> BTreeSet<PolicyId> {
        self.blocked.clone()
    }
}

#[derive(Clone, Debug)]
pub struct ResendRequest {
    pub policy_id: PolicyId,
    pub sequence: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct AsyncActions {
    pub violations: alloc::vec::Vec<crate::policy::PolicyCapsule>,
    pub resend: alloc::vec::Vec<ResendRequest>,
    pub blocked: BTreeSet<PolicyId>,
}
