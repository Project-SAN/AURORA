use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::core::policy::{PolicyCapsule, PolicyId, PolicyMetadata, ProofKind};
use crate::types::Error;

pub trait CapsuleValidator {
    fn validate(
        &self,
        capsule: &PolicyCapsule,
        metadata: &PolicyMetadata,
    ) -> core::result::Result<(), Error>;

    fn validate_with_role(
        &self,
        capsule: &PolicyCapsule,
        metadata: &PolicyMetadata,
        _role: PolicyRole,
    ) -> core::result::Result<(), Error> {
        self.validate(capsule, metadata)
    }
}

pub struct PolicyRegistry {
    entries: BTreeMap<PolicyId, PolicyMetadata>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRole {
    Entry,
    Middle,
    Exit,
    All,
}

impl PolicyRole {
    pub fn allows(self, kind: ProofKind) -> bool {
        match self {
            PolicyRole::Entry => kind == ProofKind::KeyBinding,
            PolicyRole::Middle => kind == ProofKind::Consistency,
            PolicyRole::Exit => kind == ProofKind::Policy,
            PolicyRole::All => true,
        }
    }

    pub fn required_kinds(self) -> &'static [ProofKind] {
        const ENTRY: [ProofKind; 1] = [ProofKind::KeyBinding];
        const MIDDLE: [ProofKind; 1] = [ProofKind::Consistency];
        const EXIT: [ProofKind; 1] = [ProofKind::Policy];
        const ALL: [ProofKind; 0] = [];
        match self {
            PolicyRole::Entry => &ENTRY,
            PolicyRole::Middle => &MIDDLE,
            PolicyRole::Exit => &EXIT,
            PolicyRole::All => &ALL,
        }
    }
}

impl PolicyRegistry {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, meta: PolicyMetadata) -> core::result::Result<(), Error> {
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
    ) -> core::result::Result<(PolicyCapsule, usize), Error> {
        self.enforce_with_role(payload, validator, PolicyRole::All)
    }

    pub fn enforce_batch<V: CapsuleValidator + ?Sized>(
        &self,
        payloads: &mut [Vec<u8>],
        validator: &V,
    ) -> core::result::Result<Vec<(PolicyCapsule, usize)>, Error> {
        self.enforce_batch_with_role(payloads, validator, PolicyRole::All)
    }

    pub fn enforce_with_role<V: CapsuleValidator + ?Sized>(
        &self,
        payload: &mut Vec<u8>,
        validator: &V,
        role: PolicyRole,
    ) -> core::result::Result<(PolicyCapsule, usize), Error> {
        let (capsule, consumed) = PolicyCapsule::decode(payload.as_slice())?;
        let metadata = self
            .entries
            .get(&capsule.policy_id)
            .ok_or(Error::PolicyViolation)?;

        for required in role.required_kinds() {
            if capsule.part(*required).is_none() {
                return Err(Error::PolicyViolation);
            }
        }

        validator.validate_with_role(&capsule, metadata, role)?;

        Ok((capsule, consumed))
    }

    pub fn enforce_batch_with_role<V: CapsuleValidator + ?Sized>(
        &self,
        payloads: &mut [Vec<u8>],
        validator: &V,
        role: PolicyRole,
    ) -> core::result::Result<Vec<(PolicyCapsule, usize)>, Error> {
        let mut results = Vec::with_capacity(payloads.len());
        for payload in payloads.iter_mut() {
            results.push(self.enforce_with_role(payload, validator, role)?);
        }
        Ok(results)
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
