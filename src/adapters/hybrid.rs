use crate::adapters::plonk::validator::PlonkCapsuleValidator;
use crate::adapters::zkboo::validator::ZkBooCapsuleValidator;
use crate::core::policy::{CapsuleValidator, PolicyCapsule, PolicyMetadata, PolicyRole};
use crate::types::Result;

pub struct HybridCapsuleValidator {
    plonk: PlonkCapsuleValidator,
    zkboo: ZkBooCapsuleValidator,
}

impl HybridCapsuleValidator {
    pub const fn new() -> Self {
        Self {
            plonk: PlonkCapsuleValidator::new(),
            zkboo: ZkBooCapsuleValidator::new(),
        }
    }
}

impl Default for HybridCapsuleValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsuleValidator for HybridCapsuleValidator {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()> {
        self.validate_with_role(capsule, metadata, PolicyRole::All)
    }

    fn validate_with_role(
        &self,
        capsule: &PolicyCapsule,
        metadata: &PolicyMetadata,
        role: PolicyRole,
    ) -> Result<()> {
        if metadata.supports_zkboo() {
            self.zkboo.validate_with_role(capsule, metadata, role)?;
        }
        self.plonk.validate_with_role(capsule, metadata, role)
    }
}
