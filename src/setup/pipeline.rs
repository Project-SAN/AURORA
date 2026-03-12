//! Setup flow interfaces.

use crate::core::policy::PolicyMetadata;

pub trait SetupPipeline {
    fn install(
        &mut self,
        metadata: PolicyMetadata,
    ) -> core::result::Result<(), crate::types::Error>;
}
