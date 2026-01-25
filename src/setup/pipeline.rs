//! Setup flow interfaces.

use crate::core::policy::PolicyMetadata;
use crate::types::Result;

pub trait SetupPipeline {
    fn install(&mut self, metadata: PolicyMetadata) -> Result<()>;
}
