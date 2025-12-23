//! Proof-generation pipeline abstractions.

use crate::core::policy::{PolicyCapsule, PolicyId};
use crate::policy::extract::ExtractionError;
use crate::types::Error as HornetError;

pub struct ProveInput<'a> {
    pub policy_id: PolicyId,
    pub payload: &'a [u8],
    pub aux: &'a [u8],
}

#[derive(Debug)]
pub enum ProofError {
    PolicyNotFound,
    Extraction(ExtractionError),
    Prover(HornetError),
}

pub trait ProofPipeline {
    fn prove(&self, request: ProveInput<'_>) -> Result<PolicyCapsule, ProofError>;
}
