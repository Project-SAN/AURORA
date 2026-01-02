//! Proof-generation pipeline abstractions.

use crate::core::policy::{PolicyCapsule, PolicyId};
use crate::policy::extract::ExtractionError;
use crate::types::Error as HornetError;

pub struct ProveInput<'a> {
    pub policy_id: PolicyId,
    pub payload: &'a [u8],
    pub aux: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct PrecomputeToken {
    pub policy_id: PolicyId,
    pub token: alloc::string::String,
}

#[derive(Clone, Debug)]
pub struct PrecomputeResult {
    pub token: PrecomputeToken,
    pub commitment: alloc::vec::Vec<u8>,
    pub version: u8,
}

#[derive(Debug)]
pub enum ProofError {
    PolicyNotFound,
    Extraction(ExtractionError),
    Prover(HornetError),
    Unsupported,
}

pub trait ProofPipeline {
    fn prove(&self, request: ProveInput<'_>) -> Result<PolicyCapsule, ProofError>;

    fn prove_batch(&self, requests: &[ProveInput<'_>]) -> Result<alloc::vec::Vec<PolicyCapsule>, ProofError> {
        let mut out = alloc::vec::Vec::with_capacity(requests.len());
        for request in requests {
            out.push(self.prove(ProveInput {
                policy_id: request.policy_id,
                payload: request.payload,
                aux: request.aux,
            })?);
        }
        Ok(out)
    }

    fn precompute(&self, _request: ProveInput<'_>) -> Result<PrecomputeResult, ProofError> {
        Err(ProofError::Unsupported)
    }

    fn prove_precomputed(&self, _token: &PrecomputeToken) -> Result<PolicyCapsule, ProofError> {
        Err(ProofError::Unsupported)
    }
}
