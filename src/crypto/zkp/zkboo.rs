use alloc::vec::Vec;

use crate::crypto::zkp::chain::{ChainInputs, Witness};
use crate::types::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub rounds: u16,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProverConfig {
    pub rounds: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierConfig {
    pub rounds: u16,
}

pub trait Prover {
    fn prove(&self, inputs: &ChainInputs, witness: &Witness, cfg: ProverConfig) -> Result<Proof>;
}

pub trait Verifier {
    fn verify(&self, inputs: &ChainInputs, proof: &Proof, cfg: VerifierConfig) -> Result<()>;
}

/// Placeholder engine; wire in a real ZKBoo implementation here.
pub struct ZkBooEngine;

impl Prover for ZkBooEngine {
    fn prove(&self, _inputs: &ChainInputs, _witness: &Witness, _cfg: ProverConfig) -> Result<Proof> {
        Err(Error::NotImplemented)
    }
}

impl Verifier for ZkBooEngine {
    fn verify(&self, _inputs: &ChainInputs, _proof: &Proof, _cfg: VerifierConfig) -> Result<()> {
        Err(Error::NotImplemented)
    }
}
