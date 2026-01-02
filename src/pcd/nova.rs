use crate::pcd::{PcdBackend, PcdState};
use crate::types::{Error, Result};

#[derive(Clone, Debug, Default)]
pub struct NovaPcdBackend;

impl NovaPcdBackend {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_step(&self, _prev_state: &PcdState) -> Result<Vec<u8>> {
        Err(Error::NotImplemented)
    }

    pub fn verify_step(&self, _prev_state: &PcdState, _proof: &[u8]) -> Result<()> {
        Err(Error::NotImplemented)
    }
}

impl PcdBackend for NovaPcdBackend {
    fn hash(&self, state: &PcdState) -> [u8; 32] {
        state.hash()
    }

    fn step(&self, prev: &PcdState) -> PcdState {
        prev.next_seq()
    }
}
