use alloc::boxed::Box;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcdState {
    pub hkey: [u8; 32],
    pub seq: u64,
    pub root: [u8; 32],
    pub htarget: [u8; 32],
}

impl PcdState {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.hkey);
        hasher.update(&self.seq.to_be_bytes());
        hasher.update(&self.root);
        hasher.update(&self.htarget);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn next_seq(&self) -> PcdState {
        PcdState {
            hkey: self.hkey,
            seq: self.seq.saturating_add(1),
            root: self.root,
            htarget: self.htarget,
        }
    }
}

pub trait PcdBackend {
    fn hash(&self, state: &PcdState) -> [u8; 32];
    fn step(&self, prev: &PcdState) -> PcdState;
    fn prove_base(&self, initial: &PcdState) -> Result<Vec<u8>, crate::types::Error>;
    fn prove_step(
        &self,
        prev: &PcdState,
        prev_proof: &[u8],
    ) -> Result<Vec<u8>, crate::types::Error>;
    fn verify_step(&self, prev: &PcdState, proof: &[u8]) -> Result<(), crate::types::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HashPcdBackend;

impl PcdBackend for HashPcdBackend {
    fn hash(&self, state: &PcdState) -> [u8; 32] {
        state.hash()
    }

    fn step(&self, prev: &PcdState) -> PcdState {
        prev.next_seq()
    }

    fn prove_base(&self, _initial: &PcdState) -> Result<Vec<u8>, crate::types::Error> {
        Ok(Vec::new())
    }

    fn prove_step(
        &self,
        _prev: &PcdState,
        _prev_proof: &[u8],
    ) -> Result<Vec<u8>, crate::types::Error> {
        Ok(Vec::new())
    }

    fn verify_step(&self, _prev: &PcdState, proof: &[u8]) -> Result<(), crate::types::Error> {
        if proof.is_empty() {
            Ok(())
        } else {
            Err(crate::types::Error::PolicyViolation)
        }
    }
}

pub fn default_backend() -> Box<dyn PcdBackend> {
    Box::new(HashPcdBackend::default())
}

#[cfg(feature = "pcd-nova")]
pub mod nova;
