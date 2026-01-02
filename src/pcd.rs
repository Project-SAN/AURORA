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
}

pub fn default_backend() -> Box<dyn PcdBackend> {
    Box::new(HashPcdBackend::default())
}

#[cfg(feature = "pcd-nova")]
pub mod nova;
