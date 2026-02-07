use alloc::vec::Vec;

use crate::crypto::zkp::commitment::{CommitmentScheme, COMMIT_LEN};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkMeta {
    pub record_index: u64,
    pub record_len: u32,
    pub rule_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainState {
    pub index: u64,
    pub commit: [u8; COMMIT_LEN],
}

impl ChainState {
    pub fn new<C: CommitmentScheme>(index: u64, state: &[u8], salt: &[u8]) -> Self {
        Self {
            index,
            commit: C::commit(state, salt, index),
        }
    }

    pub fn next<C: CommitmentScheme>(&self, next_state: &[u8], next_salt: &[u8]) -> Self {
        let next_index = self.index.saturating_add(1);
        Self {
            index: next_index,
            commit: C::commit(next_state, next_salt, next_index),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInputs {
    pub meta: ChunkMeta,
    pub prev_commit: [u8; COMMIT_LEN],
    pub next_commit: [u8; COMMIT_LEN],
    pub ok: bool,
}

impl ChainInputs {
    pub fn new(meta: ChunkMeta, prev_commit: [u8; COMMIT_LEN], next_commit: [u8; COMMIT_LEN]) -> Self {
        Self {
            meta,
            prev_commit,
            next_commit,
            ok: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub prev_state: Vec<u8>,
    pub prev_salt: Vec<u8>,
    pub chunk_plaintext: Vec<u8>,
    pub next_state: Vec<u8>,
    pub next_salt: Vec<u8>,
}
