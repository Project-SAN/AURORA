//! ZKP-related building blocks (streaming-friendly scaffolding).

pub mod chain;
pub mod commitment;
pub mod zkboo;

pub use chain::{ChainInputs, ChainState, ChunkMeta, Witness};
pub use commitment::{AsconCommitment, CommitmentScheme, COMMIT_LEN};
pub use zkboo::{Proof, ProverConfig, VerifierConfig, ZkBooEngine};
