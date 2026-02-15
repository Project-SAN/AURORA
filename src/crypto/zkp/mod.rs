//! ZKP-related building blocks (streaming-friendly scaffolding).

pub mod chain;
pub mod circuit;
pub mod commitment;
pub mod merkle;
pub mod seed_tree;
pub mod zkboo;

pub use chain::{ChainInputs, ChainState, ChunkMeta, Witness};
pub use circuit::{Circuit, Gate, WireId};
pub use commitment::{AsconCommitment, CommitmentScheme, COMMIT_LEN};
pub use merkle::MerkleTree;
pub use seed_tree::{SeedDeriver, SeedReveal, SeedRevealSet, SeedTree};
pub use zkboo::{Proof, ProverConfig, VerifierConfig, ZkBooEngine};
