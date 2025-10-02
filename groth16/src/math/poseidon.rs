use alloc::vec::Vec;
use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds,
    PoseidonConfig,
    PoseidonSponge,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::PrimeField;

const POSEIDON_RATE: usize = 2;
const POSEIDON_ALPHA: u64 = 17;
const POSEIDON_FULL_ROUNDS: usize = 8;
const POSEIDON_PARTIAL_ROUNDS: usize = 31;
const POSEIDON_SKIP_MATRICES: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleTreeError {
    EmptyLeaves,
    NonPowerOfTwo,
    IndexOutOfBounds,
}

fn poseidon_config() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        POSEIDON_RATE,
        POSEIDON_FULL_ROUNDS as u64,
        POSEIDON_PARTIAL_ROUNDS as u64,
        POSEIDON_SKIP_MATRICES,
    );

    PoseidonConfig {
        full_rounds: POSEIDON_FULL_ROUNDS,
        partial_rounds: POSEIDON_PARTIAL_ROUNDS,
        alpha: POSEIDON_ALPHA,
        ark,
        mds,
        rate: POSEIDON_RATE,
        capacity: 1,
    }
}

/// Poseidon ハッシュ (rate=2, capacity=1) のシンプルなユーティリティ。
pub fn hash(elements: &[Fr]) -> Fr {
    let params = poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);
    for element in elements {
        sponge.absorb(element);
    }
    sponge
        .squeeze_native_field_elements(1)
        .into_iter()
        .next()
        .expect("Poseidon sponge must output at least one element")
}

/// 2 入力に特化したハッシュ。
pub fn hash_pair(left: Fr, right: Fr) -> Fr {
    hash(&[left, right])
}

/// Poseidon-arity2 の完全二分木を扱うための単純なメルクル構造体。
#[derive(Clone, Debug)]
pub struct PoseidonMerkleTree {
    depth: usize,
    levels: Vec<Vec<Fr>>, // level 0 が葉、最後が root
}

impl PoseidonMerkleTree {
    pub fn new(leaves: &[Fr]) -> Result<Self, MerkleTreeError> {
        if leaves.is_empty() {
            return Err(MerkleTreeError::EmptyLeaves);
        }
        if !leaves.len().is_power_of_two() {
            return Err(MerkleTreeError::NonPowerOfTwo);
        }

        let mut levels = Vec::new();
        levels.push(leaves.to_vec());
        let mut current = levels[0].clone();

        while current.len() > 1 {
            let mut parents = Vec::with_capacity(current.len() / 2);
            for chunk in current.chunks(2) {
                let left = chunk[0];
                let right = chunk[1];
                parents.push(hash_pair(left, right));
            }
            levels.push(parents.clone());
            current = parents;
        }

        Ok(Self {
            depth: levels.len() - 1,
            levels,
        })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    pub fn root(&self) -> Fr {
        self.levels
            .last()
            .expect("merkle tree must have a root")[0]
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.levels[0]
    }

    pub fn authentication_path(&self, index: usize) -> Result<PoseidonMerklePath, MerkleTreeError> {
        if index >= self.leaf_count() {
            return Err(MerkleTreeError::IndexOutOfBounds);
        }

        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let nodes = &self.levels[level];
            let is_right = idx % 2 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            siblings.push(PoseidonMerkleSibling {
                sibling: nodes[sibling_idx],
                sibling_is_left: is_right,
            });
            idx /= 2;
        }

        Ok(PoseidonMerklePath { siblings })
    }
}

#[derive(Clone, Debug)]
pub struct PoseidonMerkleSibling {
    pub sibling: Fr,
    /// true の場合、sibling は左側（= 対象ノードが右側）
    pub sibling_is_left: bool,
}

#[derive(Clone, Debug)]
pub struct PoseidonMerklePath {
    pub siblings: Vec<PoseidonMerkleSibling>,
}

impl PoseidonMerklePath {
    pub fn len(&self) -> usize {
        self.siblings.len()
    }

    pub fn compute_root(&self, leaf: Fr) -> Fr {
        self.siblings.iter().fold(leaf, |acc, step| {
            if step.sibling_is_left {
                hash_pair(step.sibling, acc)
            } else {
                hash_pair(acc, step.sibling)
            }
        })
    }

    pub fn verify(&self, leaf: Fr, root: Fr) -> bool {
        self.compute_root(leaf) == root
    }
}

/// ストリーミング吸収が必要な場合のための Poseidon sponge ラッパー。
pub struct PoseidonHasher {
    sponge: PoseidonSponge<Fr>,
}

impl PoseidonHasher {
    /// パラメータを取得して新しいスポンジを初期化する。
    pub fn new() -> Self {
        let params = poseidon_config();
        Self {
            sponge: PoseidonSponge::<Fr>::new(&params),
        }
    }

    /// 単一要素を吸収する。
    pub fn absorb(&mut self, element: Fr) {
        self.sponge.absorb(&element);
    }

    /// 任意長のスライスを順番に吸収する。
    pub fn absorb_slice(&mut self, elements: &[Fr]) {
        for element in elements {
            self.sponge.absorb(element);
        }
    }

    /// スポンジから 1 要素をスクイーズする。
    pub fn squeeze(&mut self) -> Fr {
        self
            .sponge
            .squeeze_native_field_elements(1)
            .into_iter()
            .next()
            .expect("Poseidon sponge must output at least one element")
    }

    /// 現在のスポンジ状態をコピーして独立に利用する。
    pub fn fork(&self) -> Self {
        Self {
            sponge: self.sponge.clone(),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_ff::MontFp;

    #[test]
    fn hash_two_elements_is_deterministic() {
        let digest = hash(&[Fr::from(0u64), Fr::from(1u64)]);
        assert_eq!(
            digest,
            MontFp!(
                "13448327772685069967512731534055470395695158152855748480780242185299015955086"
            )
        );
        assert_eq!(digest, hash(&[Fr::from(0u64), Fr::from(1u64)]));
    }

    #[test]
    fn streaming_interface_matches_batch() {
        let batch_digest = hash(&[Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)]);
        let mut hasher = PoseidonHasher::new();
        hasher.absorb_slice(&[Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(batch_digest, hasher.squeeze());
    }

    #[test]
    fn merkle_tree_root_and_paths() {
        let leaves: Vec<Fr> = (0u64..4).map(Fr::from).collect();
        let tree = PoseidonMerkleTree::new(&leaves).expect("tree");
        assert_eq!(tree.depth(), 2);
        let root = tree.root();

        for (idx, leaf) in leaves.iter().enumerate() {
            let path = tree
                .authentication_path(idx)
                .expect("path must exist");
            assert_eq!(path.len(), tree.depth());
            assert!(path.verify(*leaf, root));
        }

        assert!(matches!(
            PoseidonMerkleTree::new(&[]),
            Err(MerkleTreeError::EmptyLeaves)
        ));
        assert!(matches!(
            PoseidonMerkleTree::new(&leaves[..3]),
            Err(MerkleTreeError::NonPowerOfTwo)
        ));
    }
}
