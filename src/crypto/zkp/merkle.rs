use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::ascon::AsconHash256;

const LEAF_DOMAIN: &[u8] = b"AURORA-ZKBOO-LEAF";
const NODE_DOMAIN: &[u8] = b"AURORA-ZKBOO-NODE";

#[derive(Clone, Debug)]
pub struct MerkleTree {
    leaf_count: usize,
    nodes: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn build(leaves: &[[u8; 32]]) -> Self {
        let leaf_count = next_pow2(leaves.len().max(1));
        let mut nodes = vec![[0u8; 32]; leaf_count * 2];
        for i in 0..leaf_count {
            let leaf = if i < leaves.len() {
                leaves[i]
            } else {
                [0u8; 32]
            };
            nodes[leaf_count + i] = hash_leaf(&leaf);
        }
        for i in (1..leaf_count).rev() {
            nodes[i] = hash_node(&nodes[i * 2], &nodes[i * 2 + 1]);
        }
        Self { leaf_count, nodes }
    }

    pub fn root(&self) -> [u8; 32] {
        self.nodes[1]
    }

    pub fn open(&self, index: usize) -> Vec<[u8; 32]> {
        let mut idx = self.leaf_count + index;
        let mut path = Vec::new();
        while idx > 1 {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            path.push(self.nodes[sibling]);
            idx /= 2;
        }
        path
    }

    pub fn verify(root: [u8; 32], leaf: [u8; 32], index: usize, path: &[[u8; 32]]) -> bool {
        let mut hash = hash_leaf(&leaf);
        let mut idx = index;
        for sibling in path {
            if idx % 2 == 0 {
                hash = hash_node(&hash, sibling);
            } else {
                hash = hash_node(sibling, &hash);
            }
            idx /= 2;
        }
        hash == root
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }
}

fn hash_leaf(leaf: &[u8; 32]) -> [u8; 32] {
    let mut hasher = AsconHash256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(leaf);
    hasher.finalize()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = AsconHash256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

fn next_pow2(mut n: usize) -> usize {
    n = n.saturating_sub(1);
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    if usize::BITS == 64 {
        n |= n >> 32;
    }
    n.saturating_add(1)
}
