use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::ascon::AsconHash256;

const SEEDTREE_DOMAIN: &[u8] = b"AURORA-ZKBOO-SEEDTREE";

#[derive(Clone, Debug)]
pub struct SeedTree {
    leaf_count: usize,
    rounds: usize,
    nodes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedReveal {
    pub node: u32,
    pub seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedRevealSet {
    pub leaf_count: u32,
    pub rounds: u32,
    pub nodes: Vec<SeedReveal>,
}

impl SeedTree {
    pub fn new(root: [u8; 32], rounds: usize) -> Self {
        let leaf_count = next_pow2(rounds.max(1));
        let mut nodes = vec![[0u8; 32]; leaf_count * 2];
        nodes[1] = root;
        for idx in 1..leaf_count {
            let left = idx * 2;
            let right = left + 1;
            if left < nodes.len() {
                nodes[left] = derive_child(nodes[idx], idx as u32, 0);
            }
            if right < nodes.len() {
                nodes[right] = derive_child(nodes[idx], idx as u32, 1);
            }
        }
        Self {
            leaf_count,
            rounds,
            nodes,
        }
    }

    pub fn seed_for_round(&self, round: usize) -> Option<[u8; 32]> {
        if round >= self.rounds {
            return None;
        }
        Some(self.nodes[self.leaf_count + round])
    }

    pub fn reveal_for_opened(&self, opened: &[bool]) -> SeedRevealSet {
        let mut nodes = Vec::new();
        let rounds = self.rounds.min(opened.len());
        let mut prefix = vec![0usize; rounds + 1];
        for i in 0..rounds {
            prefix[i + 1] = prefix[i] + opened[i] as usize;
        }
        cover_range(
            &self.nodes,
            self.leaf_count,
            rounds,
            1,
            0,
            self.leaf_count,
            &prefix,
            &mut nodes,
        );
        SeedRevealSet {
            leaf_count: self.leaf_count as u32,
            rounds: rounds as u32,
            nodes,
        }
    }
}

pub struct SeedDeriver {
    leaf_count: usize,
    rounds: usize,
    nodes: Vec<Option<[u8; 32]>>,
}

impl SeedDeriver {
    pub fn new(reveal: &SeedRevealSet) -> Self {
        let leaf_count = reveal.leaf_count as usize;
        let mut nodes = vec![None; leaf_count * 2];
        for item in &reveal.nodes {
            let idx = item.node as usize;
            if idx < nodes.len() {
                nodes[idx] = Some(item.seed);
            }
        }
        Self {
            leaf_count,
            rounds: reveal.rounds as usize,
            nodes,
        }
    }

    pub fn seed_for_round(&self, round: usize) -> Option<[u8; 32]> {
        if round >= self.rounds {
            return None;
        }
        let leaf = self.leaf_count + round;
        let mut node = leaf;
        while node > 0 && self.nodes[node].is_none() {
            node /= 2;
        }
        let mut seed = self.nodes.get(node)?.clone()?;
        let (mut start, mut span) = node_range(self.leaf_count, node);
        while span > 1 {
            let mid = start + span / 2;
            if round < mid {
                seed = derive_child(seed, node as u32, 0);
                node *= 2;
                span /= 2;
            } else {
                seed = derive_child(seed, node as u32, 1);
                node = node * 2 + 1;
                start = mid;
                span /= 2;
            }
        }
        Some(seed)
    }
}

fn cover_range(
    nodes: &[[u8; 32]],
    leaf_count: usize,
    rounds: usize,
    node: usize,
    start: usize,
    span: usize,
    prefix: &[usize],
    out: &mut Vec<SeedReveal>,
) {
    if span == 0 {
        return;
    }
    let end = start.saturating_add(span).min(rounds);
    let count = prefix[end] - prefix[start.min(rounds)];
    if count == 0 {
        return;
    }
    if count == span && end - start == span {
        out.push(SeedReveal {
            node: node as u32,
            seed: nodes[node],
        });
        return;
    }
    if span == 1 {
        out.push(SeedReveal {
            node: node as u32,
            seed: nodes[node],
        });
        return;
    }
    let half = span / 2;
    cover_range(
        nodes,
        leaf_count,
        rounds,
        node * 2,
        start,
        half,
        prefix,
        out,
    );
    cover_range(
        nodes,
        leaf_count,
        rounds,
        node * 2 + 1,
        start + half,
        half,
        prefix,
        out,
    );
}

fn node_range(leaf_count: usize, node: usize) -> (usize, usize) {
    let depth = (usize::BITS - (node as usize).leading_zeros() - 1) as usize;
    let level_start = 1usize << depth;
    let idx = node - level_start;
    let span = leaf_count >> depth;
    (idx * span, span)
}

fn derive_child(seed: [u8; 32], node: u32, dir: u8) -> [u8; 32] {
    let mut hasher = AsconHash256::new();
    hasher.update(SEEDTREE_DOMAIN);
    hasher.update(&seed);
    hasher.update(&node.to_be_bytes());
    hasher.update(&[dir]);
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
