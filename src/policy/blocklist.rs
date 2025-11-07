use crate::types::Error;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem;
use core::str;
use dusk_plonk::prelude::BlsScalar;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};

use super::extract::TargetValue;

const TAG_EXACT: u8 = 0x01;
const TAG_PREFIX: u8 = 0x02;
const TAG_CIDR: u8 = 0x03;
const TAG_RANGE: u8 = 0x04;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CidrBlock {
    version: IpVersion,
    network: [u8; 16],
    prefix_len: u8,
}

impl CidrBlock {
    pub fn version(&self) -> IpVersion {
        self.version
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn network_bytes(&self) -> &[u8] {
        match self.version {
            IpVersion::V4 => &self.network[..4],
            IpVersion::V6 => &self.network,
        }
    }

    fn leaf_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 1 + self.network_bytes().len());
        out.push(TAG_CIDR);
        out.push(match self.version {
            IpVersion::V4 => 4,
            IpVersion::V6 => 6,
        });
        out.push(self.prefix_len);
        out.extend_from_slice(self.network_bytes());
        out
    }
}

/// Blocklist entry kinds exposed to the rest of the policy layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlocklistEntry {
    /// Raw canonical leaf bytes kept for backwards compatibility.
    Raw(Vec<u8>),
    /// Exact string match (e.g. domain name, token).
    Exact(String),
    /// Prefix match on a string target.
    Prefix(String),
    /// CIDR style network specification.
    Cidr(CidrBlock),
    /// Generic inclusive range (start <= target <= end) encoded as bytes.
    Range { start: Vec<u8>, end: Vec<u8> },
}

impl BlocklistEntry {
    pub fn kind(&self) -> BlocklistEntryKind {
        match self {
            BlocklistEntry::Raw(_) => BlocklistEntryKind::Raw,
            BlocklistEntry::Exact(_) => BlocklistEntryKind::Exact,
            BlocklistEntry::Prefix(_) => BlocklistEntryKind::Prefix,
            BlocklistEntry::Cidr(_) => BlocklistEntryKind::Cidr,
            BlocklistEntry::Range { .. } => BlocklistEntryKind::Range,
        }
    }

    pub fn leaf_bytes(&self) -> Vec<u8> {
        match self {
            BlocklistEntry::Raw(bytes) => bytes.clone(),
            BlocklistEntry::Exact(value) => encode_tagged(TAG_EXACT, value.as_bytes()),
            BlocklistEntry::Prefix(value) => encode_tagged(TAG_PREFIX, value.as_bytes()),
            BlocklistEntry::Cidr(block) => block.leaf_bytes(),
            BlocklistEntry::Range { start, end } => encode_range_leaf(start, end),
        }
    }
}

/// Symbolic kind hint to simplify downstream handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlocklistEntryKind {
    Raw,
    Exact,
    Prefix,
    Cidr,
    Range,
}

/// Merkle authentication path for a specific leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub index: usize,
    pub leaf_bytes: Vec<u8>,
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Reconstruct the Merkle root from the path.
    pub fn compute_root(&self) -> [u8; 32] {
        let mut hash = self.leaf_hash;
        let mut idx = self.index;
        for sibling in &self.siblings {
            hash = if idx % 2 == 0 {
                hash_pair(&hash, sibling)
            } else {
                hash_pair(sibling, &hash)
            };
            idx /= 2;
        }
        hash
    }
}

/// Blocklist parsed from JSON or constructed programmatically.
#[derive(Clone, Debug, Default)]
pub struct Blocklist {
    entries: Vec<BlocklistEntry>,
}

impl Blocklist {
    pub fn new(mut entries: Vec<BlocklistEntry>) -> Self {
        entries.sort_by(|a, b| a.leaf_bytes().cmp(&b.leaf_bytes()));
        Self { entries }
    }

    /// Construct from pre-encoded canonical leaves for backwards compatibility.
    pub fn from_canonical_bytes(entries: Vec<Vec<u8>>) -> Self {
        let entries = entries.into_iter().map(BlocklistEntry::Raw).collect();
        Self::new(entries)
    }

    pub fn entries(&self) -> &[BlocklistEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return the canonical payload for each leaf (including type tags).
    pub fn canonical_leaves(&self) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .map(BlocklistEntry::leaf_bytes)
            .collect()
    }

    /// Compute the Merkle authentication path for the leaf at `index`.
    pub fn merkle_proof(&self, index: usize) -> Option<MerkleProof> {
        let leaves = self.leaf_hashes();
        if index >= leaves.len() {
            return None;
        }
        let leaf_hash = leaves[index];
        let leaf_bytes = self.entries[index].leaf_bytes();
        let mut idx = index;
        let mut siblings = Vec::new();
        let mut level = leaves;
        while level.len() > 1 {
            let is_right = idx % 2 == 1;
            let sibling_idx = if is_right {
                idx.saturating_sub(1)
            } else {
                idx + 1
            };
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[idx]
            };
            siblings.push(sibling);

            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for chunk in level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
                next.push(hash_pair(&left, &right));
            }
            idx /= 2;
            level = next;
        }
        Some(MerkleProof {
            index,
            leaf_bytes,
            leaf_hash,
            siblings,
        })
    }

    /// Return Merkle proofs for the immediate neighbors of `index`.
    pub fn merkle_neighbors(&self, index: usize) -> (Option<MerkleProof>, Option<MerkleProof>) {
        if self.entries.is_empty() || index >= self.entries.len() {
            return (None, None);
        }
        let left = if index > 0 {
            self.merkle_proof(index - 1)
        } else {
            None
        };
        let right = if index + 1 < self.entries.len() {
            self.merkle_proof(index + 1)
        } else {
            None
        };
        (left, right)
    }

    /// Hash each entry with SHA-256 to produce fixed-length leaves.
    pub fn leaf_hashes(&self) -> Vec<[u8; 32]> {
        self.entries
            .iter()
            .map(|entry| {
                let mut hasher = Sha256::new();
                hasher.update(&entry.leaf_bytes());
                let digest = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&digest);
                out
            })
            .collect()
    }

    /// Build a binary Merkle tree from the hashed leaves and return the root.
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut leaves = self.leaf_hashes();
        if leaves.is_empty() {
            return [0u8; 32];
        }
        while leaves.len() > 1 {
            let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
            for chunk in leaves.chunks(2) {
                let pair = if chunk.len() == 2 {
                    [chunk[0], chunk[1]]
                } else {
                    [chunk[0], chunk[0]]
                };
                next.push(hash_pair(&pair[0], &pair[1]));
            }
            leaves = next;
        }
        leaves[0]
    }

    pub fn hashes_as_scalars(&self) -> Vec<BlsScalar> {
        self.entries
            .iter()
            .map(|entry| scalar_from_leaf(entry.leaf_bytes()))
            .collect()
    }

    pub fn from_json(json: &str) -> crate::types::Result<Self> {
        let parsed: BlocklistJson = serde_json::from_str(json).map_err(|_| Error::Crypto)?;
        let mut entries = Vec::with_capacity(parsed.entries.len());
        for rule in parsed.entries {
            let entry = match rule.kind {
                BlocklistJsonKind::Exact => {
                    let value = rule.value.ok_or(Error::Crypto)?;
                    BlocklistEntry::Exact(normalize_ascii(&value)?)
                }
                BlocklistJsonKind::Prefix => {
                    let value = rule.value.ok_or(Error::Crypto)?;
                    BlocklistEntry::Prefix(normalize_ascii(&value)?)
                }
                BlocklistJsonKind::Cidr => {
                    let value = rule.value.ok_or(Error::Crypto)?;
                    let normalized = normalize_ascii(&value)?;
                    BlocklistEntry::Cidr(parse_cidr(&normalized)?)
                }
                BlocklistJsonKind::Range => {
                    let start = rule.start.ok_or(Error::Crypto)?;
                    let end = rule.end.ok_or(Error::Crypto)?;
                    let normalized_start = normalize_ascii(&start)?;
                    let normalized_end = normalize_ascii(&end)?;
                    let (start_bytes, end_bytes) = ensure_range_order(
                        normalized_start.into_bytes(),
                        normalized_end.into_bytes(),
                    );
                    BlocklistEntry::Range {
                        start: start_bytes,
                        end: end_bytes,
                    }
                }
            };
            entries.push(entry);
        }
        Ok(Self::new(entries))
    }
}

/// Build a canonical blocklist entry from a target value extracted from payloads.
pub fn entry_from_target(target: &TargetValue) -> crate::types::Result<BlocklistEntry> {
    match target {
        TargetValue::Domain(bytes) => {
            let value = str::from_utf8(bytes).map_err(|_| Error::Crypto)?;
            Ok(BlocklistEntry::Exact(value.to_owned()))
        }
        TargetValue::Ipv4(addr) => {
            let bytes = addr.to_vec();
            Ok(BlocklistEntry::Range {
                start: bytes.clone(),
                end: bytes,
            })
        }
        TargetValue::Ipv6(addr) => {
            let bytes = addr.to_vec();
            Ok(BlocklistEntry::Range {
                start: bytes.clone(),
                end: bytes,
            })
        }
    }
}

fn encode_tagged(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + payload.len());
    out.push(tag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn encode_range_leaf(start: &[u8], end: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + start.len() + 4 + end.len());
    out.push(TAG_RANGE);
    out.extend_from_slice(&(start.len() as u32).to_be_bytes());
    out.extend_from_slice(start);
    out.extend_from_slice(&(end.len() as u32).to_be_bytes());
    out.extend_from_slice(end);
    out
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn scalar_from_leaf(leaf: Vec<u8>) -> BlsScalar {
    let digest = Sha512::digest(&leaf);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    BlsScalar::from_bytes_wide(&wide)
}

fn normalize_ascii(input: &str) -> crate::types::Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Crypto);
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn ensure_range_order(mut start: Vec<u8>, mut end: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    if start > end {
        mem::swap(&mut start, &mut end);
    }
    (start, end)
}

#[derive(Deserialize)]
struct BlocklistJson {
    #[serde(default)]
    entries: Vec<BlocklistJsonRule>,
}

#[derive(Deserialize)]
struct BlocklistJsonRule {
    #[serde(rename = "type")]
    kind: BlocklistJsonKind,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum BlocklistJsonKind {
    Exact,
    Prefix,
    Cidr,
    Range,
}

fn parse_cidr(value: &str) -> crate::types::Result<CidrBlock> {
    let (addr_part, prefix_part) = value.split_once('/').ok_or(Error::Crypto)?;
    let prefix_len: u8 = prefix_part.parse().map_err(|_| Error::Crypto)?;
    if addr_part.contains(':') {
        if prefix_len > 128 {
            return Err(Error::Crypto);
        }
        let addr_bytes = parse_ipv6(addr_part).ok_or(Error::Crypto)?;
        let mask = if prefix_len == 0 {
            0u128
        } else {
            (!0u128) << (128 - prefix_len as u32)
        };
        let network = u128::from_be_bytes(addr_bytes) & mask;
        Ok(CidrBlock {
            version: IpVersion::V6,
            network: network.to_be_bytes(),
            prefix_len,
        })
    } else {
        if prefix_len > 32 {
            return Err(Error::Crypto);
        }
        let octets = parse_ipv4(addr_part).ok_or(Error::Crypto)?;
        let mut value = ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | octets[3] as u32;
        let mask = if prefix_len == 0 {
            0u32
        } else {
            (!0u32) << (32 - prefix_len as u32)
        };
        value &= mask;
        let mut network = [0u8; 16];
        network[..4].copy_from_slice(&value.to_be_bytes());
        Ok(CidrBlock {
            version: IpVersion::V4,
            network,
            prefix_len,
        })
    }
}

fn parse_ipv4(addr: &str) -> Option<[u8; 4]> {
    let mut bytes = [0u8; 4];
    let mut parts = addr.split('.');
    for i in 0..4 {
        let part = parts.next()?;
        if part.is_empty() {
            return None;
        }
        let value: u8 = part.parse().ok()?;
        bytes[i] = value;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(bytes)
}

fn parse_ipv6(addr: &str) -> Option<[u8; 16]> {
    if addr.is_empty() {
        return None;
    }
    if let Some(first) = addr.find("::") {
        if addr[first + 2..].contains("::") {
            return None;
        }
    }
    let mut bytes = [0u8; 16];
    if let Some((head, tail)) = addr.split_once("::") {
        let head_parts: Vec<&str> = if head.is_empty() {
            Vec::new()
        } else {
            head.split(':').collect()
        };
        let tail_parts: Vec<&str> = if tail.is_empty() {
            Vec::new()
        } else {
            tail.split(':').collect()
        };
        if head_parts.iter().any(|p| p.is_empty()) || tail_parts.iter().any(|p| p.is_empty()) {
            return None;
        }
        if head_parts.len() + tail_parts.len() > 8 {
            return None;
        }
        let mut hextets = Vec::with_capacity(8);
        for part in head_parts {
            if part.contains('.') {
                return None;
            }
            hextets.push(parse_hextet(part)?);
        }
        let zero_fill = 8 - (hextets.len() + tail_parts.len());
        for _ in 0..zero_fill {
            hextets.push(0);
        }
        for part in tail_parts {
            if part.contains('.') {
                return None;
            }
            hextets.push(parse_hextet(part)?);
        }
        if hextets.len() != 8 {
            return None;
        }
        for (i, value) in hextets.iter().enumerate() {
            bytes[i * 2] = (value >> 8) as u8;
            bytes[i * 2 + 1] = (*value & 0xFF) as u8;
        }
        Some(bytes)
    } else {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 8 {
            return None;
        }
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() || part.contains('.') {
                return None;
            }
            let value = parse_hextet(part)?;
            bytes[i * 2] = (value >> 8) as u8;
            bytes[i * 2 + 1] = (value & 0xFF) as u8;
        }
        Some(bytes)
    }
}

fn parse_hextet(part: &str) -> Option<u16> {
    if part.len() > 4 || part.is_empty() {
        return None;
    }
    u16::from_str_radix(part, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn merkle_root_deterministic() {
        let bl = Blocklist::from_canonical_bytes(vec![b"a".to_vec(), b"b".to_vec()]);
        let root1 = bl.merkle_root();
        let root2 = bl.merkle_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn canonical_leaf_tags() {
        let entries = vec![
            BlocklistEntry::Exact("Example.COM".into()),
            BlocklistEntry::Prefix(" sub ".into()),
            BlocklistEntry::Raw(b"raw".to_vec()),
            BlocklistEntry::Range {
                start: b"1".to_vec(),
                end: b"9".to_vec(),
            },
        ];
        let blocklist = Blocklist::new(entries);
        let leaves = blocklist.canonical_leaves();
        assert!(leaves.iter().any(|leaf| leaf.first() == Some(&TAG_EXACT)));
        assert!(leaves.iter().any(|leaf| leaf.first() == Some(&TAG_PREFIX)));
        assert!(leaves.iter().any(|leaf| leaf.first() == Some(&TAG_RANGE)));
        assert!(leaves.iter().any(|leaf| leaf == b"raw"));
    }

    #[test]
    fn merkle_proof_reconstructs_root() {
        let blocklist = Blocklist::from_canonical_bytes(vec![
            b"alpha".to_vec(),
            b"beta".to_vec(),
            b"gamma".to_vec(),
        ]);
        let root = blocklist.merkle_root();
        let proof = blocklist.merkle_proof(1).expect("proof");
        assert_eq!(proof.leaf_bytes, b"beta".to_vec());
        assert_eq!(proof.compute_root(), root);
        assert_eq!(proof.siblings.len(), 2);
    }

    #[test]
    fn merkle_neighbors_return_adjacent_proofs() {
        let blocklist = Blocklist::from_canonical_bytes(vec![
            b"alpha".to_vec(),
            b"beta".to_vec(),
            b"gamma".to_vec(),
        ]);
        let root = blocklist.merkle_root();
        let (left, right) = blocklist.merkle_neighbors(1);
        assert_eq!(left.unwrap().compute_root(), root);
        assert_eq!(right.unwrap().compute_root(), root);
    }

    #[test]
    fn parse_from_json() {
        let json = r#"{
            "entries": [
                {"type": "exact", "value": "Example.com"},
                {"type": "prefix", "value": "Admin"},
                {"type": "cidr", "value": "192.168.10.42/16"},
                {"type": "range", "start": "2000", "end": "1000"}
            ]
        }"#;
        let bl = Blocklist::from_json(json).expect("parse");
        assert_eq!(bl.entries().len(), 4);
        let exact = bl
            .entries()
            .iter()
            .find_map(|entry| match entry {
                BlocklistEntry::Exact(value) => Some(value.as_str()),
                _ => None,
            })
            .unwrap();
        assert_eq!(exact, "example.com");
        let cidr = bl
            .entries()
            .iter()
            .find_map(|entry| match entry {
                BlocklistEntry::Cidr(block) => Some(block),
                _ => None,
            })
            .unwrap();
        assert_eq!(cidr.version(), IpVersion::V4);
        assert_eq!(cidr.prefix_len(), 16);
        assert_eq!(cidr.network_bytes(), &[192, 168, 0, 0]);
        let range = bl
            .entries()
            .iter()
            .find_map(|entry| match entry {
                BlocklistEntry::Range { start, end } => Some((start, end)),
                _ => None,
            })
            .unwrap();
        assert!(range.0 <= range.1);
    }

    #[test]
    fn cidr_ipv6_normalization() {
        let block = parse_cidr("2001:0db8:0:0:0:0:0:1/64").expect("parse");
        assert_eq!(block.version(), IpVersion::V6);
        assert_eq!(block.prefix_len(), 64);
        assert_eq!(
            block.network_bytes()[..16],
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ]
        );
    }
}
