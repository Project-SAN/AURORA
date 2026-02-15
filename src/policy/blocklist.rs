use crate::types::Error;
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
pub const MAX_VALUE_LEN: usize = 255;
pub const MAX_LEAF_LEN: usize = 1 + 4 + MAX_VALUE_LEN + 4 + MAX_VALUE_LEN;
pub const MAX_BLOCKLIST_ENTRIES: usize = 4096;
pub const MAX_MERKLE_DEPTH: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FixedBytes<const N: usize> {
    len: u16,
    buf: [u8; N],
}

impl<const N: usize> FixedBytes<N> {
    pub fn new(data: &[u8]) -> crate::types::Result<Self> {
        if data.len() > N || data.len() > u16::MAX as usize {
            return Err(Error::Crypto);
        }
        let mut buf = [0u8; N];
        buf[..data.len()].copy_from_slice(data);
        Ok(Self {
            len: data.len() as u16,
            buf,
        })
    }

    pub const fn empty() -> Self {
        Self {
            len: 0,
            buf: [0u8; N],
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len()]
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    pub fn as_str(&self) -> crate::types::Result<&str> {
        str::from_utf8(self.as_slice()).map_err(|_| Error::Crypto)
    }
}

impl<const N: usize> core::fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FixedBytes")
            .field("len", &self.len())
            .field("bytes", &self.as_slice())
            .finish()
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> Ord for FixedBytes<N> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl<const N: usize> PartialOrd for FixedBytes<N> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub type LeafBytes = FixedBytes<MAX_LEAF_LEN>;
pub type ValueBytes = FixedBytes<MAX_VALUE_LEN>;

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

    fn leaf_bytes(&self) -> LeafBytes {
        let mut out = [0u8; MAX_LEAF_LEN];
        let mut idx = 0;
        out[idx] = TAG_CIDR;
        idx += 1;
        out[idx] = match self.version {
            IpVersion::V4 => 4,
            IpVersion::V6 => 6,
        };
        idx += 1;
        out[idx] = self.prefix_len;
        idx += 1;
        let network = self.network_bytes();
        out[idx..idx + network.len()].copy_from_slice(network);
        idx += network.len();
        LeafBytes {
            len: idx as u16,
            buf: out,
        }
    }
}

/// Blocklist entry kinds exposed to the rest of the policy layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlocklistEntry {
    /// Raw canonical leaf bytes kept for backwards compatibility.
    Raw(LeafBytes),
    /// Exact string match (e.g. domain name, token).
    Exact(ValueBytes),
    /// Prefix match on a string target.
    Prefix(ValueBytes),
    /// CIDR style network specification.
    Cidr(CidrBlock),
    /// Generic inclusive range (start <= target <= end) encoded as bytes.
    Range { start: ValueBytes, end: ValueBytes },
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

    pub fn leaf_bytes(&self) -> LeafBytes {
        match self {
            BlocklistEntry::Raw(bytes) => *bytes,
            BlocklistEntry::Exact(value) => encode_tagged(TAG_EXACT, value.as_slice()),
            BlocklistEntry::Prefix(value) => encode_tagged(TAG_PREFIX, value.as_slice()),
            BlocklistEntry::Cidr(block) => block.leaf_bytes(),
            BlocklistEntry::Range { start, end } => {
                encode_range_leaf(start.as_slice(), end.as_slice())
            }
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
    pub leaf_bytes: LeafBytes,
    pub leaf_hash: [u8; 32],
    pub siblings_len: u8,
    pub siblings: [[u8; 32]; MAX_MERKLE_DEPTH],
}

#[derive(Clone)]
pub struct MerkleWorkspace {
    level: [[u8; 32]; MAX_BLOCKLIST_ENTRIES],
    next: [[u8; 32]; MAX_BLOCKLIST_ENTRIES],
}

impl MerkleWorkspace {
    pub const fn new() -> Self {
        Self {
            level: [[0u8; 32]; MAX_BLOCKLIST_ENTRIES],
            next: [[0u8; 32]; MAX_BLOCKLIST_ENTRIES],
        }
    }

    pub fn slices(&mut self) -> (&mut [[u8; 32]], &mut [[u8; 32]]) {
        (&mut self.level, &mut self.next)
    }
}

impl Default for MerkleWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleProof {
    /// Reconstruct the Merkle root from the path.
    pub fn compute_root(&self) -> [u8; 32] {
        let mut hash = self.leaf_hash;
        let mut idx = self.index;
        for sibling in self.siblings[..self.siblings_len as usize].iter() {
            hash = if idx.is_multiple_of(2) {
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
    pub fn new(mut entries: Vec<BlocklistEntry>) -> crate::types::Result<Self> {
        if entries.len() > MAX_BLOCKLIST_ENTRIES {
            return Err(Error::Crypto);
        }
        entries.sort_by_key(BlocklistEntry::leaf_bytes);
        Ok(Self { entries })
    }

    /// Construct from pre-encoded canonical leaves for backwards compatibility.
    pub fn from_canonical_bytes(entries: Vec<LeafBytes>) -> crate::types::Result<Self> {
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

    pub fn insertion_index(&self, leaf: &LeafBytes) -> crate::types::Result<usize> {
        let mut low = 0usize;
        let mut high = self.entries.len();
        while low < high {
            let mid = (low + high) / 2;
            let mid_leaf = self.entries[mid].leaf_bytes();
            match mid_leaf.as_slice().cmp(leaf.as_slice()) {
                core::cmp::Ordering::Less => low = mid + 1,
                core::cmp::Ordering::Greater => high = mid,
                core::cmp::Ordering::Equal => return Err(Error::PolicyViolation),
            }
        }
        Ok(low)
    }

    /// Return the canonical payload for each leaf (including type tags).
    pub fn canonical_leaves_into(&self, out: &mut [LeafBytes]) -> crate::types::Result<usize> {
        let len = self.entries.len();
        if out.len() < len {
            return Err(Error::Crypto);
        }
        for (idx, entry) in self.entries.iter().enumerate() {
            out[idx] = entry.leaf_bytes();
        }
        Ok(len)
    }

    pub fn merkle_proof_with(
        &self,
        level: &mut [[u8; 32]],
        next: &mut [[u8; 32]],
        index: usize,
    ) -> Option<MerkleProof> {
        if level.len() < self.entries.len() || next.len() < self.entries.len() {
            return None;
        }
        let mut level_len = match self.leaf_hashes_into(level) {
            Ok(len) => len,
            Err(_) => return None,
        };
        if index >= level_len {
            return None;
        }
        let leaf_hash = level[index];
        let leaf_bytes = self.entries[index].leaf_bytes();
        let mut idx = index;
        let mut siblings = [[0u8; 32]; MAX_MERKLE_DEPTH];
        let mut siblings_len = 0usize;
        while level_len > 1 {
            let is_right = idx % 2 == 1;
            let sibling_idx = if is_right {
                idx.saturating_sub(1)
            } else {
                idx + 1
            };
            let sibling = if sibling_idx < level_len {
                level[sibling_idx]
            } else {
                level[idx]
            };
            if siblings_len >= MAX_MERKLE_DEPTH {
                return None;
            }
            siblings[siblings_len] = sibling;
            siblings_len += 1;

            let mut next_len = 0usize;
            let mut i = 0usize;
            while i < level_len {
                let left = level[i];
                let right = if i + 1 < level_len {
                    level[i + 1]
                } else {
                    level[i]
                };
                next[next_len] = hash_pair(&left, &right);
                next_len += 1;
                i += 2;
            }
            idx /= 2;
            level[..next_len].copy_from_slice(&next[..next_len]);
            level_len = next_len;
        }
        Some(MerkleProof {
            index,
            leaf_bytes,
            leaf_hash,
            siblings_len: siblings_len as u8,
            siblings,
        })
    }

    /// Return Merkle proofs for the immediate neighbors of `index`.
    pub fn merkle_neighbors_with(
        &self,
        level: &mut [[u8; 32]],
        next: &mut [[u8; 32]],
        index: usize,
    ) -> (Option<MerkleProof>, Option<MerkleProof>) {
        if self.entries.is_empty() || index >= self.entries.len() {
            return (None, None);
        }
        let left = if index > 0 {
            self.merkle_proof_with(level, next, index - 1)
        } else {
            None
        };
        let right = if index + 1 < self.entries.len() {
            self.merkle_proof_with(level, next, index + 1)
        } else {
            None
        };
        (left, right)
    }

    /// Hash each entry with SHA-256 to produce fixed-length leaves.
    pub fn leaf_hashes_into(&self, out: &mut [[u8; 32]]) -> crate::types::Result<usize> {
        let len = self.entries.len();
        if out.len() < len {
            return Err(Error::Crypto);
        }
        for (idx, entry) in self.entries.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(entry.leaf_bytes().as_slice());
            let digest = hasher.finalize();
            out[idx].copy_from_slice(&digest);
        }
        Ok(len)
    }

    pub fn merkle_root_with(&self, level: &mut [[u8; 32]], next: &mut [[u8; 32]]) -> [u8; 32] {
        if level.len() < self.entries.len() || next.len() < self.entries.len() {
            return [0u8; 32];
        }
        let mut level_len = match self.leaf_hashes_into(level) {
            Ok(len) => len,
            Err(_) => return [0u8; 32],
        };
        if level_len == 0 {
            return [0u8; 32];
        }
        while level_len > 1 {
            let mut next_len = 0usize;
            let mut i = 0usize;
            while i < level_len {
                let left = level[i];
                let right = if i + 1 < level_len {
                    level[i + 1]
                } else {
                    level[i]
                };
                next[next_len] = hash_pair(&left, &right);
                next_len += 1;
                i += 2;
            }
            level[..next_len].copy_from_slice(&next[..next_len]);
            level_len = next_len;
        }
        level[0]
    }

    pub fn merkle_proof_in_workspace(
        &self,
        workspace: &mut MerkleWorkspace,
        index: usize,
    ) -> Option<MerkleProof> {
        let (level, next) = workspace.slices();
        self.merkle_proof_with(level, next, index)
    }

    pub fn merkle_neighbors_in_workspace(
        &self,
        workspace: &mut MerkleWorkspace,
        index: usize,
    ) -> (Option<MerkleProof>, Option<MerkleProof>) {
        let (level, next) = workspace.slices();
        self.merkle_neighbors_with(level, next, index)
    }

    pub fn merkle_root_in_workspace(&self, workspace: &mut MerkleWorkspace) -> [u8; 32] {
        let (level, next) = workspace.slices();
        self.merkle_root_with(level, next)
    }

    pub fn hashes_as_scalars_into(&self, out: &mut [BlsScalar]) -> crate::types::Result<usize> {
        let len = self.entries.len();
        if out.len() < len {
            return Err(Error::Crypto);
        }
        for (idx, entry) in self.entries.iter().enumerate() {
            out[idx] = scalar_from_leaf(entry.leaf_bytes().as_slice());
        }
        Ok(len)
    }

    pub fn from_json(json: &str) -> crate::types::Result<Self> {
        let parsed: BlocklistJson<'_> = serde_json::from_str(json).map_err(|_| Error::Crypto)?;
        let mut entries = Vec::with_capacity(parsed.entries.len());
        for rule in parsed.entries {
            let entry = match rule.kind {
                BlocklistJsonKind::Exact => {
                    let value = rule.value.ok_or(Error::Crypto)?;
                    BlocklistEntry::Exact(normalize_ascii(value)?)
                }
                BlocklistJsonKind::Prefix => {
                    let value = rule.value.ok_or(Error::Crypto)?;
                    BlocklistEntry::Prefix(normalize_ascii(value)?)
                }
                BlocklistJsonKind::Cidr => {
                    let value = rule.value.ok_or(Error::Crypto)?;
                    let normalized = normalize_ascii(value)?;
                    BlocklistEntry::Cidr(parse_cidr(normalized.as_str()?)?)
                }
                BlocklistJsonKind::Range => {
                    let start = rule.start.ok_or(Error::Crypto)?;
                    let end = rule.end.ok_or(Error::Crypto)?;
                    let normalized_start = normalize_ascii(start)?;
                    let normalized_end = normalize_ascii(end)?;
                    let (start_bytes, end_bytes) =
                        ensure_range_order(normalized_start, normalized_end);
                    BlocklistEntry::Range {
                        start: start_bytes,
                        end: end_bytes,
                    }
                }
            };
            entries.push(entry);
        }
        Self::new(entries)
    }
}

/// Build a canonical blocklist entry from a target value extracted from payloads.
pub fn entry_from_target(target: &TargetValue) -> crate::types::Result<BlocklistEntry> {
    match target {
        TargetValue::Domain(bytes) => {
            let value = str::from_utf8(bytes).map_err(|_| Error::Crypto)?;
            Ok(BlocklistEntry::Exact(ValueBytes::new(value.as_bytes())?))
        }
        TargetValue::Ipv4(addr) => {
            let bytes = ValueBytes::new(addr)?;
            Ok(BlocklistEntry::Range {
                start: bytes,
                end: bytes,
            })
        }
        TargetValue::Ipv6(addr) => {
            let bytes = ValueBytes::new(addr)?;
            Ok(BlocklistEntry::Range {
                start: bytes,
                end: bytes,
            })
        }
    }
}

fn encode_tagged(tag: u8, payload: &[u8]) -> LeafBytes {
    let mut out = [0u8; MAX_LEAF_LEN];
    let mut idx = 0;
    out[idx] = tag;
    idx += 1;
    out[idx..idx + 4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    idx += 4;
    out[idx..idx + payload.len()].copy_from_slice(payload);
    idx += payload.len();
    LeafBytes {
        len: idx as u16,
        buf: out,
    }
}

fn encode_range_leaf(start: &[u8], end: &[u8]) -> LeafBytes {
    let mut out = [0u8; MAX_LEAF_LEN];
    let mut idx = 0;
    out[idx] = TAG_RANGE;
    idx += 1;
    out[idx..idx + 4].copy_from_slice(&(start.len() as u32).to_be_bytes());
    idx += 4;
    out[idx..idx + start.len()].copy_from_slice(start);
    idx += start.len();
    out[idx..idx + 4].copy_from_slice(&(end.len() as u32).to_be_bytes());
    idx += 4;
    out[idx..idx + end.len()].copy_from_slice(end);
    idx += end.len();
    LeafBytes {
        len: idx as u16,
        buf: out,
    }
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

fn scalar_from_leaf(leaf: &[u8]) -> BlsScalar {
    let digest = Sha512::digest(leaf);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    BlsScalar::from_bytes_wide(&wide)
}

fn normalize_ascii(input: &str) -> crate::types::Result<ValueBytes> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Crypto);
    }
    if trimmed.len() > MAX_VALUE_LEN {
        return Err(Error::Crypto);
    }
    let mut buf = [0u8; MAX_VALUE_LEN];
    for (idx, byte) in trimmed.as_bytes().iter().enumerate() {
        buf[idx] = byte.to_ascii_lowercase();
    }
    Ok(ValueBytes {
        len: trimmed.len() as u16,
        buf,
    })
}

fn ensure_range_order(mut start: ValueBytes, mut end: ValueBytes) -> (ValueBytes, ValueBytes) {
    if start.as_slice() > end.as_slice() {
        mem::swap(&mut start, &mut end);
    }
    (start, end)
}

#[derive(Deserialize)]
struct BlocklistJson<'a> {
    #[serde(default)]
    #[serde(borrow)]
    entries: Vec<BlocklistJsonRule<'a>>,
}

#[derive(Deserialize)]
struct BlocklistJsonRule<'a> {
    #[serde(rename = "type")]
    kind: BlocklistJsonKind,
    #[serde(default)]
    value: Option<&'a str>,
    #[serde(default)]
    start: Option<&'a str>,
    #[serde(default)]
    end: Option<&'a str>,
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
    for byte in &mut bytes {
        let part = parts.next()?;
        if part.is_empty() {
            return None;
        }
        let value: u8 = part.parse().ok()?;
        *byte = value;
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
        let mut hextets = [0u16; 8];
        let mut head_len = 0usize;
        let mut tail_len = 0usize;
        if !head.is_empty() {
            for part in head.split(':') {
                if part.is_empty() || part.contains('.') || head_len >= 8 {
                    return None;
                }
                hextets[head_len] = parse_hextet(part)?;
                head_len += 1;
            }
        }
        let mut tail_values = [0u16; 8];
        if !tail.is_empty() {
            for part in tail.split(':') {
                if part.is_empty() || part.contains('.') || tail_len >= 8 {
                    return None;
                }
                tail_values[tail_len] = parse_hextet(part)?;
                tail_len += 1;
            }
        }
        if head_len + tail_len > 8 {
            return None;
        }
        for i in 0..tail_len {
            hextets[8 - tail_len + i] = tail_values[i];
        }
        for (i, value) in hextets.iter().enumerate() {
            bytes[i * 2] = (value >> 8) as u8;
            bytes[i * 2 + 1] = (*value & 0xFF) as u8;
        }
        Some(bytes)
    } else {
        let mut idx = 0usize;
        for part in addr.split(':') {
            if part.is_empty() || part.contains('.') || idx >= 8 {
                return None;
            }
            let value = parse_hextet(part)?;
            bytes[idx * 2] = (value >> 8) as u8;
            bytes[idx * 2 + 1] = (value & 0xFF) as u8;
            idx += 1;
        }
        if idx != 8 {
            return None;
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
        let bl = Blocklist::from_canonical_bytes(vec![
            LeafBytes::new(b"a").unwrap(),
            LeafBytes::new(b"b").unwrap(),
        ])
        .unwrap();
        let mut workspace = MerkleWorkspace::new();
        let root1 = bl.merkle_root_in_workspace(&mut workspace);
        let root2 = bl.merkle_root_in_workspace(&mut workspace);
        assert_eq!(root1, root2);
    }

    #[test]
    fn canonical_leaf_tags() {
        let entries = vec![
            BlocklistEntry::Exact(ValueBytes::new(b"Example.COM").unwrap()),
            BlocklistEntry::Prefix(ValueBytes::new(b" sub ").unwrap()),
            BlocklistEntry::Raw(LeafBytes::new(b"raw").unwrap()),
            BlocklistEntry::Range {
                start: ValueBytes::new(b"1").unwrap(),
                end: ValueBytes::new(b"9").unwrap(),
            },
        ];
        let blocklist = Blocklist::new(entries).unwrap();
        let mut leaves = [LeafBytes::empty(); 8];
        let len = blocklist.canonical_leaves_into(&mut leaves).unwrap();
        let leaves = &leaves[..len];
        assert!(leaves
            .iter()
            .any(|leaf| leaf.as_slice().first() == Some(&TAG_EXACT)));
        assert!(leaves
            .iter()
            .any(|leaf| leaf.as_slice().first() == Some(&TAG_PREFIX)));
        assert!(leaves
            .iter()
            .any(|leaf| leaf.as_slice().first() == Some(&TAG_RANGE)));
        assert!(leaves.iter().any(|leaf| leaf.as_slice() == b"raw"));
    }

    #[test]
    fn merkle_proof_reconstructs_root() {
        let blocklist = Blocklist::from_canonical_bytes(vec![
            LeafBytes::new(b"alpha").unwrap(),
            LeafBytes::new(b"beta").unwrap(),
            LeafBytes::new(b"gamma").unwrap(),
        ])
        .unwrap();
        let mut workspace = MerkleWorkspace::new();
        let root = blocklist.merkle_root_in_workspace(&mut workspace);
        let proof = blocklist
            .merkle_proof_in_workspace(&mut workspace, 1)
            .expect("proof");
        assert_eq!(proof.leaf_bytes.as_slice(), b"beta");
        assert_eq!(proof.compute_root(), root);
        assert_eq!(proof.siblings_len, 2);
    }

    #[test]
    fn merkle_neighbors_return_adjacent_proofs() {
        let blocklist = Blocklist::from_canonical_bytes(vec![
            LeafBytes::new(b"alpha").unwrap(),
            LeafBytes::new(b"beta").unwrap(),
            LeafBytes::new(b"gamma").unwrap(),
        ])
        .unwrap();
        let mut workspace = MerkleWorkspace::new();
        let root = blocklist.merkle_root_in_workspace(&mut workspace);
        let (left, right) = blocklist.merkle_neighbors_in_workspace(&mut workspace, 1);
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
                BlocklistEntry::Exact(value) => Some(value.as_str().unwrap()),
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
        assert!(range.0.as_slice() <= range.1.as_slice());
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
