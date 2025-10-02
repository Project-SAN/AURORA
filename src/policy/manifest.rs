#![allow(dead_code)]

use alloc::vec::Vec;

use ark_bls12_381::Fr;
use ark_ff::PrimeField;

use groth16::math::poseidon::{self, PoseidonMerklePath, PoseidonMerkleTree};

#[cfg(feature = "std")]
use alloc::string::String;

/// CLI など外部入力から受け取る生のルール情報（std 機能前提）
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct RawRule {
    pub cidr: String,
    pub port_start: u16,
    pub port_end: u16,
    pub proto_mask: u16,
    pub classification_tag: u64,
}

/// Poseidon メルクル木に載せる正規化済みルール
#[derive(Clone, Debug)]
pub struct Rule {
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    pub port_start: u16,
    pub port_end: u16,
    pub proto_mask: u16,
    pub classification_tag: u64,
}

/// ルール集合を Poseidon メルクル木と一緒に保持するラッパー
#[derive(Clone, Debug)]
pub struct PolicyTree {
    pub tree: PoseidonMerkleTree,
    pub leaves: Vec<Fr>,
    pub rules: Vec<Rule>,
}

/// クライアント配布用のルール + メルクルパス
#[derive(Clone, Debug)]
pub struct RulePackage {
    pub rule: Rule,
    pub descriptor: Fr,
    pub path: Vec<PoseidonMerkleSibling>,
}

/// メルクルパスに含まれる兄弟ノード情報
#[derive(Clone, Debug)]
pub struct PoseidonMerkleSibling {
    pub sibling: Fr,
    pub sibling_is_left: bool,
}

/// マニフェスト本体
#[derive(Clone, Debug)]
pub struct PolicyManifest {
    pub policy_id: u32,
    pub valid_from_epoch: u64,
    pub valid_until_epoch: u64,
    pub h_policy: Fr,
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// マニフェスト関連のエラー
#[derive(Clone, Debug)]
pub enum ManifestError {
    InvalidCidr,
    InvalidPrefixLen,
    TreePadding,
    Serialization,
}

/// RawRule から Rule を生成（std 前提）
#[cfg(feature = "std")]
pub fn normalize_rule(input: RawRule) -> Result<Rule, ManifestError> {
    use core::str::FromStr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), ManifestError> {
        let mut parts = cidr.split('/');
        let ip_part = parts.next().ok_or(ManifestError::InvalidCidr)?;
        let prefix_part = parts.next().ok_or(ManifestError::InvalidCidr)?;
        if parts.next().is_some() {
            return Err(ManifestError::InvalidCidr);
        }

        let addr = IpAddr::from_str(ip_part).map_err(|_| ManifestError::InvalidCidr)?;
        let prefix_len: u8 = prefix_part
            .parse()
            .map_err(|_| ManifestError::InvalidPrefixLen)?;

        let max_len = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_len {
            return Err(ManifestError::InvalidPrefixLen);
        }

        Ok((addr, prefix_len))
    }

    fn ip_to_128(addr: IpAddr) -> [u8; 16] {
        match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let mut out = [0u8; 16];
                out[12..].copy_from_slice(&octets);
                out
            }
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    let (ip, prefix_len) = parse_cidr(&input.cidr)?;

    Ok(Rule {
        prefix: ip_to_128(ip),
        prefix_len,
        port_start: input.port_start,
        port_end: input.port_end,
        proto_mask: input.proto_mask,
        classification_tag: input.classification_tag,
    })
}

/// 各 Rule の Poseidon 葉ハッシュを計算
pub fn compute_descriptors(rules: &[Rule]) -> Vec<Fr> {
    rules.iter().map(rule_descriptor).collect()
}

/// ルールを Poseidon ハッシュで要約
pub fn rule_descriptor(rule: &Rule) -> Fr {
    let mut elements = Vec::with_capacity(6);

    elements.push(fr_from_u128_bytes(&rule.prefix));
    elements.push(Fr::from(rule.prefix_len as u64));
    elements.push(Fr::from(rule.port_start as u64));
    elements.push(Fr::from(rule.port_end as u64));
    elements.push(Fr::from(rule.proto_mask as u64));
    elements.push(Fr::from(rule.classification_tag));

    poseidon::hash(&elements)
}

/// ルール集合から Poseidon メルクル木を生成
pub fn build_policy_tree(rules: Vec<Rule>) -> Result<PolicyTree, ManifestError> {
    if rules.is_empty() {
        return Err(ManifestError::TreePadding);
    }

    let mut leaves = compute_descriptors(&rules);
    pad_to_power_of_two(&mut leaves)?;

    let tree = PoseidonMerkleTree::new(&leaves).map_err(|_| ManifestError::TreePadding)?;

    Ok(PolicyTree { tree, leaves, rules })
}

/// 葉数を 2 の冪に揃えるためのパディング
fn pad_to_power_of_two(leaves: &mut Vec<Fr>) -> Result<(), ManifestError> {
    let mut len = leaves.len();
    if len == 0 {
        return Err(ManifestError::TreePadding);
    }

    if len.is_power_of_two() {
        return Ok(());
    }

    let last = *leaves.last().unwrap();
    while !len.is_power_of_two() {
        leaves.push(last);
        len += 1;
    }
    Ok(())
}

/// 指定ルールとそのメルクルパスを抽出
pub fn export_rule_package(tree: &PolicyTree, index: usize) -> Result<RulePackage, ManifestError> {
    if index >= tree.rules.len() {
        return Err(ManifestError::TreePadding);
    }

    let path: PoseidonMerklePath = tree
        .tree
        .authentication_path(index)
        .map_err(|_| ManifestError::TreePadding)?;

    let siblings = path
        .siblings
        .iter()
        .map(|sibling| PoseidonMerkleSibling {
            sibling: sibling.sibling,
            sibling_is_left: sibling.sibling_is_left,
        })
        .collect();

    Ok(RulePackage {
        rule: tree.rules[index].clone(),
        descriptor: tree.leaves[index],
        path: siblings,
    })
}

/// マニフェストを構築
pub fn build_manifest(
    policy_id: u32,
    valid_from_epoch: u64,
    valid_until_epoch: u64,
    tree: &PolicyTree,
    verifying_key: Vec<u8>,
    signature: Vec<u8>,
) -> PolicyManifest {
    PolicyManifest {
        policy_id,
        valid_from_epoch,
        valid_until_epoch,
        h_policy: tree.tree.root(),
        verifying_key,
        signature,
    }
}

fn fr_from_u128_bytes(bytes: &[u8; 16]) -> Fr {
    let mut wide = [0u8; 32];
    wide[16..].copy_from_slice(bytes);
    Fr::from_be_bytes_mod_order(&wide)
}
