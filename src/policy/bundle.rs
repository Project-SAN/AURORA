use crate::utils::{decode_hex, encode_hex};
use alloc::vec::Vec;
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct PolicyBundle {
    pub policy_id: [u8; 32],
    pub prover_bytes: Vec<u8>,
    pub block_hashes: Vec<[u8; 32]>,
}

#[derive(Deserialize)]
struct PolicyBundleResponse {
    policy_id: String,
    prover_hex: String,
    block_hashes_hex: Vec<String>,
}

#[cfg(feature = "http-client")]
pub fn fetch_policy_bundle(
    bundle_url: &str,
    policy_id: &[u8; 32],
) -> Result<PolicyBundle, String> {
    let policy_hex = encode_hex(policy_id);
    let endpoint = format!("{}/{}", bundle_url.trim_end_matches('/'), policy_hex);
    let response = ureq::get(&endpoint)
        .call()
        .map_err(|err| format!("policy bundle request failed: {err}"))?;
    let parsed: PolicyBundleResponse = response
        .into_json()
        .map_err(|err| format!("policy bundle decode failed: {err}"))?;
    if parsed.policy_id != policy_hex {
        return Err("policy bundle policy_id mismatch".into());
    }
    let prover_bytes =
        decode_hex(&parsed.prover_hex).map_err(|err| format!("prover hex decode: {err}"))?;
    let mut block_hashes = Vec::with_capacity(parsed.block_hashes_hex.len());
    for hex in parsed.block_hashes_hex {
        let bytes = decode_hex(&hex).map_err(|err| format!("block hash decode: {err}"))?;
        if bytes.len() != 32 {
            return Err("block hash length mismatch".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        block_hashes.push(out);
    }
    Ok(PolicyBundle {
        policy_id: *policy_id,
        prover_bytes,
        block_hashes,
    })
}

#[cfg(feature = "std")]
pub fn policy_bundle_url(authority_url: &str) -> Option<String> {
    std::env::var("POLICY_BUNDLE_URL")
        .ok()
        .or_else(|| {
            let trimmed = authority_url.trim_end_matches('/');
            Some(format!("{trimmed}/policy-bundle"))
        })
}
