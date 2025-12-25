use std::env;
use std::process;

use hornet::config::DEFAULT_AUTHORITY_URL;
use hornet::policy::blocklist;
use hornet::policy::extract::HttpHostExtractor;
use hornet::policy::oprf;
use hornet::policy::plonk::PlonkPolicy;
use hornet::policy::Extractor;
use hornet::types::Error as HornetError;
use hornet::utils::{decode_hex, encode_hex};
use rand::rngs::SmallRng;
use rand::SeedableRng;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use ureq;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "zkmb_client".into());
    let host = args
        .next()
        .ok_or_else(|| format!("usage: {program} <hostname> (requires POLICY_ID_HEX)"))?;

    let authority_url =
        env::var("POLICY_AUTHORITY_URL").unwrap_or_else(|_| DEFAULT_AUTHORITY_URL.into());
    let policy_id = policy_id_from_env()?
        .ok_or_else(|| "POLICY_ID_HEX is required to fetch policy bundle".to_string())?;
    let bundle_url = policy_bundle_url(&authority_url)
        .ok_or_else(|| "policy bundle url missing".to_string())?;
    let bundle = fetch_policy_bundle(&bundle_url, &policy_id)?;
    let policy = PlonkPolicy::from_prover_bytes(
        bundle.policy_id,
        &bundle.prover_bytes,
        bundle.block_hashes,
    )
    .map_err(|err| format!("failed to load proving key: {err:?}"))?;
    let extractor = HttpHostExtractor::default();
    let request_payload = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let target = extractor
        .extract(request_payload.as_bytes())
        .map_err(|err| format!("failed to extract host: {err:?}"))?;
    let entry = blocklist::entry_from_target(&target)
        .map_err(|err| format!("failed to canonicalise host: {err:?}"))?;
    let canonical_bytes = entry.leaf_bytes();
    let target_leaf = if let Some(oprf_endpoint) = oprf_url(&authority_url) {
        oprf_eval(&oprf_endpoint, &policy_id, &canonical_bytes)?
    } else {
        canonical_bytes.clone()
    };

    let capsule = policy
        .prove_payload(&target_leaf)
        .map_err(|err| match err {
            HornetError::PolicyViolation => format!("host '{host}' violates the policy"),
            _ => format!("failed to generate proof: {err:?}"),
        })?;
    let capsule_bytes = capsule.encode();

    let policy_hex = encode_hex(&policy_id);
    let capsule_hex = encode_hex(&capsule_bytes);
    let payload_hex = encode_hex(&target_leaf);

    let verify_url = format!("{}/verify", authority_url.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new().build();

    let body = serde_json::json!({
        "policy_id": policy_hex,
        "capsule_hex": capsule_hex,
        "payload_hex": payload_hex,
    });

    let response = agent
        .post(&verify_url)
        .set("content-type", "application/json")
        .send_string(&body.to_string());

    let response = match response {
        Ok(resp) => resp,
        Err(ureq::Error::Status(code, resp)) => {
            let message = extract_error(resp);
            return Err(format!(
                "policy authority rejected proof (status {code}): {message}"
            ));
        }
        Err(err) => {
            return Err(format!("failed to contact policy authority: {err}"));
        }
    };

    let verify: VerifyResponse = response
        .into_json()
        .map_err(|err| format!("unable to decode verification response: {err}"))?;

    if !verify.valid {
        return Err("policy authority reported invalid proof".into());
    }

    println!("verification succeeded for host '{host}'");
    println!("policy_id: {policy_hex}");
    println!("commitment: {}", verify.commitment_hex);

    Ok(())
}

struct PolicyBundle {
    policy_id: [u8; 32],
    prover_bytes: Vec<u8>,
    block_hashes: Vec<[u8; 32]>,
}

#[derive(Deserialize)]
struct PolicyBundleResponse {
    policy_id: String,
    prover_hex: String,
    block_hashes_hex: Vec<String>,
}

fn fetch_policy_bundle(bundle_url: &str, policy_id: &[u8; 32]) -> Result<PolicyBundle, String> {
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

fn policy_bundle_url(authority_url: &str) -> Option<String> {
    env::var("POLICY_BUNDLE_URL")
        .ok()
        .or_else(|| {
            let trimmed = authority_url.trim_end_matches('/');
            Some(format!("{trimmed}/policy-bundle"))
        })
}

fn oprf_url(authority_url: &str) -> Option<String> {
    env::var("POLICY_OPRF_URL")
        .ok()
        .or_else(|| {
            let trimmed = authority_url.trim_end_matches('/');
            Some(format!("{trimmed}/oprf"))
        })
}

fn policy_id_from_env() -> Result<Option<[u8; 32]>, String> {
    let value = match env::var("POLICY_ID_HEX") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let bytes = decode_hex(&value).map_err(|err| format!("policy_id hex decode: {err}"))?;
    if bytes.len() != 32 {
        return Err("policy_id must be 32 bytes".into());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(Some(id))
}

#[derive(Deserialize)]
struct OprfResponse {
    evaluated_hex: String,
}

fn oprf_eval(
    oprf_endpoint: &str,
    policy_id: &[u8; 32],
    input: &[u8],
) -> Result<Vec<u8>, String> {
    let mut rng = SmallRng::from_seed(oprf_seed(policy_id, input));
    let (blind, blinded) = oprf::blind(input, &mut rng);
    let body = serde_json::json!({
        "policy_id": encode_hex(policy_id),
        "blinded_hex": encode_hex(&blinded),
    });
    let response = ureq::post(oprf_endpoint)
        .set("content-type", "application/json")
        .send_string(&body.to_string())
        .map_err(|err| format!("oprf request failed: {err}"))?;
    let parsed: OprfResponse = response
        .into_json()
        .map_err(|err| format!("oprf decode failed: {err}"))?;
    let evaluated =
        decode_hex(&parsed.evaluated_hex).map_err(|err| format!("oprf hex decode: {err}"))?;
    if evaluated.len() != 32 {
        return Err("oprf response length mismatch".into());
    }
    let mut evaluated_bytes = [0u8; 32];
    evaluated_bytes.copy_from_slice(&evaluated);
    let unblinded = oprf::unblind(&blind, &evaluated_bytes)
        .ok_or_else(|| "invalid oprf response".to_string())?;
    Ok(unblinded.to_vec())
}

fn oprf_seed(policy_id: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"oprf-blind");
    hasher.update(policy_id);
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn extract_error(response: ureq::Response) -> String {
    match response.into_json::<Value>() {
        Ok(value) => value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown error")
            .to_owned(),
        Err(_) => "unknown error".into(),
    }
}

#[derive(Deserialize)]
struct VerifyResponse {
    valid: bool,
    commitment_hex: String,
}
