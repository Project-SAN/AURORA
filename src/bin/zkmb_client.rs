use std::env;
use std::fs;
use std::process;

use hornet::config::{DEFAULT_BLOCKLIST_PATH, DEFAULT_POLICY_LABEL};
use hornet::policy::blocklist;
use hornet::policy::extract::HttpHostExtractor;
use hornet::policy::plonk::PlonkPolicy;
use hornet::policy::Blocklist;
use hornet::policy::Extractor;
use hornet::policy::PolicyRegistry;
use hornet::adapters::plonk::validator::PlonkCapsuleValidator;
use hornet::core::policy::ProofKind;
use hornet::types::Error as HornetError;
use hornet::utils::encode_hex;

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
        .ok_or_else(|| format!("usage: {program} <hostname>"))?;

    let blocklist_path =
        env::var("POLICY_BLOCKLIST_JSON").unwrap_or_else(|_| DEFAULT_BLOCKLIST_PATH.into());

    let blocklist_json = fs::read_to_string(&blocklist_path)
        .map_err(|err| format!("failed to read {blocklist_path}: {err}"))?;
    let blocklist = Blocklist::from_json(&blocklist_json)
        .map_err(|err| format!("blocklist parse error: {err:?}"))?;

    let policy = PlonkPolicy::new_from_blocklist(DEFAULT_POLICY_LABEL, &blocklist)
        .map_err(|err| format!("failed to build policy: {err:?}"))?;
    let extractor = HttpHostExtractor::default();
    let request_payload = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let target = extractor
        .extract(request_payload.as_bytes())
        .map_err(|err| format!("failed to extract host: {err:?}"))?;
    let entry = blocklist::entry_from_target(&target)
        .map_err(|err| format!("failed to canonicalise host: {err:?}"))?;
    let canonical_bytes = entry.leaf_bytes();

    let capsule = policy
        .prove_payload(&canonical_bytes)
        .map_err(|err| match err {
            HornetError::PolicyViolation => format!("host '{host}' violates the policy"),
            _ => format!("failed to generate proof: {err:?}"),
        })?;
    let capsule_bytes = capsule.encode();

    let policy_hex = encode_hex(policy.policy_id());
    let expected_commit = hornet::policy::plonk::payload_commitment_bytes(&canonical_bytes);

    let mut registry = PolicyRegistry::new();
    let metadata = policy.metadata(600, 0);
    registry
        .register(metadata)
        .map_err(|_| "failed to register policy metadata".to_string())?;
    let validator = PlonkCapsuleValidator::new();
    let mut payload = capsule_bytes.clone();
    payload.extend_from_slice(&canonical_bytes);
    let (verified, consumed) = registry
        .enforce(&mut payload, &validator)
        .map_err(|_| "local verification failed".to_string())?;
    if consumed != capsule_bytes.len() {
        return Err("capsule length mismatch".into());
    }
    let policy_part = verified
        .part(ProofKind::Policy)
        .ok_or("missing policy proof".to_string())?;
    if policy_part.commitment != expected_commit {
        return Err("commitment mismatch".into());
    }

    println!("local verification succeeded for host '{host}'");
    println!("policy_id: {policy_hex}");
    println!("commitment: {}", encode_hex(&expected_commit));

    Ok(())
}

// Remote verification removed: zkmb_client now runs fully locally.
