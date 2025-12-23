use std::env;
use std::fs;
use std::process;

use hornet::config::{DEFAULT_AUTHORITY_URL, DEFAULT_BLOCKLIST_PATH, DEFAULT_POLICY_LABEL};
use hornet::policy::blocklist;
use hornet::policy::extract::HttpHostExtractor;
use hornet::policy::plonk::PlonkPolicy;
use hornet::policy::Blocklist;
use hornet::policy::Extractor;
use hornet::types::Error as HornetError;
use hornet::utils::encode_hex;
use serde::Deserialize;
use serde_json::Value;

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

    let authority_url =
        env::var("POLICY_AUTHORITY_URL").unwrap_or_else(|_| DEFAULT_AUTHORITY_URL.into());
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
    let capsule_hex = encode_hex(&capsule_bytes);
    let payload_hex = encode_hex(&canonical_bytes);

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
