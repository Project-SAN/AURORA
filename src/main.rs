use std::fs;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use actix_web::{web, App, HttpServer};
use hornet::api::hello::{hello, manual_hello};
use hornet::api::prove::{
    oprf_eval, policy_bundle, prove, verify, witness, PolicyAuthorityState, ProofPipelineHandle,
};
use hornet::config::{DEFAULT_BLOCKLIST_PATH, DEFAULT_POLICY_LABEL};
use hornet::policy::extract::HttpHostExtractor;
use hornet::policy::oprf;
use hornet::policy::plonk::{self, PlonkPolicy};
use hornet::policy::Blocklist;
use hornet::utils::encode_hex;
use hornet::utils::decode_hex;

#[actix_web::main]
async fn main() -> io::Result<()> {
    let authority_state = Arc::new(init_authority_state()?);
    let directory_data: web::Data<PolicyAuthorityState> = web::Data::from(authority_state.clone());
    let pipeline_arc: Arc<ProofPipelineHandle> = authority_state.clone();
    let pipeline_data: web::Data<Arc<ProofPipelineHandle>> = web::Data::new(pipeline_arc);
    HttpServer::new(move || {
        App::new()
            .app_data(directory_data.clone())
            .app_data(pipeline_data.clone())
            .service(hello)
            .service(prove)
            .service(verify)
            .service(witness)
            .service(oprf_eval)
            .service(policy_bundle)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

fn init_authority_state() -> io::Result<PolicyAuthorityState> {
    let mut state = PolicyAuthorityState::new();
    let label = policy_label_from_env();
    let (policy, policy_id, blocklist, oprf_key) =
        load_policy_with_label(DEFAULT_BLOCKLIST_PATH, &label)?;
    plonk::register_policy(policy.clone());
    state.register_policy(policy, HttpHostExtractor::default(), oprf_key, blocklist);

    println!("registered policy {}", encode_hex(&policy_id));
    Ok(state)
}

fn load_policy_with_label(
    block_list_path: &str,
    label: &[u8],
) -> io::Result<(
    Arc<PlonkPolicy>,
    hornet::policy::PolicyId,
    Blocklist,
    curve25519_dalek::scalar::Scalar,
)> {
    let json = fs::read_to_string(block_list_path)?;
    let blocklist = Blocklist::from_json(&json).map_err(|err| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("blocklist parse error: {err:?}"),
        )
    })?;
    let oprf_key = oprf_key_from_env_or_label(label)?;
    let oprf_blocklist = oprf_blocklist_from(&blocklist, &oprf_key);
    let policy = Arc::new(
        PlonkPolicy::new_from_blocklist(label, &oprf_blocklist).map_err(|err| {
            io::Error::new(ErrorKind::Other, format!("failed to build policy: {err:?}"))
        })?,
    );

    let policy_id = *policy.policy_id();
    Ok((policy, policy_id, oprf_blocklist, oprf_key))
}

fn policy_label_from_env() -> Vec<u8> {
    match std::env::var("POLICY_LABEL") {
        Ok(label) if !label.trim().is_empty() => label.into_bytes(),
        _ => DEFAULT_POLICY_LABEL.to_vec(),
    }
}

fn oprf_key_from_env_or_label(label: &[u8]) -> io::Result<curve25519_dalek::scalar::Scalar> {
    match std::env::var("POLICY_OPRF_KEY_HEX") {
        Ok(hex) => {
            let seed = decode_hex(hex.as_str()).map_err(|err| {
                io::Error::new(ErrorKind::InvalidData, format!("OPRF key hex error: {err}"))
            })?;
            Ok(oprf::derive_key_from_seed(&seed))
        }
        Err(_) => Ok(oprf::derive_key_from_seed(label)),
    }
}

fn oprf_blocklist_from(
    blocklist: &Blocklist,
    key: &curve25519_dalek::scalar::Scalar,
) -> Blocklist {
    let mut leaves = Vec::with_capacity(blocklist.len());
    for entry in blocklist.entries() {
        let leaf = entry.leaf_bytes();
        let evaluated = oprf::eval_unblinded(key, &leaf);
        leaves.push(evaluated.to_vec());
    }
    Blocklist::from_canonical_bytes(leaves)
}
