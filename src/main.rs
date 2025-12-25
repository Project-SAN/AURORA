use std::fs;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use actix_web::{web, App, HttpServer};
use hornet::api::hello::{hello, manual_hello};
use hornet::api::prove::{prove, verify, witness, PolicyAuthorityState, ProofPipelineHandle};
use hornet::config::{DEFAULT_BLOCKLIST_PATH, DEFAULT_POLICY_LABEL};
use hornet::policy::extract::HttpHostExtractor;
use hornet::policy::plonk::{self, PlonkPolicy};
use hornet::policy::Blocklist;
use hornet::utils::encode_hex;

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
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

fn init_authority_state() -> io::Result<PolicyAuthorityState> {
    let mut state = PolicyAuthorityState::new();
    let (policy, policy_id, blocklist) = load_policy(DEFAULT_BLOCKLIST_PATH)?;
    plonk::register_policy(policy.clone());
    state.register_policy(policy, HttpHostExtractor::default(), blocklist);

    println!("registered policy {}", encode_hex(&policy_id));
    Ok(state)
}

fn load_policy(
    block_list_path: &str,
) -> io::Result<(Arc<PlonkPolicy>, hornet::policy::PolicyId, Blocklist)> {
    let json = fs::read_to_string(block_list_path)?;
    let blocklist = Blocklist::from_json(&json).map_err(|err| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("blocklist parse error: {err:?}"),
        )
    })?;
    let policy = Arc::new(
        PlonkPolicy::new_from_blocklist(DEFAULT_POLICY_LABEL, &blocklist).map_err(|err| {
            io::Error::new(ErrorKind::Other, format!("failed to build policy: {err:?}"))
        })?,
    );

    let policy_id = *policy.policy_id();
    Ok((policy, policy_id, blocklist))
}
