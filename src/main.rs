use std::fs;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use actix_web::{web, App, HttpServer};
use hornet::api::hello::{hello, manual_hello};
use hornet::api::prove::{prove, PolicyAuthorityState};
use hornet::policy::extract::HttpHostExtractor;
use hornet::policy::plonk::{self, PlonkPolicy};
use hornet::policy::Blocklist;
use hornet::utils::encode_hex;

const BLOCKLIST_PATH: &str = "config/blocklist.json";
const POLICY_LABEL: &[u8] = b"default-blocklist-policy";

#[actix_web::main]
async fn main() -> io::Result<()> {
    let authority_state = web::Data::new(init_authority_state()?);
    HttpServer::new(move || {
        App::new()
            .app_data(authority_state.clone())
            .service(hello)
            .service(prove)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

fn init_authority_state() -> io::Result<PolicyAuthorityState> {
    let mut state = PolicyAuthorityState::new();
    let (policy, policy_id) = load_policy(BLOCKLIST_PATH)?;
    plonk::register_policy(policy.clone());
    state.register_policy(policy, HttpHostExtractor::default());
    
    println!("registered policy {}", encode_hex(&policy_id));
    Ok(state)
}

fn load_policy(block_list_path: &str) -> io::Result<(Arc<PlonkPolicy>, hornet::policy::PolicyId)> {
    let json = fs::read_to_string(block_list_path)?;
    let blocklist =
        Blocklist::from_json(&json).map_err(|err| io::Error::new(ErrorKind::InvalidData, format!("blocklist parse error: {err:?}")))?;
    let policy = Arc::new(
        PlonkPolicy::new_from_blocklist(POLICY_LABEL, &blocklist)
            .map_err(|err| io::Error::new(ErrorKind::Other, format!("failed to build policy: {err:?}")))?,
    );

    let policy_id = *policy.policy_id();
    Ok((policy, policy_id))
}