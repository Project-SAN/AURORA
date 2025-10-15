use actix_web::{HttpResponse, Responder, ResponseError, http::StatusCode, post, web};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::policy::extract::{ExtractionError, Extractor};
use crate::policy::plonk::PlonkPolicy;
use crate::policy::{PolicyCapsule, PolicyId};
use crate::types::Error as HornetError;

pub struct PolicyAuthorityState {
    policies: BTreeMap<PolicyId, PolicyAuthorityEntry>,
}

impl PolicyAuthorityState {
    pub fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
        }
    }

    pub fn register_policy<E>(&mut self, policy: Arc<PlonkPolicy>, extractor: E) -> PolicyId
    where
        E: Extractor + Send + Sync + 'static,
    {
        let entry = PolicyAuthorityEntry::new(policy, extractor);
        let policy_id = entry.policy_id;
        self.policies.insert(policy_id, entry);
        policy_id
    }

    fn get(&self, policy_id: &PolicyId) -> Option<&PolicyAuthorityEntry> {
        self.policies.get(policy_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::extract::HttpHostExtractor;
    use crate::policy::plonk;
    use actix_web::{App, http::StatusCode, test};
    use alloc::vec;

    fn demo_authority_state() -> (PolicyAuthorityState, PolicyId) {
        let blocklist = vec![b"blocked.example".to_vec(), b"malicious.test".to_vec()];
        let policy =
            Arc::new(PlonkPolicy::new_with_blocklist(b"test-policy", &blocklist).expect("policy"));
        plonk::register_policy(policy.clone());
        let mut state = PolicyAuthorityState::new();
        let policy_id = state.register_policy(policy, HttpHostExtractor::default());
        (state, policy_id)
    }

    #[actix_web::test]
    async fn prove_endpoint_returns_capsule() {
        let (state, policy_id) = demo_authority_state();
        let data = web::Data::new(state);
        let app = test::init_service(App::new().app_data(data.clone()).service(prove)).await;

        let payload = b"GET / HTTP/1.1\r\nHost: safe.example\r\n\r\n";
        let body = json!({
            "policy_id": encode_hex(&policy_id),
            "payload_hex": encode_hex(payload),
            "aux_hex": ""
        });

        let request = test::TestRequest::post()
            .uri("/plonk/prove")
            .set_json(body)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: ProveResponse = test::read_body_json(response).await;
        assert_eq!(parsed.version, 1);
        assert!(!parsed.proof_hex.is_empty());
        assert!(!parsed.commitment_hex.is_empty());
    }

    #[actix_web::test]
    async fn prove_endpoint_rejects_blocklisted_target() {
        let (state, policy_id) = demo_authority_state();
        let data = web::Data::new(state);
        let app = test::init_service(App::new().app_data(data.clone()).service(prove)).await;

        let payload = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
        let body = json!({
            "policy_id": encode_hex(&policy_id),
            "payload_hex": encode_hex(payload),
            "aux_hex": ""
        });

        let request = test::TestRequest::post()
            .uri("/plonk/prove")
            .set_json(body)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let payload: serde_json::Value = test::read_body_json(response).await;
        assert!(
            payload
                .get("error")
                .and_then(|value| value.as_str())
                .is_some()
        );
    }
}

struct PolicyAuthorityEntry {
    policy_id: PolicyId,
    policy: Arc<PlonkPolicy>,
    extractor: Box<dyn Extractor + Send + Sync>,
}

impl PolicyAuthorityEntry {
    fn new<E>(policy: Arc<PlonkPolicy>, extractor: E) -> Self
    where
        E: Extractor + Send + Sync + 'static,
    {
        let policy_id = *policy.policy_id();
        Self {
            policy_id,
            policy,
            extractor: Box::new(extractor),
        }
    }

    fn prove(&self, payload: &[u8]) -> Result<PolicyCapsule, ApiError> {
        let target = self
            .extractor
            .extract(payload)
            .map_err(ApiError::from_extraction)?;
        let target_bytes = target.as_bytes();
        self.policy
            .prove_payload(&target_bytes)
            .map_err(ApiError::from_prover)
    }
}

#[derive(Deserialize)]
pub struct ProveRequest {
    pub policy_id: String,
    pub payload_hex: String,
    #[serde(default)]
    pub aux_hex: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProveResponse {
    pub proof_hex: String,
    pub commitment_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aux_hex: Option<String>,
    pub version: u8,
}

#[post("/plonk/prove")]
pub async fn prove(
    state: web::Data<PolicyAuthorityState>,
    request: web::Json<ProveRequest>,
) -> Result<impl Responder, ApiError> {
    let policy_id = decode_policy_id(request.policy_id.as_str())?;
    let payload = decode_hex(request.payload_hex.as_str())?;

    let entry = state
        .get(&policy_id)
        .ok_or(ApiError::PolicyNotFound(request.policy_id.clone()))?;
    let capsule = entry.prove(&payload)?;

    // Optional aux passthrough: if caller supplied aux data, echo it back when proof is empty.
    let aux = if !capsule.aux.is_empty() {
        Some(encode_hex(&capsule.aux))
    } else if !request.aux_hex.is_empty() {
        Some(request.aux_hex.clone())
    } else {
        None
    };

    let response = ProveResponse {
        proof_hex: encode_hex(&capsule.proof),
        commitment_hex: encode_hex(&capsule.commitment),
        aux_hex: aux,
        version: capsule.version,
    };

    Ok(web::Json(response))
}

fn decode_policy_id(hex: &str) -> Result<PolicyId, ApiError> {
    let bytes = decode_hex(hex)?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidPolicyId(hex.to_string()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ApiError> {
    if input.len() % 2 != 0 {
        return Err(ApiError::InvalidHex("odd length".into()));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut chars = input.chars();
    while let Some(high) = chars.next() {
        let low = chars
            .next()
            .ok_or_else(|| ApiError::InvalidHex("odd length".into()))?;
        let hi = nibble(high).map_err(ApiError::InvalidHex)?;
        let lo = nibble(low).map_err(ApiError::InvalidHex)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(c: char) -> Result<u8, String> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        'a'..='f' => Ok((c as u8) - b'a' + 10),
        'A'..='F' => Ok((c as u8) - b'A' + 10),
        _ => Err(format!("invalid hex char '{c}'")),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0F) as usize] as char);
    }
    out
}

#[derive(Debug)]
pub enum ApiError {
    InvalidHex(String),
    InvalidPolicyId(String),
    PolicyNotFound(String),
    PayloadExtraction(String),
    PolicyViolation,
    ProofFailure,
}

impl ApiError {
    fn from_extraction(err: ExtractionError) -> Self {
        ApiError::PayloadExtraction(format!("{err:?}"))
    }

    fn from_prover(err: HornetError) -> Self {
        match err {
            HornetError::PolicyViolation => ApiError::PolicyViolation,
            _ => ApiError::ProofFailure,
        }
    }

    fn message(&self) -> String {
        match self {
            ApiError::InvalidHex(msg) => format!("invalid hex input: {msg}"),
            ApiError::InvalidPolicyId(id) => format!("invalid policy_id length: {id}"),
            ApiError::PolicyNotFound(id) => format!("policy_id not found: {id}"),
            ApiError::PayloadExtraction(msg) => format!("unable to extract payload target: {msg}"),
            ApiError::PolicyViolation => "requested payload violates policy".into(),
            ApiError::ProofFailure => "failed to produce zero-knowledge proof".into(),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::InvalidHex(_)
            | ApiError::InvalidPolicyId(_)
            | ApiError::PayloadExtraction(_) => StatusCode::BAD_REQUEST,
            ApiError::PolicyNotFound(_) => StatusCode::NOT_FOUND,
            ApiError::PolicyViolation => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::ProofFailure => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let body = json!({ "error": self.message() });
        HttpResponse::build(self.status_code()).json(body)
    }
}
