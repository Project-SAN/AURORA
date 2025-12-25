use actix_web::{get, http::StatusCode, post, web, HttpResponse, Responder, ResponseError};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::adapters::plonk::validator::PlonkCapsuleValidator;
use crate::application::prove::{ProofError, ProofPipeline as DomainProofPipeline, ProveInput};
use crate::policy::extract::{ExtractionError, Extractor};
use crate::policy::oprf;
use crate::policy::plonk::{self, PlonkPolicy};
use crate::policy::{Blocklist, PolicyCapsule, PolicyId, PolicyMetadata, PolicyRegistry};
use crate::types::Error as HornetError;
use crate::utils::{decode_hex, encode_hex, HexError};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

pub struct PolicyAuthorityState {
    policies: BTreeMap<PolicyId, PolicyAuthorityEntry>,
}

impl PolicyAuthorityState {
    pub fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
        }
    }

    pub fn register_policy<E>(
        &mut self,
        policy: Arc<PlonkPolicy>,
        extractor: E,
        oprf_key: Scalar,
        blocklist: Blocklist,
    ) -> PolicyId
    where
        E: Extractor + Send + Sync + 'static,
    {
        let entry = PolicyAuthorityEntry::new(policy, extractor, oprf_key, blocklist);
        let policy_id = entry.policy_id;
        self.policies.insert(policy_id, entry);
        policy_id
    }

    fn get(&self, policy_id: &PolicyId) -> Option<&PolicyAuthorityEntry> {
        self.policies.get(policy_id)
    }

    fn metadata(&self, policy_id: &PolicyId, expiry: u32, flags: u16) -> Option<PolicyMetadata> {
        self.policies
            .get(policy_id)
            .map(|entry| entry.metadata(expiry, flags))
    }
}

impl DomainProofPipeline for PolicyAuthorityState {
    fn prove(&self, request: ProveInput<'_>) -> Result<PolicyCapsule, ProofError> {
        let entry = self
            .get(&request.policy_id)
            .ok_or(ProofError::PolicyNotFound)?;
        entry.prove(request.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::blocklist::BlocklistEntry;
    use crate::policy::extract::HttpHostExtractor;
    use crate::policy::oprf;
    use crate::policy::{plonk, PolicyCapsule, PolicyRegistry};
    use crate::utils::decode_hex;
    use actix_web::{http::StatusCode, test, App};
    use alloc::vec;
    use alloc::vec::Vec;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::SmallRng;
    use rand::{RngCore, SeedableRng};

    fn demo_authority_state() -> (PolicyAuthorityState, PolicyId) {
        let blocklist_entries = vec![
            BlocklistEntry::Exact("blocked.example".into()).leaf_bytes(),
            BlocklistEntry::Exact("malicious.test".into()).leaf_bytes(),
        ];
        let blocklist = crate::policy::Blocklist::from_canonical_bytes(blocklist_entries);
        let oprf_key = oprf::derive_key_from_seed(b"test-oprf");
        let oprf_blocklist = oprf_blocklist_from(&blocklist, &oprf_key);
        let policy =
            Arc::new(PlonkPolicy::new_from_blocklist(b"test-policy", &oprf_blocklist).expect("policy"));
        plonk::register_policy(policy.clone());
        let mut state = PolicyAuthorityState::new();
        let policy_id =
            state.register_policy(policy, HttpHostExtractor::default(), oprf_key, oprf_blocklist);
        (state, policy_id)
    }

    fn oprf_blocklist_from(blocklist: &Blocklist, key: &Scalar) -> Blocklist {
        let mut leaves = Vec::with_capacity(blocklist.len());
        for entry in blocklist.entries() {
            let leaf = entry.leaf_bytes();
            let evaluated = oprf::eval_unblinded(key, &leaf);
            leaves.push(evaluated.to_vec());
        }
        Blocklist::from_canonical_bytes(leaves)
    }

    fn wrap_state_data(
        state: PolicyAuthorityState,
    ) -> (
        web::Data<PolicyAuthorityState>,
        web::Data<Arc<ProofPipelineHandle>>,
    ) {
        let directory = web::Data::new(state);
        let pipeline_arc: Arc<ProofPipelineHandle> = directory.clone().into_inner();
        let pipeline_data = web::Data::new(pipeline_arc);
        (directory, pipeline_data)
    }

    #[actix_web::test]
    async fn prove_endpoint_returns_capsule() {
        let (state, policy_id) = demo_authority_state();
        let (directory, pipeline_data) = wrap_state_data(state);
        let app = test::init_service(
            App::new()
                .app_data(directory.clone())
                .app_data(pipeline_data.clone())
                .service(prove),
        )
        .await;

        let payload = b"GET / HTTP/1.1\r\nHost: safe.example\r\n\r\n";
        let body = json!({
            "policy_id": encode_hex(&policy_id),
            "payload_hex": encode_hex(payload),
            "aux_hex": ""
        });

        let request = test::TestRequest::post()
            .uri("/prove")
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
        let (directory, pipeline_data) = wrap_state_data(state);
        let app = test::init_service(
            App::new()
                .app_data(directory.clone())
                .app_data(pipeline_data.clone())
                .service(prove),
        )
        .await;

        let payload = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
        let body = json!({
            "policy_id": encode_hex(&policy_id),
            "payload_hex": encode_hex(payload),
            "aux_hex": ""
        });

        let request = test::TestRequest::post()
            .uri("/prove")
            .set_json(body)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let payload: serde_json::Value = test::read_body_json(response).await;
        assert!(payload
            .get("error")
            .and_then(|value| value.as_str())
            .is_some());
    }

    #[actix_web::test]
    async fn user_obtains_capsule_and_router_verifies() {
        let (state, policy_id) = demo_authority_state();
        let policy = plonk::get_policy(&policy_id).expect("policy exists");
        let metadata = policy.metadata(600, 0);
        let mut registry = PolicyRegistry::new();
        registry.register(metadata).expect("register metadata");
        let validator = PlonkCapsuleValidator::new();

        let (directory, pipeline_data) = wrap_state_data(state);
        let app = test::init_service(
            App::new()
                .app_data(directory.clone())
                .app_data(pipeline_data.clone())
                .service(prove),
        )
        .await;

        let payload = b"GET / HTTP/1.1\r\nHost: safe.example\r\n\r\n";
        let body = json!({
            "policy_id": encode_hex(&policy_id),
            "payload_hex": encode_hex(payload),
            "aux_hex": ""
        });

        let request = test::TestRequest::post()
            .uri("/prove")
            .set_json(body)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let parsed: ProveResponse = test::read_body_json(response).await;
        let proof_bytes = decode_hex(parsed.proof_hex.as_str()).expect("proof hex decode");
        let commit_bytes = decode_hex(parsed.commitment_hex.as_str()).expect("commitment decode");
        let aux_bytes = if let Some(ref aux_hex) = parsed.aux_hex {
            decode_hex(aux_hex.as_str()).expect("aux decode")
        } else {
            vec![]
        };
        let capsule = PolicyCapsule {
            policy_id,
            version: parsed.version,
            proof: proof_bytes,
            commitment: commit_bytes,
            aux: aux_bytes,
        };

        let mut forward_payload = capsule.encode();
        let capsule_len = forward_payload.len();
        forward_payload.extend_from_slice(payload);

        let (verified_capsule, consumed) = registry
            .enforce(&mut forward_payload, &validator)
            .expect("registry enforce");
        assert_eq!(consumed, capsule_len);
        assert_eq!(verified_capsule, capsule);
        assert_eq!(&forward_payload[consumed..], payload);
    }

    #[actix_web::test]
    async fn user2router() {
        let (state, policy_id) = demo_authority_state();
        let policy = plonk::get_policy(&policy_id).expect("policy exists");
        let now_secs = 1_690_000_000u32;
        let exp = crate::types::Exp(now_secs.saturating_add(600));
        let metadata = policy.metadata(exp.0, 0);

        let mut registry = PolicyRegistry::new();
        registry.register(metadata).expect("register metadata");
        let validator = PlonkCapsuleValidator::new();
        let forward_pipeline = crate::application::forward::RegistryForwardPipeline::new();
        let (directory, pipeline_data) = wrap_state_data(state);
        let app = test::init_service(
            App::new()
                .app_data(directory.clone())
                .app_data(pipeline_data.clone())
                .service(prove),
        )
        .await;

        let payload = b"GET / HTTP/1.1\r\nHost: safe.example\r\n\r\n";
        let body = json!({
            "policy_id": encode_hex(&policy_id),
            "payload_hex": encode_hex(payload),
            "aux_hex": ""
        });

        let request = test::TestRequest::post()
            .uri("/prove")
            .set_json(body)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let parsed: ProveResponse = test::read_body_json(response).await;
        let proof_bytes = decode_hex(parsed.proof_hex.as_str()).expect("proof hex decode");
        let commit_bytes = decode_hex(parsed.commitment_hex.as_str()).expect("commitment decode");
        let aux_bytes = if let Some(ref aux_hex) = parsed.aux_hex {
            decode_hex(aux_hex.as_str()).expect("aux decode")
        } else {
            vec![]
        };
        let capsule = PolicyCapsule {
            policy_id,
            version: parsed.version,
            proof: proof_bytes,
            commitment: commit_bytes,
            aux: aux_bytes,
        };

        // Construct a single-hop packet for the router.
        let mut rng = SmallRng::seed_from_u64(0xA55A_5AA5);
        let mut sv_bytes = [0u8; 16];
        rng.fill_bytes(&mut sv_bytes);
        let sv = crate::types::Sv(sv_bytes);

        let mut si_bytes = [0u8; 16];
        rng.fill_bytes(&mut si_bytes);
        let si = crate::types::Si(si_bytes);

        let route = deliver_route();
        let fs = crate::packet::core::create(&sv, &si, &route, exp).expect("fs create");
        let mut rng_ahdr = SmallRng::seed_from_u64(0x1CEB_00DA);
        let ahdr =
            crate::packet::ahdr::create_ahdr(&[si], &[fs], crate::types::R_MAX, &mut rng_ahdr)
                .expect("create ahdr");
        let mut node_ahdr = crate::types::Ahdr {
            bytes: ahdr.bytes.clone(),
        };

        let mut nonce_bytes = [0u8; 16];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = crate::types::Nonce(nonce_bytes);
        let mut chdr = crate::packet::chdr::data_header(1, nonce);

        let message_plain = payload.to_vec();
        let mut encrypted_tail = message_plain.clone();
        let mut iv_for_build = nonce;
        crate::source::build(
            &mut chdr,
            &ahdr,
            &[si],
            &mut iv_for_build,
            &mut encrypted_tail,
        )
        .expect("build forward payload");

        let mut onwire_payload = encrypted_tail;
        capsule.prepend_to(&mut onwire_payload);

        // Router should forward the capsule followed by the decrypted plaintext payload.
        let mut expected_forward_payload = capsule.encode();
        expected_forward_payload.extend_from_slice(&message_plain);

        let mut forward = RecordingForward::new(expected_forward_payload);
        let mut replay = crate::node::NoReplay;
        let time = FixedTimeProvider { now: now_secs };

        let mut ctx = crate::node::NodeCtx {
            sv,
            now: &time,
            forward: &mut forward,
            replay: &mut replay,
            policy: Some(crate::node::PolicyRuntime {
                registry: &registry,
                validator: &validator,
                forward: &forward_pipeline,
                expected_policy_id: None,
            }),
        };

        crate::node::forward::process_data(
            &mut ctx,
            &mut chdr,
            &mut node_ahdr,
            &mut onwire_payload,
        )
        .expect("process forward data");

        assert!(forward.was_called());
        // Ensure payload forwarded in plaintext after capsule.
        let capsule_len = capsule.encode().len();
        assert_eq!(&onwire_payload[..4], b"ZKMB");
        assert_eq!(&onwire_payload[capsule_len..], message_plain.as_slice());
    }

    // Forward shim that records the payload forwarded by the node for assertions.
    struct RecordingForward {
        expected_payload: Vec<u8>,
        called: bool,
    }

    impl RecordingForward {
        fn new(expected_payload: Vec<u8>) -> Self {
            Self {
                expected_payload,
                called: false,
            }
        }

        fn was_called(&self) -> bool {
            self.called
        }
    }

    impl crate::forward::Forward for RecordingForward {
        fn send(
            &mut self,
            _rseg: &crate::types::RoutingSegment,
            chdr: &crate::types::Chdr,
            _ahdr: &crate::types::Ahdr,
            payload: &mut Vec<u8>,
            direction: crate::types::PacketDirection,
        ) -> crate::types::Result<()> {
            assert_eq!(chdr.hops, 1);
            assert!(matches!(direction, crate::types::PacketDirection::Forward));
            assert_eq!(payload.as_slice(), self.expected_payload.as_slice());
            self.called = true;
            Ok(())
        }
    }

    struct FixedTimeProvider {
        now: u32,
    }

    impl crate::time::TimeProvider for FixedTimeProvider {
        fn now_coarse(&self) -> u32 {
            self.now
        }
    }

    // Minimal routing segment representing local delivery for the final hop.
    fn deliver_route() -> crate::types::RoutingSegment {
        crate::types::RoutingSegment(vec![0xFF, 0x00])
    }
}

struct PolicyAuthorityEntry {
    policy_id: PolicyId,
    policy: Arc<PlonkPolicy>,
    extractor: Box<dyn Extractor + Send + Sync>,
    oprf_key: Scalar,
    blocklist: Blocklist,
}

impl PolicyAuthorityEntry {
    fn new<E>(
        policy: Arc<PlonkPolicy>,
        extractor: E,
        oprf_key: Scalar,
        blocklist: Blocklist,
    ) -> Self
    where
        E: Extractor + Send + Sync + 'static,
    {
        let policy_id = *policy.policy_id();
        Self {
            policy_id,
            policy,
            extractor: Box::new(extractor),
            oprf_key,
            blocklist,
        }
    }

    fn metadata(&self, expiry: u32, flags: u16) -> PolicyMetadata {
        self.policy.metadata(expiry, flags)
    }

    fn prove(&self, payload: &[u8]) -> Result<PolicyCapsule, ProofError> {
        let target = self
            .extractor
            .extract(payload)
            .map_err(ProofError::Extraction)?;
        let entry =
            crate::policy::blocklist::entry_from_target(&target).map_err(ProofError::Prover)?;
        let canonical_bytes = entry.leaf_bytes();
        let oprf_leaf = oprf::eval_unblinded(&self.oprf_key, &canonical_bytes);
        self.policy
            .prove_payload(&oprf_leaf)
            .map_err(ProofError::Prover)
    }

    fn witness_from_leaf(&self, leaf: Vec<u8>) -> Result<WitnessResponse, HornetError> {
        let leaves = self.blocklist.canonical_leaves();
        match leaves.binary_search(&leaf) {
            Ok(_) => Err(HornetError::PolicyViolation),
            Err(index) => {
                let left = if index > 0 {
                    self.blocklist
                        .merkle_proof(index - 1)
                        .map(MerkleProofResponse::from_proof)
                } else {
                    None
                };
                let right = if index < self.blocklist.len() {
                    self.blocklist
                        .merkle_proof(index)
                        .map(MerkleProofResponse::from_proof)
                } else {
                    None
                };
                let mut hasher = Sha256::new();
                hasher.update(&leaf);
                let digest = hasher.finalize();
                let mut target_hash = [0u8; 32];
                target_hash.copy_from_slice(&digest);
                Ok(WitnessResponse {
                    root_hex: encode_hex(&self.blocklist.merkle_root()),
                    target_leaf_hex: encode_hex(&leaf),
                    target_hash_hex: encode_hex(&target_hash),
                    gap_index: index as u64,
                    left,
                    right,
                })
            }
        }
    }

    fn evaluate_oprf(&self, blinded: [u8; 32]) -> Result<[u8; 32], HornetError> {
        oprf::eval_blinded(&self.oprf_key, &blinded).ok_or(HornetError::Crypto)
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

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub policy_id: String,
    pub capsule_hex: String,
    pub payload_hex: String,
    #[serde(default)]
    pub expiry: Option<u32>,
    #[serde(default)]
    pub flags: Option<u16>,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub commitment_hex: String,
}

#[derive(Serialize)]
pub struct PolicyBundleResponse {
    pub policy_id: String,
    pub prover_hex: String,
    pub block_hashes_hex: Vec<String>,
}

#[derive(Deserialize)]
pub struct WitnessRequest {
    pub policy_id: String,
    #[serde(default)]
    pub target_leaf_hex: Option<String>,
    #[serde(default)]
    pub target_hash_hex: Option<String>,
}

#[derive(Deserialize)]
pub struct OprfRequest {
    pub policy_id: String,
    pub blinded_hex: String,
}

#[derive(Serialize)]
pub struct OprfResponse {
    pub evaluated_hex: String,
}

#[derive(Serialize, Clone)]
pub struct MerkleProofResponse {
    pub index: u64,
    pub leaf_hex: String,
    pub leaf_hash_hex: String,
    pub siblings_hex: Vec<String>,
}

impl MerkleProofResponse {
    fn from_proof(proof: crate::policy::blocklist::MerkleProof) -> Self {
        Self {
            index: proof.index as u64,
            leaf_hex: encode_hex(&proof.leaf_bytes),
            leaf_hash_hex: encode_hex(&proof.leaf_hash),
            siblings_hex: proof.siblings.iter().map(|sib| encode_hex(sib)).collect(),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct WitnessResponse {
    pub root_hex: String,
    pub target_leaf_hex: String,
    pub target_hash_hex: String,
    pub gap_index: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left: Option<MerkleProofResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right: Option<MerkleProofResponse>,
}

#[post("/prove")]
pub async fn prove(
    pipeline: web::Data<Arc<ProofPipelineHandle>>,
    request: web::Json<ProveRequest>,
) -> Result<impl Responder, ApiError> {
    let policy_id = decode_policy_id(request.policy_id.as_str())?;
    let payload = decode_hex(request.payload_hex.as_str())?;
    let aux_bytes = if request.aux_hex.is_empty() {
        Vec::new()
    } else {
        decode_hex(request.aux_hex.as_str())?
    };
    let input = ProveInput {
        policy_id,
        payload: payload.as_slice(),
        aux: aux_bytes.as_slice(),
    };
    let capsule = pipeline
        .prove(input)
        .map_err(|err| ApiError::from_proof(err, request.policy_id.as_str()))?;

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

#[post("/verify")]
pub async fn verify(
    state: web::Data<PolicyAuthorityState>,
    request: web::Json<VerifyRequest>,
) -> Result<impl Responder, ApiError> {
    let policy_id = decode_policy_id(request.policy_id.as_str())?;
    let mut capsule_bytes = decode_hex(request.capsule_hex.as_str())?;
    let payload = decode_hex(request.payload_hex.as_str())?;

    let expiry = request.expiry.unwrap_or(600);
    let flags = request.flags.unwrap_or(0);
    let metadata = state
        .metadata(&policy_id, expiry, flags)
        .ok_or(ApiError::PolicyNotFound(request.policy_id.clone()))?;

    let mut registry = PolicyRegistry::new();
    registry.register(metadata).map_err(ApiError::from_prover)?;
    let validator = PlonkCapsuleValidator::new();

    let original_len = capsule_bytes.len();
    let (capsule, consumed) = registry
        .enforce(&mut capsule_bytes, &validator)
        .map_err(ApiError::from_prover)?;
    if consumed != original_len {
        return Err(ApiError::ProofFailure);
    }
    if capsule.policy_id != policy_id {
        return Err(ApiError::PolicyViolation);
    }

    let expected_commit = plonk::payload_commitment_bytes(&payload);
    if expected_commit != capsule.commitment {
        return Err(ApiError::PolicyViolation);
    }

    let response = VerifyResponse {
        valid: true,
        commitment_hex: encode_hex(&expected_commit),
    };
    Ok(web::Json(response))
}

#[get("/policy-bundle/{policy_id}")]
pub async fn policy_bundle(
    state: web::Data<PolicyAuthorityState>,
    path: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    let policy_id_hex = path.into_inner();
    let policy_id = decode_policy_id(policy_id_hex.as_str())?;
    let entry = state
        .get(&policy_id)
        .ok_or(ApiError::PolicyNotFound(policy_id_hex.clone()))?;
    let prover_hex = encode_hex(&entry.policy.prover_bytes());
    let block_hashes_hex = entry
        .policy
        .block_hashes_bytes()
        .into_iter()
        .map(|hash| encode_hex(&hash))
        .collect();
    let response = PolicyBundleResponse {
        policy_id: policy_id_hex,
        prover_hex,
        block_hashes_hex,
    };
    Ok(web::Json(response))
}

#[post("/witness")]
pub async fn witness(
    state: web::Data<PolicyAuthorityState>,
    request: web::Json<WitnessRequest>,
) -> Result<impl Responder, ApiError> {
    let policy_id = decode_policy_id(request.policy_id.as_str())?;
    let target_hex = request
        .target_hash_hex
        .as_deref()
        .or(request.target_leaf_hex.as_deref())
        .ok_or_else(|| ApiError::InvalidHex("missing target leaf".into()))?;
    let target_leaf = decode_hex(target_hex)?;
    let entry = state
        .get(&policy_id)
        .ok_or(ApiError::PolicyNotFound(request.policy_id.clone()))?;
    let response = entry
        .witness_from_leaf(target_leaf)
        .map_err(ApiError::from_prover)?;
    Ok(web::Json(response))
}

#[post("/oprf")]
pub async fn oprf_eval(
    state: web::Data<PolicyAuthorityState>,
    request: web::Json<OprfRequest>,
) -> Result<impl Responder, ApiError> {
    let policy_id = decode_policy_id(request.policy_id.as_str())?;
    let blinded = decode_hex(request.blinded_hex.as_str())?;
    if blinded.len() != 32 {
        return Err(ApiError::InvalidHex("blinded element must be 32 bytes".into()));
    }
    let mut blinded_bytes = [0u8; 32];
    blinded_bytes.copy_from_slice(&blinded);
    let entry = state
        .get(&policy_id)
        .ok_or(ApiError::PolicyNotFound(request.policy_id.clone()))?;
    let evaluated = entry
        .evaluate_oprf(blinded_bytes)
        .map_err(ApiError::from_prover)?;
    let response = OprfResponse {
        evaluated_hex: encode_hex(&evaluated),
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

    fn from_proof(err: ProofError, policy_ref: &str) -> Self {
        match err {
            ProofError::PolicyNotFound => ApiError::PolicyNotFound(policy_ref.to_string()),
            ProofError::Extraction(inner) => ApiError::from_extraction(inner),
            ProofError::Prover(inner) => ApiError::from_prover(inner),
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

impl From<HexError> for ApiError {
    fn from(err: HexError) -> Self {
        match err {
            HexError::OddLength => ApiError::InvalidHex("odd length".into()),
            HexError::InvalidChar(c) => ApiError::InvalidHex(format!("invalid hex char '{c}'")),
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
pub type ProofPipelineHandle = dyn DomainProofPipeline + Send + Sync + 'static;
