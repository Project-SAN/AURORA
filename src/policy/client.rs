use crate::policy::blocklist::{self, Blocklist, BlocklistEntry, MerkleProof};
use crate::policy::oprf;
use crate::policy::plonk::{self, PlonkPolicy};
use crate::policy::{Extractor, PolicyCapsule, PolicyMetadata, TargetValue};
use crate::types::{Error, Result};
use crate::utils::{decode_hex, encode_hex};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rand::rngs::SmallRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct ProofRequest<'a> {
    pub policy: &'a PolicyMetadata,
    pub payload: &'a [u8],
    pub aux: &'a [u8],
    pub non_membership: Option<NonMembershipWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipWitness {
    pub target_leaf: Vec<u8>,
    pub target_hash: [u8; 32],
    pub blocklist_root: [u8; 32],
    pub gap_index: usize,
    pub left: Option<MerkleProof>,
    pub right: Option<MerkleProof>,
}

impl NonMembershipWitness {
    pub fn from_canonical_leaf(blocklist: &Blocklist, leaf: Vec<u8>) -> Result<Self> {
        let leaves = blocklist.canonical_leaves();
        match leaves.binary_search(&leaf) {
            Ok(_) => Err(Error::PolicyViolation),
            Err(index) => {
                let blocklist_root = blocklist.merkle_root();
                let left = if index > 0 {
                    blocklist.merkle_proof(index - 1)
                } else {
                    None
                };
                let right = if index < blocklist.len() {
                    blocklist.merkle_proof(index)
                } else {
                    None
                };
                let mut hasher = Sha256::new();
                hasher.update(&leaf);
                let digest = hasher.finalize();
                let mut target_hash = [0u8; 32];
                target_hash.copy_from_slice(&digest);
                Ok(Self {
                    target_leaf: leaf,
                    target_hash,
                    blocklist_root,
                    gap_index: index,
                    left,
                    right,
                })
            }
        }
    }

    pub fn from_entry(blocklist: &Blocklist, entry: &BlocklistEntry) -> Result<Self> {
        Self::from_canonical_leaf(blocklist, entry.leaf_bytes())
    }

    pub fn from_target(blocklist: &Blocklist, target: &TargetValue) -> Result<Self> {
        let entry = blocklist::entry_from_target(target)?;
        Self::from_entry(blocklist, &entry)
    }
}

pub struct ProofPreprocessor<E> {
    extractor: E,
    blocklist: Arc<Blocklist>,
    fail_open: bool,
}

impl<E> ProofPreprocessor<E>
where
    E: Extractor,
{
    pub fn new(extractor: E, blocklist: Blocklist) -> Self {
        Self {
            extractor,
            blocklist: Arc::new(blocklist),
            fail_open: false,
        }
    }

    pub fn with_shared_blocklist(extractor: E, blocklist: Arc<Blocklist>) -> Self {
        Self {
            extractor,
            blocklist,
            fail_open: false,
        }
    }

    pub fn fail_open(mut self, enabled: bool) -> Self {
        self.fail_open = enabled;
        self
    }

    pub fn prepare<'a>(
        &self,
        policy: &'a PolicyMetadata,
        payload: &'a [u8],
        aux: &'a [u8],
    ) -> Result<ProofRequest<'a>> {
        let target = self
            .extractor
            .extract(payload)
            .map_err(|_| Error::PolicyViolation)?;
        match NonMembershipWitness::from_target(&self.blocklist, &target) {
            Ok(witness) => Ok(ProofRequest {
                policy,
                payload,
                aux,
                non_membership: Some(witness),
            }),
            Err(err) if self.fail_open => {
                let _ = err;
                Ok(ProofRequest {
                    policy,
                    payload,
                    aux,
                    non_membership: None,
                })
            }
            Err(err) => Err(err),
        }
    }

    pub fn blocklist(&self) -> &Blocklist {
        &self.blocklist
    }

    pub fn extractor(&self) -> &E {
        &self.extractor
    }
}

pub trait ProofService {
    fn obtain_proof(&self, request: &ProofRequest<'_>) -> Result<PolicyCapsule>;
}

pub trait WitnessService {
    fn obtain_witness(
        &self,
        policy_id: &[u8; 32],
        target_leaf: &[u8],
    ) -> Result<NonMembershipWitness>;
}

#[derive(Clone, Debug)]
pub struct HttpProofService {
    endpoint: String,
    agent: ureq::Agent,
}

impl HttpProofService {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new().build();
        Self {
            endpoint: endpoint.into(),
            agent,
        }
    }

    pub fn obtain_with_preprocessor<E>(
        &self,
        preprocessor: &ProofPreprocessor<E>,
        policy: &PolicyMetadata,
        payload: &[u8],
        aux: &[u8],
    ) -> Result<PolicyCapsule>
    where
        E: Extractor,
    {
        let request = preprocessor.prepare(policy, payload, aux)?;
        self.obtain_proof(&request)
    }
}

impl ProofService for HttpProofService {
    fn obtain_proof(&self, request: &ProofRequest<'_>) -> Result<PolicyCapsule> {
        let body = ProofServiceRequest::from_request(request);
        let json = serde_json::to_string(&body).map_err(|_| Error::Crypto)?;
        let response = self
            .agent
            .post(self.endpoint.as_str())
            .set("content-type", "application/json")
            .send_string(&json)
            .map_err(|_| Error::Crypto)?;
        let parsed: ProofServiceResponse = response.into_json().map_err(|_| Error::Crypto)?;
        parsed.into_capsule(&request.policy.policy_id)
    }
}

#[derive(Clone, Debug)]
pub struct HttpWitnessService {
    endpoint: String,
    agent: ureq::Agent,
}

impl HttpWitnessService {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new().build();
        Self {
            endpoint: endpoint.into(),
            agent,
        }
    }
}

impl WitnessService for HttpWitnessService {
    fn obtain_witness(
        &self,
        policy_id: &[u8; 32],
        target_leaf: &[u8],
    ) -> Result<NonMembershipWitness> {
        let body = WitnessRequest {
            policy_id: encode_hex(policy_id),
            target_leaf_hex: Some(encode_hex(target_leaf)),
            target_hash_hex: None,
        };
        let json = serde_json::to_string(&body).map_err(|_| Error::Crypto)?;
        let response = self
            .agent
            .post(self.endpoint.as_str())
            .set("content-type", "application/json")
            .send_string(&json)
            .map_err(|_| Error::Crypto)?;
        let parsed: WitnessResponse = response.into_json().map_err(|_| Error::Crypto)?;
        parsed.into_witness()
    }
}

#[derive(Clone, Debug)]
pub struct OprfWitnessService {
    oprf_endpoint: String,
    witness_endpoint: String,
    agent: ureq::Agent,
}

impl OprfWitnessService {
    pub fn new(oprf_endpoint: impl Into<String>, witness_endpoint: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new().build();
        Self {
            oprf_endpoint: oprf_endpoint.into(),
            witness_endpoint: witness_endpoint.into(),
            agent,
        }
    }
}

impl WitnessService for OprfWitnessService {
    fn obtain_witness(
        &self,
        policy_id: &[u8; 32],
        target_leaf: &[u8],
    ) -> Result<NonMembershipWitness> {
        let mut rng = SmallRng::from_seed(oprf_seed(policy_id, target_leaf));
        let (blind, blinded) = oprf::blind(target_leaf, &mut rng);
        let oprf_body = OprfRequest {
            policy_id: encode_hex(policy_id),
            blinded_hex: encode_hex(&blinded),
        };
        let oprf_json = serde_json::to_string(&oprf_body).map_err(|_| Error::Crypto)?;
        let response = self
            .agent
            .post(self.oprf_endpoint.as_str())
            .set("content-type", "application/json")
            .send_string(&oprf_json)
            .map_err(|_| Error::Crypto)?;
        let parsed: OprfResponse = response.into_json().map_err(|_| Error::Crypto)?;
        let evaluated = decode_fixed_32(&parsed.evaluated_hex)?;
        let unblinded = oprf::unblind(&blind, &evaluated).ok_or(Error::Crypto)?;

        let witness_body = WitnessRequest {
            policy_id: encode_hex(policy_id),
            target_leaf_hex: None,
            target_hash_hex: Some(encode_hex(&unblinded)),
        };
        let witness_json = serde_json::to_string(&witness_body).map_err(|_| Error::Crypto)?;
        let response = self
            .agent
            .post(self.witness_endpoint.as_str())
            .set("content-type", "application/json")
            .send_string(&witness_json)
            .map_err(|_| Error::Crypto)?;
        let parsed: WitnessResponse = response.into_json().map_err(|_| Error::Crypto)?;
        parsed.into_witness()
    }
}

#[derive(Serialize)]
struct ProofServiceRequest {
    policy_id: String,
    payload_hex: String,
    aux_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    non_membership: Option<NonMembershipRequest>,
}

impl ProofServiceRequest {
    fn from_request(req: &ProofRequest<'_>) -> Self {
        let non_membership = req
            .non_membership
            .as_ref()
            .map(NonMembershipRequest::from_witness);
        Self {
            policy_id: encode_hex(&req.policy.policy_id),
            payload_hex: encode_hex(req.payload),
            aux_hex: encode_hex(req.aux),
            non_membership,
        }
    }
}

#[derive(Serialize)]
struct NonMembershipRequest {
    target_leaf_hex: String,
    target_hash_hex: String,
    root_hex: String,
    gap_index: u64,
    left: Option<MerkleProofRequest>,
    right: Option<MerkleProofRequest>,
}

impl NonMembershipRequest {
    fn from_witness(witness: &NonMembershipWitness) -> Self {
        Self {
            target_leaf_hex: encode_hex(&witness.target_leaf),
            target_hash_hex: encode_hex(&witness.target_hash),
            root_hex: encode_hex(&witness.blocklist_root),
            gap_index: witness.gap_index as u64,
            left: witness.left.as_ref().map(MerkleProofRequest::from_proof),
            right: witness.right.as_ref().map(MerkleProofRequest::from_proof),
        }
    }
}

#[derive(Serialize)]
struct MerkleProofRequest {
    index: u64,
    leaf_hex: String,
    leaf_hash_hex: String,
    siblings_hex: Vec<String>,
}

impl MerkleProofRequest {
    fn from_proof(proof: &MerkleProof) -> Self {
        Self {
            index: proof.index as u64,
            leaf_hex: encode_hex(&proof.leaf_bytes),
            leaf_hash_hex: encode_hex(&proof.leaf_hash),
            siblings_hex: proof.siblings.iter().map(|sib| encode_hex(sib)).collect(),
        }
    }
}

#[derive(Serialize)]
struct WitnessRequest {
    policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_leaf_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_hash_hex: Option<String>,
}

#[derive(Serialize)]
struct OprfRequest {
    policy_id: String,
    blinded_hex: String,
}

#[derive(Deserialize)]
struct OprfResponse {
    evaluated_hex: String,
}

#[derive(Deserialize)]
struct WitnessResponse {
    root_hex: String,
    target_leaf_hex: String,
    target_hash_hex: String,
    gap_index: u64,
    left: Option<MerkleProofResponse>,
    right: Option<MerkleProofResponse>,
}

impl WitnessResponse {
    fn into_witness(self) -> Result<NonMembershipWitness> {
        let target_leaf = decode_hex_bytes(&self.target_leaf_hex)?;
        let target_hash = decode_fixed_32(&self.target_hash_hex)?;
        let blocklist_root = decode_fixed_32(&self.root_hex)?;
        let left = self.left.map(MerkleProofResponse::into_proof).transpose()?;
        let right = self
            .right
            .map(MerkleProofResponse::into_proof)
            .transpose()?;
        Ok(NonMembershipWitness {
            target_leaf,
            target_hash,
            blocklist_root,
            gap_index: self.gap_index as usize,
            left,
            right,
        })
    }
}

#[derive(Deserialize)]
struct MerkleProofResponse {
    index: u64,
    leaf_hex: String,
    leaf_hash_hex: String,
    siblings_hex: Vec<String>,
}

impl MerkleProofResponse {
    fn into_proof(self) -> Result<MerkleProof> {
        let leaf_bytes = decode_hex_bytes(&self.leaf_hex)?;
        let leaf_hash = decode_fixed_32(&self.leaf_hash_hex)?;
        let mut siblings = Vec::with_capacity(self.siblings_hex.len());
        for sib_hex in self.siblings_hex {
            siblings.push(decode_fixed_32(&sib_hex)?);
        }
        Ok(MerkleProof {
            index: self.index as usize,
            leaf_bytes,
            leaf_hash,
            siblings,
        })
    }
}

#[derive(Deserialize)]
struct ProofServiceResponse {
    proof_hex: String,
    commitment_hex: String,
    aux_hex: Option<String>,
    version: Option<u8>,
}

impl ProofServiceResponse {
    fn into_capsule(self, policy_id: &[u8; 32]) -> Result<PolicyCapsule> {
        let proof = decode_hex_bytes(&self.proof_hex)?;
        let commitment = decode_hex_bytes(&self.commitment_hex)?;
        let aux = if let Some(aux_hex) = self.aux_hex {
            decode_hex_bytes(&aux_hex)?
        } else {
            Vec::new()
        };
        if proof.is_empty() || commitment.is_empty() {
            return Err(Error::Crypto);
        }
        Ok(PolicyCapsule {
            policy_id: *policy_id,
            version: self.version.unwrap_or(1),
            proof,
            commitment,
            aux,
        })
    }
}

pub struct MockProofService<F>
where
    F: Fn(&ProofRequest<'_>) -> Result<PolicyCapsule>,
{
    handler: F,
}

impl<F> MockProofService<F>
where
    F: Fn(&ProofRequest<'_>) -> Result<PolicyCapsule>,
{
    pub fn new(handler: F) -> Self {
        Self { handler }
    }
}

impl<F> ProofService for MockProofService<F>
where
    F: Fn(&ProofRequest<'_>) -> Result<PolicyCapsule>,
{
    fn obtain_proof(&self, request: &ProofRequest<'_>) -> Result<PolicyCapsule> {
        (self.handler)(request)
    }
}

pub struct PlonkProofService<E: Extractor + Send + Sync + 'static> {
    extractor: E,
    policy: Arc<PlonkPolicy>,
}

impl<E: Extractor + Send + Sync + 'static> PlonkProofService<E> {
    pub fn new(label: &[u8], blocklist: Vec<Vec<u8>>, extractor: E) -> Result<Self> {
        let policy = Arc::new(
            PlonkPolicy::new_with_blocklist(label, &blocklist).map_err(|_| Error::Crypto)?,
        );
        plonk::register_policy(policy.clone());
        Ok(Self { extractor, policy })
    }

    pub fn policy_metadata(&self, expiry: u32, flags: u16) -> PolicyMetadata {
        self.policy.metadata(expiry, flags)
    }
}

impl<E: Extractor + Send + Sync + 'static> ProofService for PlonkProofService<E> {
    fn obtain_proof(&self, request: &ProofRequest<'_>) -> Result<PolicyCapsule> {
        let target = self
            .extractor
            .extract(request.payload)
            .map_err(|_| Error::PolicyViolation)?;
        let entry = blocklist::entry_from_target(&target)?;
        let bytes = entry.leaf_bytes();
        self.policy.prove_payload(&bytes)
    }
}

pub struct WitnessPreprocessor<E, W> {
    extractor: E,
    witness: W,
    fail_open: bool,
}

impl<E, W> WitnessPreprocessor<E, W>
where
    E: Extractor,
    W: WitnessService,
{
    pub fn new(extractor: E, witness: W) -> Self {
        Self {
            extractor,
            witness,
            fail_open: false,
        }
    }

    pub fn fail_open(mut self, enabled: bool) -> Self {
        self.fail_open = enabled;
        self
    }

    pub fn prepare<'a>(
        &self,
        policy: &'a PolicyMetadata,
        payload: &'a [u8],
        aux: &'a [u8],
    ) -> Result<ProofRequest<'a>> {
        let target = self
            .extractor
            .extract(payload)
            .map_err(|_| Error::PolicyViolation)?;
        let entry = blocklist::entry_from_target(&target)?;
        let leaf = entry.leaf_bytes();
        match self.witness.obtain_witness(&policy.policy_id, &leaf) {
            Ok(witness) => Ok(ProofRequest {
                policy,
                payload,
                aux,
                non_membership: Some(witness),
            }),
            Err(err) if self.fail_open => {
                let _ = err;
                Ok(ProofRequest {
                    policy,
                    payload,
                    aux,
                    non_membership: None,
                })
            }
            Err(err) => Err(err),
        }
    }
}

fn decode_fixed_32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex_bytes(hex_str)?;
    if bytes.len() != 32 {
        return Err(Error::Crypto);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_bytes(hex_str: &str) -> Result<Vec<u8>> {
    decode_hex(hex_str).map_err(|_| Error::Crypto)
}

fn oprf_seed(policy_id: &[u8; 32], target_leaf: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"oprf-blind");
    hasher.update(policy_id);
    hasher.update(target_leaf);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn proof_request_serialises() {
        let meta = PolicyMetadata {
            policy_id: [0x11; 32],
            version: 1,
            expiry: 42,
            flags: 0,
            verifier_blob: vec![],
        };
        let req = ProofRequest {
            policy: &meta,
            payload: b"hello",
            aux: b"",
            non_membership: None,
        };
        let body = ProofServiceRequest::from_request(&req);
        assert_eq!(body.policy_id.len(), 64);
        assert_eq!(body.payload_hex, "68656c6c6f");
        assert!(body.non_membership.is_none());
    }

    #[test]
    fn non_membership_witness_serialises() {
        let meta = PolicyMetadata {
            policy_id: [0x77; 32],
            version: 1,
            expiry: 100,
            flags: 0,
            verifier_blob: vec![],
        };
        let blocklist = Blocklist::from_canonical_bytes(vec![b"aaa".to_vec(), b"ccc".to_vec()]);
        let witness = NonMembershipWitness::from_canonical_leaf(&blocklist, b"bbb".to_vec())
            .expect("witness");
        let req = ProofRequest {
            policy: &meta,
            payload: b"payload",
            aux: b"",
            non_membership: Some(witness),
        };
        let body = ProofServiceRequest::from_request(&req);
        assert!(body.non_membership.is_some());
        let json = serde_json::to_string(&body).expect("json");
        assert!(json.contains("non_membership"));
    }

    #[test]
    fn preprocessor_attaches_witness() {
        use crate::policy::extract::HttpHostExtractor;

        let meta = PolicyMetadata {
            policy_id: [0x12; 32],
            version: 1,
            expiry: 0,
            flags: 0,
            verifier_blob: vec![],
        };
        let blocked_leaf =
            crate::policy::blocklist::BlocklistEntry::Exact("blocked.example".into()).leaf_bytes();
        let blocklist = Blocklist::from_canonical_bytes(vec![blocked_leaf]);
        let preprocessor = ProofPreprocessor::new(HttpHostExtractor::default(), blocklist);
        let payload = b"GET / HTTP/1.1\r\nHost: safe.example\r\n\r\n";
        let request = preprocessor.prepare(&meta, payload, b"").expect("prepared");
        let witness = request.non_membership.as_ref().expect("witness present");
        assert_eq!(witness.blocklist_root.len(), 32);
        assert_eq!(witness.target_leaf[0], 0x01); // TAG_EXACT from blocklist encoding
    }

    #[test]
    fn witness_from_ipv4_target() {
        let blocklist = Blocklist::new(vec![
            BlocklistEntry::Range {
                start: vec![0, 0, 0, 0],
                end: vec![10, 0, 0, 0],
            },
            BlocklistEntry::Range {
                start: vec![192, 168, 0, 0],
                end: vec![192, 168, 255, 255],
            },
        ]);
        let target = TargetValue::Ipv4([11, 0, 0, 1]);
        let witness = NonMembershipWitness::from_target(&blocklist, &target).expect("ipv4 witness");
        assert_eq!(witness.target_leaf[0], 0x04); // TAG_RANGE from blocklist encoding
    }

    #[test]
    fn response_to_capsule() {
        let resp = ProofServiceResponse {
            proof_hex: "aabb".into(),
            commitment_hex: "ccdd".into(),
            aux_hex: None,
            version: Some(7),
        };
        let cap = resp.into_capsule(&[0x44; 32]).expect("capsule");
        assert_eq!(cap.version, 7);
        assert_eq!(cap.policy_id, [0x44; 32]);
        assert_eq!(cap.proof, vec![0xAA, 0xBB]);
    }

    #[test]
    fn mock_service_runs() {
        let meta = PolicyMetadata {
            policy_id: [0x33; 32],
            version: 1,
            expiry: 0,
            flags: 0,
            verifier_blob: vec![],
        };
        let req = ProofRequest {
            policy: &meta,
            payload: b"data",
            aux: b"aux",
            non_membership: None,
        };
        let service = MockProofService::new(|_| {
            Ok(PolicyCapsule {
                policy_id: [0x33; 32],
                version: 1,
                proof: vec![1, 2, 3],
                commitment: vec![4, 5],
                aux: vec![],
            })
        });
        let capsule = service.obtain_proof(&req).expect("capsule");
        assert_eq!(capsule.proof, vec![1, 2, 3]);
    }

    #[test]
    fn plonk_service_generates_proof() {
        use crate::policy::extract::HttpHostExtractor;
        let blocked_leaf =
            crate::policy::blocklist::BlocklistEntry::Exact("blocked.example".into()).leaf_bytes();
        let blocklist = vec![blocked_leaf];
        let service = PlonkProofService::new(b"test", blocklist, HttpHostExtractor::default())
            .expect("plonk service");
        let metadata = service.policy_metadata(42, 0);
        let payload = b"GET / HTTP/1.1\r\nHost: safe.example\r\n\r\n";
        let request = ProofRequest {
            policy: &metadata,
            payload,
            aux: &[],
            non_membership: None,
        };
        let capsule = service.obtain_proof(&request).expect("capsule");
        assert_eq!(capsule.policy_id, metadata.policy_id);
    }
}
