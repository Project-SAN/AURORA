use crate::policy::blocklist::{self, Blocklist, BlocklistEntry, MerkleProof};
use crate::policy::plonk::{self, PlonkPolicy};
use crate::policy::{Extractor, PolicyCapsule, PolicyMetadata, TargetValue, VerifierEntry};
use crate::core::policy::{ProofKind, ProofPart};
use crate::types::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
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

    fn obtain_batch(&self, requests: &[ProofRequest<'_>]) -> Result<Vec<PolicyCapsule>> {
        let mut out = Vec::with_capacity(requests.len());
        for request in requests {
            out.push(self.obtain_proof(request)?);
        }
        Ok(out)
    }

    fn precompute(&self, _request: &ProofRequest<'_>) -> Result<PrecomputeToken> {
        Err(Error::Crypto)
    }

    fn obtain_precomputed(&self, _token: &PrecomputeToken) -> Result<PolicyCapsule> {
        Err(Error::Crypto)
    }
}

#[derive(Clone, Debug)]
pub struct PrecomputeToken {
    pub policy_id: [u8; 32],
    pub token: String,
}

#[derive(Default)]
pub struct ProofCache {
    entries: BTreeMap<[u8; 32], PolicyCapsule>,
}

impl ProofCache {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, payload: &[u8], capsule: PolicyCapsule) {
        let key = payload_hash(payload);
        self.entries.insert(key, capsule);
    }

    pub fn get(&self, payload: &[u8]) -> Option<PolicyCapsule> {
        let key = payload_hash(payload);
        self.entries.get(&key).cloned()
    }
}

pub struct CachedProofService<S> {
    inner: S,
    cache: ProofCache,
}

impl<S> CachedProofService<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            cache: ProofCache::new(),
        }
    }

    pub fn precompute(&mut self, request: &ProofRequest<'_>) -> Result<()> 
    where
        S: ProofService,
    {
        let capsule = self.inner.obtain_proof(request)?;
        self.cache.insert(request.payload, capsule);
        Ok(())
    }
}

impl<S> ProofService for CachedProofService<S>
where
    S: ProofService,
{
    fn obtain_proof(&self, request: &ProofRequest<'_>) -> Result<PolicyCapsule> {
        if let Some(capsule) = self.cache.get(request.payload) {
            return Ok(capsule);
        }
        self.inner.obtain_proof(request)
    }

    fn obtain_batch(&self, requests: &[ProofRequest<'_>]) -> Result<Vec<PolicyCapsule>> {
        let mut out = Vec::with_capacity(requests.len());
        for request in requests {
            if let Some(capsule) = self.cache.get(request.payload) {
                out.push(capsule);
            } else {
                out.push(self.inner.obtain_proof(request)?);
            }
        }
        Ok(out)
    }
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

    fn endpoint_for(&self, suffix: &str) -> String {
        let trimmed = self.endpoint.trim_end_matches('/');
        if trimmed.ends_with("/prove") {
            let base = trimmed.trim_end_matches("/prove");
            format!("{base}/{suffix}")
        } else {
            format!("{trimmed}/{suffix}")
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

    fn obtain_batch(&self, requests: &[ProofRequest<'_>]) -> Result<Vec<PolicyCapsule>> {
        let items: Vec<ProofServiceRequest> = requests
            .iter()
            .map(ProofServiceRequest::from_request)
            .collect();
        let body = ProofServiceBatchRequest { items };
        let json = serde_json::to_string(&body).map_err(|_| Error::Crypto)?;
        let response = self
            .agent
            .post(self.endpoint_for("prove_batch").as_str())
            .set("content-type", "application/json")
            .send_string(&json)
            .map_err(|_| Error::Crypto)?;
        let parsed: ProofServiceBatchResponse = response.into_json().map_err(|_| Error::Crypto)?;
        if parsed.items.len() != requests.len() {
            return Err(Error::Crypto);
        }
        parsed
            .items
            .into_iter()
            .zip(requests.iter())
            .map(|(item, req)| item.into_capsule(&req.policy.policy_id))
            .collect()
    }

    fn precompute(&self, request: &ProofRequest<'_>) -> Result<PrecomputeToken> {
        let body = ProofServiceRequest::from_request(request);
        let json = serde_json::to_string(&body).map_err(|_| Error::Crypto)?;
        let response = self
            .agent
            .post(self.endpoint_for("precompute").as_str())
            .set("content-type", "application/json")
            .send_string(&json)
            .map_err(|_| Error::Crypto)?;
        let parsed: PrecomputeResponse = response.into_json().map_err(|_| Error::Crypto)?;
        Ok(PrecomputeToken {
            policy_id: request.policy.policy_id,
            token: parsed.precompute_id,
        })
    }

    fn obtain_precomputed(&self, token: &PrecomputeToken) -> Result<PolicyCapsule> {
        let body = ProvePrecomputedRequest {
            policy_id: hex::encode(&token.policy_id),
            precompute_id: token.token.clone(),
        };
        let json = serde_json::to_string(&body).map_err(|_| Error::Crypto)?;
        let response = self
            .agent
            .post(self.endpoint_for("prove_precomputed").as_str())
            .set("content-type", "application/json")
            .send_string(&json)
            .map_err(|_| Error::Crypto)?;
        let parsed: ProofServiceResponse = response.into_json().map_err(|_| Error::Crypto)?;
        parsed.into_capsule(&token.policy_id)
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
            policy_id: hex::encode(&req.policy.policy_id),
            payload_hex: hex::encode(req.payload),
            aux_hex: hex::encode(req.aux),
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
            target_leaf_hex: hex::encode(&witness.target_leaf),
            target_hash_hex: hex::encode(&witness.target_hash),
            root_hex: hex::encode(&witness.blocklist_root),
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
            leaf_hex: hex::encode(&proof.leaf_bytes),
            leaf_hash_hex: hex::encode(&proof.leaf_hash),
            siblings_hex: proof.siblings.iter().map(|sib| hex::encode(sib)).collect(),
        }
    }
}

#[derive(Deserialize)]
struct ProofServiceResponse {
    proof_hex: String,
    commitment_hex: String,
    aux_hex: Option<String>,
    version: Option<u8>,
}

#[derive(Serialize)]
struct ProofServiceBatchRequest {
    items: Vec<ProofServiceRequest>,
}

#[derive(Deserialize)]
struct ProofServiceBatchResponse {
    items: Vec<ProofServiceResponse>,
}

#[derive(Deserialize)]
struct PrecomputeResponse {
    precompute_id: String,
}

#[derive(Serialize)]
struct ProvePrecomputedRequest {
    policy_id: String,
    precompute_id: String,
}

impl ProofServiceResponse {
    fn into_capsule(self, policy_id: &[u8; 32]) -> Result<PolicyCapsule> {
        let proof = hex::decode(self.proof_hex).map_err(|_| Error::Crypto)?;
        let commitment = hex::decode(self.commitment_hex).map_err(|_| Error::Crypto)?;
        let aux = if let Some(aux_hex) = self.aux_hex {
            hex::decode(aux_hex).map_err(|_| Error::Crypto)?
        } else {
            Vec::new()
        };
        if proof.is_empty() || commitment.is_empty() {
            return Err(Error::Crypto);
        }
        let parts = vec![
            ProofPart {
                kind: ProofKind::KeyBinding,
                proof: proof.clone(),
                commitment: commitment.clone(),
                aux: aux.clone(),
            },
            ProofPart {
                kind: ProofKind::Consistency,
                proof: proof.clone(),
                commitment: commitment.clone(),
                aux: aux.clone(),
            },
            ProofPart {
                kind: ProofKind::Policy,
                proof,
                commitment,
                aux,
            },
        ];
        Ok(PolicyCapsule {
            policy_id: *policy_id,
            version: self.version.unwrap_or(1),
            parts,
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

fn payload_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

mod hex {
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt;

    pub fn encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(TABLE[(b >> 4) as usize] as char);
            out.push(TABLE[(b & 0x0f) as usize] as char);
        }
        out
    }

    pub fn decode(input: String) -> core::result::Result<Vec<u8>, HexError> {
        decode_str(input.as_str())
    }

    pub fn decode_str(input: &str) -> core::result::Result<Vec<u8>, HexError> {
        let mut buf = Vec::with_capacity(input.len() / 2);
        let mut chars = input.chars();
        while let Some(high) = chars.next() {
            let low = chars.next().ok_or(HexError::OddLength)?;
            let h = nibble(high)?;
            let l = nibble(low)?;
            buf.push((h << 4) | l);
        }
        Ok(buf)
    }

    fn nibble(c: char) -> core::result::Result<u8, HexError> {
        match c {
            '0'..='9' => Ok((c as u8) - b'0'),
            'a'..='f' => Ok((c as u8) - b'a' + 10),
            'A'..='F' => Ok((c as u8) - b'A' + 10),
            _ => Err(HexError::InvalidChar(c)),
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum HexError {
        OddLength,
        InvalidChar(char),
    }

    impl fmt::Display for HexError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                HexError::OddLength => write!(f, "odd length"),
                HexError::InvalidChar(c) => write!(f, "invalid char {c}"),
            }
        }
    }
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
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Policy as u8,
                verifier_blob: vec![],
            }],
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
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Policy as u8,
                verifier_blob: vec![],
            }],
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
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Policy as u8,
                verifier_blob: vec![],
            }],
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
        let part = cap
            .part(ProofKind::Policy)
            .expect("policy part");
        assert_eq!(part.proof, vec![0xAA, 0xBB]);
    }

    #[test]
    fn mock_service_runs() {
        let meta = PolicyMetadata {
            policy_id: [0x33; 32],
            version: 1,
            expiry: 0,
            flags: 0,
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Policy as u8,
                verifier_blob: vec![],
            }],
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
                parts: vec![ProofPart {
                    kind: ProofKind::Policy,
                    proof: vec![1, 2, 3],
                    commitment: vec![4, 5],
                    aux: vec![],
                }],
            })
        });
        let capsule = service.obtain_proof(&req).expect("capsule");
        let part = capsule
            .part(ProofKind::Policy)
            .expect("policy part");
        assert_eq!(part.proof, vec![1, 2, 3]);
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
