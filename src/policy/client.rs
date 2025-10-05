#![cfg(feature = "policy-client")]

use crate::policy::{PolicyCapsule, PolicyMetadata};
use crate::types::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct ProofRequest<'a> {
    pub policy: &'a PolicyMetadata,
    pub payload: &'a [u8],
    pub aux: &'a [u8],
}

pub trait ProofService {
    fn obtain_proof(&self, request: &ProofRequest<'_>) -> Result<PolicyCapsule>;
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

#[derive(Serialize)]
struct ProofServiceRequest {
    policy_id: String,
    payload_hex: String,
    aux_hex: String,
}

impl ProofServiceRequest {
    fn from_request(req: &ProofRequest<'_>) -> Self {
        Self {
            policy_id: hex::encode(&req.policy.policy_id),
            payload_hex: hex::encode(req.payload),
            aux_hex: hex::encode(req.aux),
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
            verifier_blob: vec![],
        };
        let req = ProofRequest {
            policy: &meta,
            payload: b"hello",
            aux: b"",
        };
        let body = ProofServiceRequest::from_request(&req);
        assert_eq!(body.policy_id.len(), 64);
        assert_eq!(body.payload_hex, "68656c6c6f");
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
}
