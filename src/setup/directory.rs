use crate::policy::{decode_metadata_tlv, encode_metadata_tlv, PolicyId, PolicyMetadata};
use crate::routing::{self, RouteElem};
use crate::types::{Error, Result, RoutingSegment};
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use core::net::{Ipv4Addr, Ipv6Addr};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct DirectoryAnnouncement {
    policy_entries: Vec<PolicyMetadata>,
    route_entries: Vec<RouteAnnouncement>,
    hop_policies: Vec<HopPolicyAnnouncement>,
}

impl DirectoryAnnouncement {
    pub fn new() -> Self {
        Self {
            policy_entries: Vec::new(),
            route_entries: Vec::new(),
            hop_policies: Vec::new(),
        }
    }

    pub fn with_policy(meta: PolicyMetadata) -> Self {
        Self {
            policy_entries: vec![meta],
            route_entries: Vec::new(),
            hop_policies: Vec::new(),
        }
    }

    pub fn push_policy(&mut self, meta: PolicyMetadata) {
        self.policy_entries.push(meta);
    }

    pub fn policies(&self) -> &[PolicyMetadata] {
        &self.policy_entries
    }

    pub fn routes(&self) -> &[RouteAnnouncement] {
        &self.route_entries
    }

    pub fn hop_policy_for(&self, interface: &str) -> Option<PolicyId> {
        self.hop_policies
            .iter()
            .find(|entry| entry.interface == interface)
            .map(|entry| entry.policy_id)
    }

    pub fn hop_policies(&self) -> &[HopPolicyAnnouncement] {
        &self.hop_policies
    }

    pub fn push_hop_policy(&mut self, interface: impl Into<String>, policy_id: PolicyId) {
        self.hop_policies.push(HopPolicyAnnouncement {
            interface: interface.into(),
            policy_id,
        });
    }

    pub fn push_route(&mut self, route: RouteAnnouncement) {
        self.route_entries.push(route);
    }

    pub fn to_tlvs(&self) -> Vec<Vec<u8>> {
        self.policy_entries
            .iter()
            .map(encode_metadata_tlv)
            .collect()
    }

    pub fn from_tlvs(tlvs: &[Vec<u8>]) -> Result<Self> {
        let mut metas = Vec::new();
        for tlv in tlvs {
            if tlv.first().copied() == Some(crate::policy::POLICY_METADATA_TLV) {
                metas.push(decode_metadata_tlv(tlv)?);
            }
        }
        Ok(Self {
            policy_entries: metas,
            route_entries: Vec::new(),
            hop_policies: Vec::new(),
        })
    }
}

impl Default for DirectoryAnnouncement {
    fn default() -> Self {
        Self::new()
    }
}

pub fn apply_to_source_state(
    state: &mut crate::setup::SourceSetupState,
    directory: &DirectoryAnnouncement,
) {
    for policy in &directory.policy_entries {
        state.attach_policy_metadata(policy);
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct DirectoryMessage {
    version: u8,
    issued_at: u64,
    policies: Vec<PolicyMetadata>,
    #[serde(default)]
    hop_policies: Vec<HopPolicyMessage>,
    #[serde(default)]
    routes: Vec<RouteMessage>,
    signature: String,
}

pub fn to_signed_json(
    announcement: &DirectoryAnnouncement,
    secret: &[u8],
    issued_at: u64,
) -> Result<String> {
    let unsigned = DirectoryMessage {
        version: 1,
        issued_at,
        policies: announcement.policy_entries.clone(),
        hop_policies: announcement
            .hop_policies
            .iter()
            .map(HopPolicyMessage::from_announcement)
            .collect::<Result<Vec<_>>>()?,
        routes: announcement
            .route_entries
            .iter()
            .map(RouteMessage::from_announcement)
            .collect::<Result<Vec<_>>>()?,
        signature: String::new(),
    };
    let serialized = serde_json::to_string(&unsigned).map_err(|_| Error::Crypto)?;
    let signature = hex_encode(&compute_hmac(secret, serialized.as_bytes()));
    let signed = DirectoryMessage {
        signature,
        ..unsigned
    };
    serde_json::to_string(&signed).map_err(|_| Error::Crypto)
}

pub fn from_signed_json(body: &str, secret: &[u8]) -> Result<DirectoryAnnouncement> {
    let signed: DirectoryMessage = serde_json::from_str(body).map_err(|_| Error::Crypto)?;
    let expected_sig = signed.signature.clone();
    let unsigned = DirectoryMessage {
        signature: String::new(),
        ..signed.clone()
    };
    let serialized = serde_json::to_string(&unsigned).map_err(|_| Error::Crypto)?;
    if !verify_hmac(secret, serialized.as_bytes(), &expected_sig) {
        return Err(Error::Crypto);
    }
    let routes = signed
        .routes
        .iter()
        .map(RouteMessage::to_announcement)
        .collect::<Result<Vec<_>>>()?;
    let hop_policies = signed
        .hop_policies
        .iter()
        .map(HopPolicyMessage::to_announcement)
        .collect::<Result<Vec<_>>>()?;
    Ok(DirectoryAnnouncement {
        policy_entries: signed.policies,
        route_entries: routes,
        hop_policies,
    })
}

#[derive(Clone)]
pub struct RouteAnnouncement {
    pub policy_id: PolicyId,
    pub segment: RoutingSegment,
    pub interface: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct RouteMessage {
    policy_id: String,
    #[serde(default)]
    interface: Option<String>,
    segments: Vec<RouteElemMessage>,
}

impl RouteMessage {
    fn from_announcement(route: &RouteAnnouncement) -> Result<Self> {
        let elems = routing::elems_from_segment(&route.segment).map_err(|_| Error::Length)?;
        let segments = elems
            .into_iter()
            .map(RouteElemMessage::from_route_elem)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            policy_id: hex_encode(&route.policy_id),
            interface: route.interface.clone(),
            segments,
        })
    }

    fn to_announcement(&self) -> Result<RouteAnnouncement> {
        let policy_id = hex_decode(&self.policy_id)?;
        if policy_id.len() != 32 {
            return Err(Error::Length);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&policy_id);
        let elems = self
            .segments
            .iter()
            .map(RouteElemMessage::to_route_elem)
            .collect::<Result<Vec<_>>>()?;
        Ok(RouteAnnouncement {
            policy_id: id,
            segment: routing::segment_from_elems(&elems),
            interface: self.interface.clone(),
        })
    }
}

#[derive(Clone)]
pub struct HopPolicyAnnouncement {
    pub interface: String,
    pub policy_id: PolicyId,
}

#[derive(Serialize, Deserialize, Clone)]
struct HopPolicyMessage {
    interface: String,
    policy_id: String,
}

impl HopPolicyMessage {
    fn from_announcement(entry: &HopPolicyAnnouncement) -> Result<Self> {
        Ok(Self {
            interface: entry.interface.clone(),
            policy_id: hex_encode(&entry.policy_id),
        })
    }

    fn to_announcement(&self) -> Result<HopPolicyAnnouncement> {
        let policy_id = hex_decode(&self.policy_id)?;
        if policy_id.len() != 32 {
            return Err(Error::Length);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&policy_id);
        Ok(HopPolicyAnnouncement {
            interface: self.interface.clone(),
            policy_id: id,
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RouteElemMessage {
    NextHop4 {
        ip: String,
        port: u16,
    },
    NextHop6 {
        ip: String,
        port: u16,
    },
    ExitTcp4 {
        ip: String,
        port: u16,
        #[serde(default)]
        tls: bool,
    },
    ExitTcp6 {
        ip: String,
        port: u16,
        #[serde(default)]
        tls: bool,
    },
}

impl RouteElemMessage {
    fn from_route_elem(elem: RouteElem) -> Result<Self> {
        match elem {
            RouteElem::NextHop {
                addr: routing::IpAddr::V4(ip),
                port,
            } => Ok(RouteElemMessage::NextHop4 {
                ip: Ipv4Addr::from(ip).to_string(),
                port,
            }),
            RouteElem::NextHop {
                addr: routing::IpAddr::V6(ip),
                port,
            } => Ok(RouteElemMessage::NextHop6 {
                ip: Ipv6Addr::from(ip).to_string(),
                port,
            }),
            RouteElem::ExitTcp {
                addr: routing::IpAddr::V4(ip),
                port,
                tls,
            } => Ok(RouteElemMessage::ExitTcp4 {
                ip: Ipv4Addr::from(ip).to_string(),
                port,
                tls,
            }),
            RouteElem::ExitTcp {
                addr: routing::IpAddr::V6(ip),
                port,
                tls,
            } => Ok(RouteElemMessage::ExitTcp6 {
                ip: Ipv6Addr::from(ip).to_string(),
                port,
                tls,
            }),
        }
    }

    fn to_route_elem(&self) -> Result<RouteElem> {
        match self {
            RouteElemMessage::NextHop4 { ip, port } => {
                let addr = parse_ipv4(ip)?;
                Ok(RouteElem::NextHop {
                    addr: routing::IpAddr::V4(addr.octets()),
                    port: *port,
                })
            }
            RouteElemMessage::NextHop6 { ip, port } => {
                let addr = parse_ipv6(ip)?;
                Ok(RouteElem::NextHop {
                    addr: routing::IpAddr::V6(addr.octets()),
                    port: *port,
                })
            }
            RouteElemMessage::ExitTcp4 { ip, port, tls } => {
                let addr = parse_ipv4(ip)?;
                Ok(RouteElem::ExitTcp {
                    addr: routing::IpAddr::V4(addr.octets()),
                    port: *port,
                    tls: *tls,
                })
            }
            RouteElemMessage::ExitTcp6 { ip, port, tls } => {
                let addr = parse_ipv6(ip)?;
                Ok(RouteElem::ExitTcp {
                    addr: routing::IpAddr::V6(addr.octets()),
                    port: *port,
                    tls: *tls,
                })
            }
        }
    }
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    input.parse().map_err(|_| Error::Length)
}

fn parse_ipv6(input: &str) -> Result<Ipv6Addr> {
    input.parse().map_err(|_| Error::Length)
}

fn compute_hmac(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac(secret: &[u8], data: &[u8], signature: &str) -> bool {
    if let Ok(expected) = hex_decode(signature) {
        if let Ok(mut mac) = HmacSha256::new_from_slice(secret) {
            mac.update(data);
            return mac.verify_slice(&expected).is_ok();
        }
    }
    false
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(input: &str) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut chars = input.chars();
    while let Some(high) = chars.next() {
        let low = chars.next().ok_or(Error::Length)?;
        let h = decode_nibble(high)?;
        let l = decode_nibble(low)?;
        out.push((h << 4) | l);
    }
    Ok(out)
}

fn decode_nibble(c: char) -> Result<u8> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        'a'..='f' => Ok((c as u8) - b'a' + 10),
        'A'..='F' => Ok((c as u8) - b'A' + 10),
        _ => Err(Error::Crypto),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_directory_tlvs() {
        let meta = PolicyMetadata {
            policy_id: [0xAA; 32],
            version: 1,
            expiry: 123,
            flags: 0,
            verifier_blob: vec![0x10, 0x20],
        };
        let directory = DirectoryAnnouncement::with_policy(meta.clone());
        let tlvs = directory.to_tlvs();
        assert_eq!(tlvs.len(), 1);
        let parsed = DirectoryAnnouncement::from_tlvs(&tlvs).expect("directory");
        assert_eq!(parsed.policies().len(), 1);
        assert_eq!(parsed.policies()[0], meta);
    }

    #[test]
    fn announcement_signed_roundtrip() {
        let meta = PolicyMetadata {
            policy_id: [0x01; 32],
            version: 1,
            expiry: 99,
            flags: 0,
            verifier_blob: vec![0xAA],
        };
        let directory = DirectoryAnnouncement::with_policy(meta.clone());
        let secret = b"directory-shared-secret";
        let body = to_signed_json(&directory, secret, 1234).expect("signed json");
        let parsed = from_signed_json(&body, secret).expect("verify");
        assert_eq!(parsed.policies()[0], meta);
        assert!(from_signed_json(&body, b"wrong").is_err());
    }

    #[test]
    fn announcement_with_routes_roundtrip() {
        let meta = PolicyMetadata {
            policy_id: [0x10; 32],
            version: 1,
            expiry: 42,
            flags: 0,
            verifier_blob: vec![0x01, 0x02],
        };
        let route_elem = RouteElem::NextHop {
            addr: routing::IpAddr::V4([192, 0, 2, 1]),
            port: 30000,
        };
        let segment = routing::segment_from_elems(&[route_elem]);
        let mut directory = DirectoryAnnouncement::with_policy(meta.clone());
        directory.push_route(RouteAnnouncement {
            policy_id: meta.policy_id,
            segment: segment.clone(),
            interface: Some("wan0".to_string()),
        });
        let secret = b"route-secret";
        let body = to_signed_json(&directory, secret, 123).expect("sign");
        let parsed = from_signed_json(&body, secret).expect("verify");
        assert_eq!(parsed.policies()[0], meta);
        assert_eq!(parsed.routes().len(), 1);
        let first = &parsed.routes()[0];
        assert_eq!(first.policy_id, meta.policy_id);
        assert_eq!(
            routing::elems_from_segment(&first.segment).unwrap().len(),
            1
        );
        assert_eq!(first.interface.as_deref(), Some("wan0"));
    }

    #[test]
    fn announcement_with_hop_policies_roundtrip() {
        let meta = PolicyMetadata {
            policy_id: [0x20; 32],
            version: 1,
            expiry: 77,
            flags: 0,
            verifier_blob: vec![0xEE],
        };
        let mut directory = DirectoryAnnouncement::with_policy(meta.clone());
        directory.push_hop_policy("router-entry", [0xA1; 32]);
        directory.push_hop_policy("router-middle", [0xB2; 32]);
        let secret = b"hop-secret";
        let body = to_signed_json(&directory, secret, 55).expect("sign");
        let parsed = from_signed_json(&body, secret).expect("verify");
        assert_eq!(parsed.policies()[0], meta);
        assert_eq!(
            parsed.hop_policy_for("router-entry"),
            Some([0xA1; 32])
        );
        assert_eq!(
            parsed.hop_policy_for("router-middle"),
            Some([0xB2; 32])
        );
    }
}
