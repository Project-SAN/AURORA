//! Wire encoding/decoding for HORNET packets in no_std + alloc.
//! Format (version 1):
//!
//! [0]      : u8   version (=1)
//! [1]      : u8   packet_type (0x01 Setup, 0x02 Data)
//! [2]      : u8   hops
//! [3]      : u8   reserved (=0)
//! [4..20]  : 16B  chdr.specific (EXP for Setup, Nonce/IV for Data)
//! [20..24] : u32  ahdr_len (big-endian)
//! [24..28] : u32  payload_len (big-endian)
//! [28..]   : optional POLICY section || ahdr bytes || payload bytes
//!
//! The caller is responsible for validating semantic sizes (e.g., AHDR length
//! matches r*c) at a higher layer. This module only enforces basic length checks.

use crate::policy::encoder::{self, PolicySection};
use crate::types::{Ahdr, Chdr, Error, PacketType, Result};
use alloc::vec::Vec;

pub const WIRE_VERSION: u8 = 1;
const FIXED_HDR_LEN: usize = 28; // bytes before AHDR and payload

fn pkt_type_to_u8(t: PacketType) -> u8 {
    match t {
        PacketType::Setup => 0x01,
        PacketType::Data => 0x02,
    }
}

fn pkt_type_from_u8(b: u8) -> core::result::Result<PacketType, Error> {
    match b {
        0x01 => Ok(PacketType::Setup),
        0x02 => Ok(PacketType::Data),
        _ => Err(Error::Length),
    }
}

fn be_u32(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}
fn read_be_u32(b: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(b);
    u32::from_be_bytes(tmp)
}

pub fn encode(
    chdr: &Chdr,
    policy: Option<&PolicySection>,
    ahdr: &Ahdr,
    payload: &[u8],
) -> Vec<u8> {
    let ah_len = ahdr.bytes.len();
    let pl_len = payload.len();
    let policy_bytes = policy.map(encoder::encode);
    let policy_len = policy_bytes.as_ref().map(|b| b.len()).unwrap_or(0);
    let mut out = Vec::with_capacity(FIXED_HDR_LEN + policy_len + ah_len + pl_len);
    out.push(WIRE_VERSION);
    out.push(pkt_type_to_u8(chdr.typ));
    out.push(chdr.hops);
    out.push(0u8); // reserved
    out.extend_from_slice(&chdr.specific);
    out.extend_from_slice(&be_u32(ah_len as u32));
    out.extend_from_slice(&be_u32(pl_len as u32));
    if let Some(policy_buf) = policy_bytes {
        out.extend_from_slice(&policy_buf);
    }
    out.extend_from_slice(&ahdr.bytes);
    out.extend_from_slice(payload);
    out
}

pub fn decode(buf: &[u8]) -> Result<(Chdr, Option<PolicySection>, Ahdr, Vec<u8>)> {
    if buf.len() < FIXED_HDR_LEN {
        return Err(Error::Length);
    }
    if buf[0] != WIRE_VERSION {
        return Err(Error::Length);
    }
    let typ = pkt_type_from_u8(buf[1])?;
    let hops = buf[2];
    let _reserved = buf[3];
    let mut specific = [0u8; 16];
    specific.copy_from_slice(&buf[4..20]);
    let ah_len = read_be_u32(&buf[20..24]) as usize;
    let pl_len = read_be_u32(&buf[24..28]) as usize;
    let remaining = buf.len() - FIXED_HDR_LEN;
    if remaining < ah_len + pl_len {
        return Err(Error::Length);
    }
    let policy_region_len = remaining - (ah_len + pl_len);
    let mut cursor = FIXED_HDR_LEN;
    let policy = if policy_region_len > 0 {
        if policy_region_len < 2 {
            return Err(Error::Length);
        }
        let end = cursor + policy_region_len;
        let section = encoder::decode(&buf[cursor..end]).map_err(|_| Error::Length)?;
        cursor = end;
        Some(section)
    } else {
        None
    };

    let ah_end = cursor + ah_len;
    let pl_end = ah_end + pl_len;

    if pl_end > buf.len() {
        return Err(Error::Length);
    }

    let ah_bytes = &buf[cursor..ah_end];
    let pl_bytes = &buf[ah_end..pl_end];
    let chdr = Chdr {
        typ,
        hops,
        specific,
    };
    let ahdr = Ahdr {
        bytes: Vec::from(ah_bytes),
    };
    let payload = Vec::from(pl_bytes);
    Ok((chdr, policy, ahdr, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Nonce;

    #[test]
    fn roundtrip_data_packet() {
        let ch = Chdr {
            typ: PacketType::Data,
            hops: 3,
            specific: Nonce([1u8; 16]).0,
        };
        let ah = Ahdr {
            bytes: alloc::vec![0xAA; 96],
        };
        let payload = alloc::vec![0x55; 80];
        let encoded = encode(&ch, None, &ah, &payload);
        let (ch2, policy, ah2, pl2) = decode(&encoded).expect("decode");
        assert!(policy.is_none());
        assert!(matches!(ch2.typ, PacketType::Data));
        assert_eq!(ch2.hops, 3);
        assert_eq!(ch2.specific, ch.specific);
        assert_eq!(ah2.bytes, ah.bytes);
        assert_eq!(pl2, payload);
    }

    #[test]
    fn reject_bad_version_or_length() {
        let mut buf = alloc::vec![0u8; FIXED_HDR_LEN - 1];
        assert!(decode(&buf).is_err());
        buf.resize(FIXED_HDR_LEN, 0);
        // set version to 2 -> error
        buf[0] = 2;
        buf[1] = 0x02; // type data
        assert!(decode(&buf).is_err());
        // minimal correct header but inconsistent lengths
        buf[0] = WIRE_VERSION;
        buf[1] = 0x02;
        buf[2] = 1;
        buf[3] = 0;
        // specific already zeros
        buf[20..24].copy_from_slice(&1u32.to_be_bytes());
        buf[24..28].copy_from_slice(&1u32.to_be_bytes());
        // missing body
        assert!(decode(&buf).is_err());
    }

    #[test]
    fn policy_section_roundtrip() {
        let ch = Chdr {
            typ: PacketType::Data,
            hops: 1,
            specific: Nonce([0u8; 16]).0,
        };
        let ah = Ahdr {
            bytes: alloc::vec![0xBB; 64],
        };
        let payload = alloc::vec![0xCC; 40];

        let section = crate::policy::encoder::PolicySection::new(
            0x01,
            42,
            10,
            0,
            [1u8; 32],
            [2u8; 32],
            [3u8; 48],
            [4u8; crate::policy::encoder::PROOF_LEN],
        );

        let encoded = encode(&ch, Some(&section), &ah, &payload);
        let (_ch2, policy, ah2, pl2) = decode(&encoded).expect("decode");
        let decoded_section = policy.expect("policy section");
        assert_eq!(decoded_section.policy_id, 42);
        assert_eq!(decoded_section.c_token, [2u8; 32]);
        assert_eq!(decoded_section.c_req, [3u8; 48]);
        assert_eq!(ah2.bytes, ah.bytes);
        assert_eq!(pl2, payload);
    }
}
