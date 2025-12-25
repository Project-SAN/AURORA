//! Wire encoding/decoding for HORNET packets in no_std + alloc.
//! Format (version 1):
//!
//! [0]      : u8   version (=1)
//! [1]      : u8   packet_type (0x01 Setup, 0x02 Data, 0x03 Reject)
//! [2]      : u8   hops
//! [3]      : u8   reserved (=0)
//! [4..20]  : 16B  chdr.specific (EXP for Setup, Nonce/IV for Data)
//! [20..24] : u32  ahdr_len (big-endian)
//! [24..28] : u32  payload_len (big-endian)
//! [28..]   : ahdr bytes || payload bytes
//!
//! The caller is responsible for validating semantic sizes (e.g., AHDR length
//! matches r*c) at a higher layer. This module only enforces basic length checks.

use crate::types::{Ahdr, Chdr, Error, PacketType, Result};
use alloc::vec::Vec;

pub const WIRE_VERSION: u8 = 1;
const FIXED_HDR_LEN: usize = 28; // bytes before AHDR and payload

fn pkt_type_to_u8(t: PacketType) -> u8 {
    match t {
        PacketType::Setup => 0x01,
        PacketType::Data => 0x02,
        PacketType::Reject => 0x03,
    }
}

fn pkt_type_from_u8(b: u8) -> core::result::Result<PacketType, Error> {
    match b {
        0x01 => Ok(PacketType::Setup),
        0x02 => Ok(PacketType::Data),
        0x03 => Ok(PacketType::Reject),
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

pub fn encode(chdr: &Chdr, ahdr: &Ahdr, payload: &[u8]) -> Vec<u8> {
    let ah_len = ahdr.bytes.len();
    let pl_len = payload.len();
    let mut out = Vec::with_capacity(FIXED_HDR_LEN + ah_len + pl_len);
    out.push(WIRE_VERSION);
    out.push(pkt_type_to_u8(chdr.typ));
    out.push(chdr.hops);
    out.push(0u8); // reserved
    out.extend_from_slice(&chdr.specific);
    out.extend_from_slice(&be_u32(ah_len as u32));
    out.extend_from_slice(&be_u32(pl_len as u32));
    out.extend_from_slice(&ahdr.bytes);
    out.extend_from_slice(payload);
    out
}

pub fn decode(buf: &[u8]) -> Result<(Chdr, Ahdr, Vec<u8>)> {
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
    let need = FIXED_HDR_LEN + ah_len + pl_len;
    if buf.len() < need {
        return Err(Error::Length);
    }
    let ah_bytes = &buf[FIXED_HDR_LEN..FIXED_HDR_LEN + ah_len];
    let pl_bytes = &buf[FIXED_HDR_LEN + ah_len..need];
    let chdr = Chdr {
        typ,
        hops,
        specific,
    };
    let ahdr = Ahdr {
        bytes: Vec::from(ah_bytes),
    };
    let payload = Vec::from(pl_bytes);
    Ok((chdr, ahdr, payload))
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
        let encoded = encode(&ch, &ah, &payload);
        let (ch2, ah2, pl2) = decode(&encoded).expect("decode");
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
}
