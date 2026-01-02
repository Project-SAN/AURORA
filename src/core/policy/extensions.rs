use alloc::vec::Vec;

use crate::types::{Error, Result};

const EXT_MAGIC: &[u8; 4] = b"ZEXT";
const EXT_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleExtension {
    Mode(u8),
    Sequence(u64),
    BatchId(u64),
    PrecomputeId(Vec<u8>),
    PrecomputeProof(Vec<u8>),
    PayloadHash([u8; 32]),
    PcdState([u8; 32]),
    PcdKeyHash([u8; 32]),
    PcdRoot([u8; 32]),
    PcdTargetHash([u8; 32]),
    PcdSeq(u64),
    PcdProof(Vec<u8>),
    SessionNonce([u8; 32]),
    RouteId([u8; 32]),
}

impl CapsuleExtension {
    fn tag(&self) -> u8 {
        match self {
            CapsuleExtension::Mode(_) => 1,
            CapsuleExtension::Sequence(_) => 2,
            CapsuleExtension::BatchId(_) => 3,
            CapsuleExtension::PrecomputeId(_) => 4,
            CapsuleExtension::PayloadHash(_) => 5,
            CapsuleExtension::PrecomputeProof(_) => 6,
            CapsuleExtension::PcdState(_) => 7,
            CapsuleExtension::PcdKeyHash(_) => 8,
            CapsuleExtension::PcdRoot(_) => 9,
            CapsuleExtension::PcdTargetHash(_) => 10,
            CapsuleExtension::PcdSeq(_) => 11,
            CapsuleExtension::PcdProof(_) => 12,
            CapsuleExtension::SessionNonce(_) => 13,
            CapsuleExtension::RouteId(_) => 14,
        }
    }
}

pub fn encode_extensions(exts: &[CapsuleExtension]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(EXT_MAGIC);
    out.push(EXT_VERSION);
    out.push(exts.len() as u8);
    for ext in exts {
        out.push(ext.tag());
        match ext {
            CapsuleExtension::Mode(mode) => {
                out.extend_from_slice(&1u16.to_be_bytes());
                out.push(*mode);
            }
            CapsuleExtension::Sequence(seq) => {
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
            }
            CapsuleExtension::BatchId(batch) => {
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&batch.to_be_bytes());
            }
            CapsuleExtension::PrecomputeId(id) => {
                let len = id.len().min(u16::MAX as usize) as u16;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&id[..len as usize]);
            }
            CapsuleExtension::PayloadHash(hash) => {
                out.extend_from_slice(&(hash.len() as u16).to_be_bytes());
                out.extend_from_slice(hash);
            }
            CapsuleExtension::PrecomputeProof(bytes) => {
                let len = bytes.len().min(u16::MAX as usize) as u16;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&bytes[..len as usize]);
            }
            CapsuleExtension::PcdState(state) => {
                out.extend_from_slice(&(state.len() as u16).to_be_bytes());
                out.extend_from_slice(state);
            }
            CapsuleExtension::PcdKeyHash(hash) => {
                out.extend_from_slice(&(hash.len() as u16).to_be_bytes());
                out.extend_from_slice(hash);
            }
            CapsuleExtension::PcdRoot(root) => {
                out.extend_from_slice(&(root.len() as u16).to_be_bytes());
                out.extend_from_slice(root);
            }
            CapsuleExtension::PcdTargetHash(hash) => {
                out.extend_from_slice(&(hash.len() as u16).to_be_bytes());
                out.extend_from_slice(hash);
            }
            CapsuleExtension::PcdSeq(seq) => {
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
            }
            CapsuleExtension::PcdProof(bytes) => {
                let len = bytes.len().min(u16::MAX as usize) as u16;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&bytes[..len as usize]);
            }
            CapsuleExtension::SessionNonce(nonce) => {
                out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
                out.extend_from_slice(nonce);
            }
            CapsuleExtension::RouteId(route) => {
                out.extend_from_slice(&(route.len() as u16).to_be_bytes());
                out.extend_from_slice(route);
            }
        }
    }
    out
}

pub fn decode_extensions(aux: &[u8]) -> Result<Option<Vec<CapsuleExtension>>> {
    if aux.len() < 6 || &aux[..4] != EXT_MAGIC {
        return Ok(None);
    }
    if aux[4] != EXT_VERSION {
        return Err(Error::Length);
    }
    let count = aux[5] as usize;
    let mut cursor = 6;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor + 3 > aux.len() {
            return Err(Error::Length);
        }
        let tag = aux[cursor];
        let len = u16::from_be_bytes([aux[cursor + 1], aux[cursor + 2]]) as usize;
        cursor += 3;
        if cursor + len > aux.len() {
            return Err(Error::Length);
        }
        let slice = &aux[cursor..cursor + len];
        cursor += len;
        let ext = match tag {
            1 => slice.first().map(|b| CapsuleExtension::Mode(*b)),
            2 if len == 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::Sequence(u64::from_be_bytes(buf)))
            }
            3 if len == 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::BatchId(u64::from_be_bytes(buf)))
            }
            4 => Some(CapsuleExtension::PrecomputeId(slice.to_vec())),
            5 if len == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::PayloadHash(buf))
            }
            6 => Some(CapsuleExtension::PrecomputeProof(slice.to_vec())),
            7 if len == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::PcdState(buf))
            }
            8 if len == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::PcdKeyHash(buf))
            }
            9 if len == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::PcdRoot(buf))
            }
            10 if len == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::PcdTargetHash(buf))
            }
            11 if len == 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::PcdSeq(u64::from_be_bytes(buf)))
            }
            12 => Some(CapsuleExtension::PcdProof(slice.to_vec())),
            13 if len == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::SessionNonce(buf))
            }
            14 if len == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(slice);
                Some(CapsuleExtension::RouteId(buf))
            }
            _ => None,
        };
        if let Some(ext) = ext {
            out.push(ext);
        }
    }
    Ok(Some(out))
}
