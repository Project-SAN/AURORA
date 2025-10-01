//! Minimal fragmentation utilities for no_std + alloc.
//!
//! This module prepends a tiny 8-byte header to each fragment:
//! - msg_id: u32 (big-endian)
//! - index : u16 (big-endian) 0..total-1
//! - total : u16 (big-endian) total number of fragments (>=1)
//!
//! Caller chooses a per-path `cap` (maximum on-wire payload) and a `msg_id`.
//! The produced fragment payloads are suitable to place directly into `wire::encode`'s payload.

use crate::types::{Error, Result};
use alloc::vec::Vec;

pub const HDR_LEN: usize = 8;

fn be_u16(x: u16) -> [u8; 2] {
    x.to_be_bytes()
}
fn be_u32(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}
fn read_be_u16(b: &[u8]) -> u16 {
    let mut t = [0u8; 2];
    t.copy_from_slice(b);
    u16::from_be_bytes(t)
}
fn read_be_u32(b: &[u8]) -> u32 {
    let mut t = [0u8; 4];
    t.copy_from_slice(b);
    u32::from_be_bytes(t)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragHeader {
    pub msg_id: u32,
    pub index: u16,
    pub total: u16,
}

impl FragHeader {
    pub fn encode(&self, out: &mut [u8; HDR_LEN]) {
        out[0..4].copy_from_slice(&be_u32(self.msg_id));
        out[4..6].copy_from_slice(&be_u16(self.index));
        out[6..8].copy_from_slice(&be_u16(self.total));
    }
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < HDR_LEN {
            return Err(Error::Length);
        }
        let msg_id = read_be_u32(&buf[0..4]);
        let index = read_be_u16(&buf[4..6]);
        let total = read_be_u16(&buf[6..8]);
        if total == 0 || index as u32 >= total as u32 {
            return Err(Error::Length);
        }
        Ok((
            FragHeader {
                msg_id,
                index,
                total,
            },
            &buf[HDR_LEN..],
        ))
    }
}

/// Split message into fragments with header, each fragment length <= cap.
/// cap must be > HDR_LEN.
pub fn split(msg: &[u8], cap: usize, msg_id: u32) -> Result<Vec<Vec<u8>>> {
    if cap <= HDR_LEN {
        return Err(Error::Length);
    }
    let chunk = cap - HDR_LEN;
    let total = msg.len().div_ceil(chunk).max(1) as u16;
    let mut out = Vec::with_capacity(total as usize);
    for i in 0..(total as usize) {
        let start = i * chunk;
        let end = core::cmp::min(start + chunk, msg.len());
        let mut frag = Vec::with_capacity(HDR_LEN + (end - start));
        let hdr = FragHeader {
            msg_id,
            index: i as u16,
            total,
        };
        let mut hdr_bytes = [0u8; HDR_LEN];
        hdr.encode(&mut hdr_bytes);
        frag.extend_from_slice(&hdr_bytes);
        frag.extend_from_slice(&msg[start..end]);
        out.push(frag);
    }
    Ok(out)
}

/// Minimal in-flight reassembler keyed by `msg_id`, storing up to `capacity` entries.
pub struct Reassembler {
    entries: alloc::vec::Vec<Entry>,
    capacity: usize,
}

struct Entry {
    msg_id: u32,
    total: u16,
    chunks: alloc::vec::Vec<Option<Vec<u8>>>,
}

impl Reassembler {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity,
        }
    }

    /// Accept a fragment (with header) and return the reassembled message when complete.
    pub fn accept(&mut self, frag: &[u8]) -> Result<Option<Vec<u8>>> {
        let (hdr, body) = FragHeader::decode(frag)?;
        // find or create entry
        let mut idx = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.msg_id == hdr.msg_id {
                idx = Some(i);
                break;
            }
        }
        if idx.is_none() {
            // evict if full (naive: drop first)
            if self.entries.len() >= self.capacity {
                self.entries.remove(0);
            }
            let mut chunks = Vec::with_capacity(hdr.total as usize);
            chunks.resize(hdr.total as usize, None);
            self.entries.push(Entry {
                msg_id: hdr.msg_id,
                total: hdr.total,
                chunks,
            });
            idx = Some(self.entries.len() - 1);
        }
        let e = &mut self.entries[idx.unwrap()];
        if e.total != hdr.total {
            return Err(Error::Length);
        }
        let pos = hdr.index as usize;
        if pos >= e.chunks.len() {
            return Err(Error::Length);
        }
        if e.chunks[pos].is_none() {
            e.chunks[pos] = Some(Vec::from(body));
        }
        // check completion
        if e.chunks.iter().all(|c| c.is_some()) {
            let mut merged = Vec::new();
            for c in e.chunks.iter_mut() {
                merged.extend_from_slice(c.as_ref().unwrap());
            }
            // remove entry
            self.entries.remove(idx.unwrap());
            return Ok(Some(merged));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_reassemble_in_order() {
        let msg = alloc::vec![0xAB; 200];
        let frags = split(&msg, 64, 0x12345678).unwrap();
        assert!(frags.len() > 1);
        let mut r = Reassembler::new(4);
        let mut out = None;
        for f in frags.iter() {
            out = r.accept(f).unwrap();
        }
        assert_eq!(out.unwrap(), msg);
    }

    #[test]
    fn split_and_reassemble_out_of_order() {
        let msg = alloc::vec![0xCD; 150];
        let mut frags = split(&msg, 50, 0xAABBCCDD).unwrap();
        frags.swap(0, 2);
        frags.swap(1, 2);
        let mut r = Reassembler::new(2);
        let mut got = None;
        for f in frags.iter() {
            let x = r.accept(f).unwrap();
            if x.is_some() {
                got = x;
            }
        }
        assert_eq!(got.unwrap(), msg);
    }

    #[test]
    fn reject_bad_header() {
        let msg = alloc::vec![1, 2, 3, 4, 5];
        assert!(split(&msg, HDR_LEN, 1).is_err()); // cap too small
        // Build truncated fragment
        let frags = split(&msg, HDR_LEN + 2, 7).unwrap();
        let mut bad = frags[0].clone();
        bad.truncate(HDR_LEN - 1);
        let mut r = Reassembler::new(1);
        assert!(r.accept(&bad).is_err());
    }
}
