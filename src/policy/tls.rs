//! Minimal TLS record parsing helpers (TLSPlaintext record layer).
//!
//! This module is intentionally small and `no_std` friendly. It is used to
//! segment and validate TLS record boundaries when producing one proof per
//! TLS record.

use crate::types::{Error, Result};

pub const TLS_RECORD_HEADER_LEN: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsRecordHeader {
    pub content_type: u8,
    pub legacy_version: u16,
    pub length: u16,
}

impl TlsRecordHeader {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < TLS_RECORD_HEADER_LEN {
            return Err(Error::Length);
        }
        Ok(Self {
            content_type: buf[0],
            legacy_version: u16::from_be_bytes([buf[1], buf[2]]),
            length: u16::from_be_bytes([buf[3], buf[4]]),
        })
    }

    pub fn total_len(&self) -> usize {
        TLS_RECORD_HEADER_LEN + (self.length as usize)
    }
}

/// Returns the first TLS record and the remaining tail.
pub fn split_first_record(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    let header = TlsRecordHeader::parse(buf)?;
    let total = header.total_len();
    if total > buf.len() {
        return Err(Error::Length);
    }
    Ok((&buf[..total], &buf[total..]))
}

/// Requires that `buf` contains exactly one complete TLS record.
pub fn take_single_record_exact(buf: &[u8]) -> Result<&[u8]> {
    let (record, rest) = split_first_record(buf)?;
    if !rest.is_empty() {
        return Err(Error::Length);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_single_record_exact_accepts_exact_len() {
        // application_data, legacy_version=0x0303, len=3, fragment="abc"
        let buf = [0x17, 0x03, 0x03, 0x00, 0x03, b'a', b'b', b'c'];
        let rec = take_single_record_exact(&buf).expect("record");
        assert_eq!(rec, buf.as_slice());
    }

    #[test]
    fn take_single_record_exact_rejects_incomplete() {
        let buf = [0x17, 0x03, 0x03, 0x00, 0x03, b'a'];
        assert!(matches!(take_single_record_exact(&buf), Err(Error::Length)));
    }

    #[test]
    fn take_single_record_exact_rejects_extra_bytes() {
        let buf = [0x17, 0x03, 0x03, 0x00, 0x00, 0x42];
        assert!(matches!(take_single_record_exact(&buf), Err(Error::Length)));
    }
}
