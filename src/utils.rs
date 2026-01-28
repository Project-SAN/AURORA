use alloc::{string::String, vec::Vec};
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    InvalidChar(char),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexError::OddLength => write!(f, "odd length"),
            HexError::InvalidChar(c) => write!(f, "invalid hex char '{c}'"),
        }
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0F) as usize] as char);
    }
    out
}

pub fn decode_hex(input: &str) -> Result<Vec<u8>, HexError> {
    if !input.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut chars = input.chars();
    while let Some(high) = chars.next() {
        let low = chars.next().ok_or(HexError::OddLength)?;
        let hi = nibble(high)?;
        let lo = nibble(low)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

pub fn nibble(c: char) -> Result<u8, HexError> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        'a'..='f' => Ok((c as u8) - b'a' + 10),
        'A'..='F' => Ok((c as u8) - b'A' + 10),
        _ => Err(HexError::InvalidChar(c)),
    }
}
