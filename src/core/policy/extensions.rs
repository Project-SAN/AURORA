use crate::types::{Error, Result};

const EXT_MAGIC: &[u8; 4] = b"ZEXT";
const EXT_VERSION: u8 = 1;

pub const EXT_TAG_MODE: u8 = 1;
pub const EXT_TAG_SEQUENCE: u8 = 2;
pub const EXT_TAG_BATCH_ID: u8 = 3;
pub const EXT_TAG_PRECOMPUTE_ID: u8 = 4;
pub const EXT_TAG_PAYLOAD_HASH: u8 = 5;
pub const EXT_TAG_PRECOMPUTE_PROOF: u8 = 6;
pub const EXT_TAG_PCD_STATE: u8 = 7;
pub const EXT_TAG_PCD_KEY_HASH: u8 = 8;
pub const EXT_TAG_PCD_ROOT: u8 = 9;
pub const EXT_TAG_PCD_TARGET_HASH: u8 = 10;
pub const EXT_TAG_PCD_SEQ: u8 = 11;
pub const EXT_TAG_PCD_PROOF: u8 = 12;
pub const EXT_TAG_SESSION_NONCE: u8 = 13;
pub const EXT_TAG_ROUTE_ID: u8 = 14;

#[derive(Clone, Copy)]
pub struct CapsuleExtensionRef<'a> {
    pub tag: u8,
    pub data: &'a [u8],
}

pub fn encode_extensions_into(exts: &[CapsuleExtensionRef<'_>], out: &mut [u8]) -> Result<usize> {
    let mut cursor = 0usize;
    if out.len() < 6 {
        return Err(Error::Length);
    }
    out[cursor..cursor + 4].copy_from_slice(EXT_MAGIC);
    cursor += 4;
    out[cursor] = EXT_VERSION;
    cursor += 1;
    out[cursor] = exts.len().min(u8::MAX as usize) as u8;
    cursor += 1;
    for ext in exts {
        let len = ext.data.len();
        if len > u16::MAX as usize {
            return Err(Error::Length);
        }
        if cursor + 3 + len > out.len() {
            return Err(Error::Length);
        }
        out[cursor] = ext.tag;
        out[cursor + 1..cursor + 3].copy_from_slice(&(len as u16).to_be_bytes());
        cursor += 3;
        out[cursor..cursor + len].copy_from_slice(ext.data);
        cursor += len;
    }
    Ok(cursor)
}

pub fn extension_iter(aux: &[u8]) -> Result<Option<ExtensionIter<'_>>> {
    if aux.len() < 6 || &aux[..4] != EXT_MAGIC {
        return Ok(None);
    }
    if aux[4] != EXT_VERSION {
        return Err(Error::Length);
    }
    let count = aux[5] as usize;
    Ok(Some(ExtensionIter {
        bytes: aux,
        cursor: 6,
        remaining: count,
    }))
}

pub struct ExtensionIter<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
}

impl<'a> ExtensionIter<'a> {
    pub fn find_tag(self, tag: u8) -> Result<Option<&'a [u8]>> {
        for entry in self {
            let (entry_tag, value) = entry?;
            if entry_tag == tag {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
}

impl<'a> Iterator for ExtensionIter<'a> {
    type Item = Result<(u8, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.cursor + 3 > self.bytes.len() {
            self.remaining = 0;
            return Some(Err(Error::Length));
        }
        let tag = self.bytes[self.cursor];
        let len =
            u16::from_be_bytes([self.bytes[self.cursor + 1], self.bytes[self.cursor + 2]]) as usize;
        self.cursor += 3;
        if self.cursor + len > self.bytes.len() {
            self.remaining = 0;
            return Some(Err(Error::Length));
        }
        let slice = &self.bytes[self.cursor..self.cursor + len];
        self.cursor += len;
        self.remaining = self.remaining.saturating_sub(1);
        Some(Ok((tag, slice)))
    }
}

pub fn find_extension(aux: &[u8], tag: u8) -> Result<Option<&[u8]>> {
    let iter = match extension_iter(aux)? {
        Some(iter) => iter,
        None => return Ok(None),
    };
    iter.find_tag(tag)
}
