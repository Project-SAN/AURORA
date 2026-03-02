use alloc::vec::Vec;

use crate::crypto::aegis::core::{open, seal, TAG128_LEN};
use crate::types::{Error, Result, Si};

const ONION_AD: &[u8] = b"AURORA-ONION-LAYER";

// {O', IV} = ADD_LAYER(s, IV, O)
// IV is used as the AEAD nonce for this packet and is carried unchanged.
pub fn add_layer(s: &Si, iv: &mut [u8; 16], payload: &mut Vec<u8>) -> Result<()> {
    let sealed = seal(&s.0, iv, ONION_AD, payload.as_slice(), TAG128_LEN)?;
    payload.clear();
    payload.extend_from_slice(&sealed);
    Ok(())
}

// {O, IV} = REMOVE_LAYER(s, IV, O')
pub fn remove_layer(s: &Si, iv: &mut [u8; 16], payload: &mut Vec<u8>) -> Result<()> {
    let opened = open(&s.0, iv, ONION_AD, payload.as_slice(), TAG128_LEN)?;
    payload.clear();
    payload.extend_from_slice(&opened);
    Ok(())
}

pub fn add_layer_suffix(
    s: &Si,
    iv: &mut [u8; 16],
    payload: &mut Vec<u8>,
    suffix_offset: usize,
) -> Result<()> {
    if suffix_offset > payload.len() {
        return Err(Error::Length);
    }
    let mut tail = payload[suffix_offset..].to_vec();
    add_layer(s, iv, &mut tail)?;
    payload.truncate(suffix_offset);
    payload.extend_from_slice(&tail);
    Ok(())
}

pub fn remove_layer_suffix(
    s: &Si,
    iv: &mut [u8; 16],
    payload: &mut Vec<u8>,
    suffix_offset: usize,
) -> Result<()> {
    if suffix_offset > payload.len() {
        return Err(Error::Length);
    }
    let mut tail = payload[suffix_offset..].to_vec();
    remove_layer(s, iv, &mut tail)?;
    payload.truncate(suffix_offset);
    payload.extend_from_slice(&tail);
    Ok(())
}
