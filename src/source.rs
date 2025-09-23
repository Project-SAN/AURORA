use crate::types::{Ahdr, Chdr, Error, Fs, Nonce, Result, Si};
use rand_core::RngCore;

pub struct Session {
    pub ahdr_f: Ahdr,
    pub ahdr_b: Ahdr,
}

pub fn initialize_session(
    _keys_f: &[Si],
    _fses_f: &[Fs],
    _keys_b: &[Si],
    _fses_b: &[Fs],
    rmax: usize,
    rng: &mut dyn RngCore,
) -> Result<Session> {
    let ahdr_f = crate::packet::ahdr::create_ahdr(_keys_f, _fses_f, rmax, rng)?;
    let ahdr_b = crate::packet::ahdr::create_ahdr(_keys_b, _fses_b, rmax, rng)?;
    Ok(Session { ahdr_f, ahdr_b })
}

pub fn build_data_packet(
    _chdr: &Chdr,
    _ahdr: &Ahdr,
    _iv0: Nonce,
    _payload: &mut [u8],
) -> Result<()> {
    // TODO: onion-encrypt payload with forward keys per Alg.19
    Err(Error::NotImplemented)
}

// Encrypt a forward payload at the source: apply layers from last to first
pub fn encrypt_forward_payload(keys: &[Si], iv0: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    let mut iv = *iv0;
    for i in (0..keys.len()).rev() {
        crate::packet::onion::add_layer(&keys[i], &mut iv, payload)?;
    }
    *iv0 = iv;
    Ok(())
}

// Decrypt a backward payload at the source: remove layers from first to last
pub fn decrypt_backward_payload(keys: &[Si], iv0: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    let mut iv = *iv0;
    for i in 0..keys.len() {
        crate::packet::onion::remove_layer(&keys[i], &mut iv, payload)?;
    }
    *iv0 = iv;
    Ok(())
}
