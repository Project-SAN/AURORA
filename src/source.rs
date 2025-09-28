use crate::types::{Ahdr, Chdr, Error, Nonce, Result, Si};
use rand_core::RngCore;

// (removed) initialize_session: thin AHDR wrapper was unnecessary

// Build a forward data packet payload per Alg.19:
// - Input: CHDR (Data), AHDR (forward), random nonce IV0, and plaintext payload.
// - Apply onion encryption layers with forward keys (last->first) to produce O0 and
//   update IV in-place to the value carried in CHDR for the first hop.
// Note: The forward per-hop keys Si must be provided by the caller based on the
// prior setup. This function does not derive keys from AHDR.
pub fn build_data_packet(
    chdr: &mut Chdr,
    _ahdr: &Ahdr,
    keys_f: &[Si],
    iv0: &mut Nonce,
    payload: &mut [u8],
) -> Result<()> {
    // CHDR must be a data header
    if !matches!(chdr.typ, crate::types::PacketType::Data) {
        return Err(Error::Length);
    }
    // Start from the provided IV0 (random nonce) and apply layers from last to first
    let mut iv = iv0.0;
    for i in (0..keys_f.len()).rev() {
        crate::packet::onion::add_layer(&keys_f[i], &mut iv, payload)?;
    }
    // Update IV0 (for caller) and CHDR.specific to the final IV carried on the wire
    iv0.0 = iv;
    chdr.specific = iv;
    Ok(())
}

// Destination-side helper: build backward AHDR from per-hop keys and node contexts.
// The caller must provide keys in the order of traversal (destination -> ... -> source).
// (removed) dest_build_ahdr_b: tests inline the construction

// Place AHDRb into the first data payload buffer.
// (removed) embed_ahdrb_into_first_data_payload

// Extract AHDRb from the first data payload buffer.
// (removed) extract_ahdrb_from_first_data_payload

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
