use alloc::vec::Vec;

use crate::policy::encoder::{EncodeError, PolicySection};
use crate::policy::witness::ProofMaterial;
use crate::types::{Ahdr, Chdr, Error, Nonce, Result, Si};

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
    for key in keys_f.iter().rev() {
        crate::packet::onion::add_layer(key, &mut iv, payload)?;
    }
    // Update IV0 (for caller) and CHDR.specific to the final IV carried on the wire
    iv0.0 = iv;
    chdr.specific = iv;
    Ok(())
}

pub fn encode_wire_with_policy(
    chdr: &Chdr,
    ahdr: &Ahdr,
    payload: &[u8],
    policy: Option<(&ProofMaterial, &[u8])>,
) -> core::result::Result<(Vec<u8>, Option<PolicySection>), EncodeError> {
    match policy {
        Some((material, proof_bytes)) => {
            let section = material.build_policy_section(proof_bytes)?;
            let bytes = crate::wire::encode(chdr, Some(&section), ahdr, payload);
            Ok((bytes, Some(section)))
        }
        None => {
            let bytes = crate::wire::encode(chdr, None, ahdr, payload);
            Ok((bytes, None))
        }
    }
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
    for key in keys.iter().rev() {
        crate::packet::onion::add_layer(key, &mut iv, payload)?;
    }
    *iv0 = iv;
    Ok(())
}

// Decrypt a backward payload at the source: remove layers from first to last
pub fn decrypt_backward_payload(keys: &[Si], iv0: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    let mut iv = *iv0;
    for key in keys {
        crate::packet::onion::remove_layer(key, &mut iv, payload)?;
    }
    *iv0 = iv;
    Ok(())
}

// tests are maintained in other modules focusing on Sphinx strict and AHDR
