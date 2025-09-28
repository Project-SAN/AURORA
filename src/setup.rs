use crate::packet::{fs_core, fs_payload};
use crate::sphinx;
use crate::types::{Chdr, Exp, Result, RoutingSegment, Si, Sv, C_BLOCK};
use rand_core::RngCore;

// Strict Sphinx-based setup packet carrying FS payload per HORNET setup.
#[cfg(feature = "strict_sphinx")]
pub struct SetupPacketStrict {
    pub chdr: Chdr,
    pub shdr: sphinx::strict::HeaderStrict,
    pub payload: fs_payload::FsPayload,
    pub rmax: usize,
}

#[cfg(feature = "strict_sphinx")]
pub struct SourceSetupState {
    pub packet: SetupPacketStrict,
    pub keys_f: alloc::vec::Vec<Si>,
    pub eph_pub: [u8; 32],
    pub seed: [u8; 16],
}

// Source initializes the setup packet (strict Sphinx): builds header and randomized FS payload.
#[cfg(feature = "strict_sphinx")]
pub fn source_init_strict(
    x_s: &[u8; 32],
    node_pubs: &[[u8; 32]],
    rmax: usize,
    exp: Exp,
    rng: &mut dyn RngCore,
) -> SourceSetupState {
    let beta_len = rmax * C_BLOCK;
    let (shdr, keys_f, eph_pub) = sphinx::strict::source_create_forward_strict(x_s, node_pubs, beta_len);
    // Initialize FS payload with random seed
    let mut seed = [0u8; 16];
    rng.fill_bytes(&mut seed);
    let payload = fs_payload::FsPayload::new_with_seed(rmax, &seed);
    let chdr = crate::packet::chdr::setup_header(node_pubs.len() as u8, exp);
    let packet = SetupPacketStrict { chdr, shdr, payload, rmax };
    SourceSetupState { packet, keys_f, eph_pub, seed }
}

// A hop processes setup: verifies/advances Sphinx strict header, creates FS from CHDR, and inserts into payload.
#[cfg(feature = "strict_sphinx")]
pub fn node_process_strict(
    pkt: &mut SetupPacketStrict,
    node_secret: &[u8; 32],
    sv: &Sv,
    rseg: &RoutingSegment,
) -> Result<Si> {
    let si = sphinx::strict::node_process_forward_strict(&mut pkt.shdr, node_secret)?;
    let fs = fs_core::create_from_chdr(sv, &si, rseg, &pkt.chdr)?;
    let _alpha = fs_payload::add_fs_into_payload(&si, &fs, &mut pkt.payload)?;
    Ok(si)
}
