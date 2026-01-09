use crate::crypto::kdf::{hop_key, OpLabel};
use crate::crypto::{prg, prp};
use crate::types::{Error, Si, R_MAX};
use core::ops::{Deref, DerefMut};
use rand_core::RngCore;
use sha2::{Digest, Sha256, Sha512};

extern crate alloc;

pub const GROUP_LEN: usize = 32; // X25519 point size
pub const MU_LEN: usize = 16; // truncated MAC size
pub const KAPPA_BYTES: usize = 16; // security parameter κ expressed in bytes
pub const TAU_TAG_BYTES: usize = 16;
const ZERO_KAPPA: [u8; KAPPA_BYTES] = [0u8; KAPPA_BYTES];
const MAX_BETA_LEN: usize = (2 * R_MAX + 1) * KAPPA_BYTES;
const MAX_RHO_LEN: usize = (2 * R_MAX + 3) * KAPPA_BYTES;
const MAX_BETA_EXT_LEN: usize = MAX_BETA_LEN + 2 * KAPPA_BYTES;
const MAX_DEST_LEN: usize = 255;
const MAX_FORWARD_BODY_LEN: usize = 9 * 1024;
const MAX_FORWARD_PAYLOAD_LEN: usize = MAX_FORWARD_BODY_LEN - KAPPA_BYTES - MAX_DEST_LEN;

use crate::crypto::mac;
use alloc::vec::Vec;
use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar};

#[derive(Clone, PartialEq, Eq)]
pub struct InlineBytes<const N: usize> {
    len: u16,
    buf: [u8; N],
}

impl<const N: usize> InlineBytes<N> {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            buf: [0u8; N],
        }
    }

    pub fn new(data: &[u8]) -> Result<Self, Error> {
        if data.len() > N || data.len() > u16::MAX as usize {
            return Err(Error::Length);
        }
        let mut buf = [0u8; N];
        buf[..data.len()].copy_from_slice(data);
        Ok(Self {
            len: data.len() as u16,
            buf,
        })
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len()]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len();
        &mut self.buf[..len]
    }

    pub fn set(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() > N || data.len() > u16::MAX as usize {
            return Err(Error::Length);
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.len = data.len() as u16;
        Ok(())
    }

    pub fn resize(&mut self, len: usize, fill: u8) -> Result<(), Error> {
        if len > N || len > u16::MAX as usize {
            return Err(Error::Length);
        }
        let cur = self.len();
        if len > cur {
            self.buf[cur..len].fill(fill);
        }
        self.len = len as u16;
        Ok(())
    }

    pub fn truncate_front(&mut self, prefix: usize) -> Result<(), Error> {
        let len = self.len();
        if prefix > len {
            return Err(Error::Length);
        }
        let new_len = len - prefix;
        self.buf.copy_within(prefix..len, 0);
        self.len = new_len as u16;
        Ok(())
    }
}

impl<const N: usize> Default for InlineBytes<N> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const N: usize> core::fmt::Debug for InlineBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InlineBytes")
            .field("len", &self.len())
            .finish()
    }
}

impl<const N: usize> Deref for InlineBytes<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const N: usize> DerefMut for InlineBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

#[derive(Clone)]
pub struct InlineKeys<const N: usize> {
    len: u8,
    keys: [[u8; 16]; N],
}

impl<const N: usize> InlineKeys<N> {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            keys: [[0u8; 16]; N],
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn push(&mut self, key: [u8; 16]) -> Result<(), Error> {
        let idx = self.len as usize;
        if idx >= N {
            return Err(Error::Length);
        }
        self.keys[idx] = key;
        self.len = (idx + 1) as u8;
        Ok(())
    }

    pub fn as_slice(&self) -> &[[u8; 16]] {
        &self.keys[..self.len()]
    }

    pub fn iter(&self) -> core::slice::Iter<'_, [u8; 16]> {
        self.as_slice().iter()
    }
}

impl<const N: usize> Default for InlineKeys<N> {
    fn default() -> Self {
        Self::empty()
    }
}

type BetaBytes = InlineBytes<MAX_BETA_LEN>;
type BodyBytes = InlineBytes<MAX_FORWARD_BODY_LEN>;
type PiKeys = InlineKeys<R_MAX>;

#[derive(Clone)]
pub struct SiKeys {
    len: u8,
    keys: [Si; R_MAX],
}

impl SiKeys {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            keys: [Si([0u8; 16]); R_MAX],
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn push(&mut self, key: Si) -> Result<(), Error> {
        let idx = self.len as usize;
        if idx >= R_MAX {
            return Err(Error::Length);
        }
        self.keys[idx] = key;
        self.len = (idx + 1) as u8;
        Ok(())
    }

    pub fn as_slice(&self) -> &[Si] {
        &self.keys[..self.len()]
    }

    pub fn iter(&self) -> core::slice::Iter<'_, Si> {
        self.as_slice().iter()
    }
}

impl Default for SiKeys {
    fn default() -> Self {
        Self::empty()
    }
}

impl Deref for SiKeys {
    type Target = [Si];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for SiKeys {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let len = self.len();
        &mut self.keys[..len]
    }
}

#[derive(Clone)]
pub struct Header {
    pub alpha: [u8; GROUP_LEN],
    pub beta: BetaBytes,
    pub gamma: [u8; MU_LEN],
    pub rmax: usize,
    pub hops: usize,
    pub stage: usize,
}

#[derive(Clone)]
pub struct ForwardMessage {
    pub header: Header,
    pub body: BodyBytes,
}

#[derive(Clone)]
pub struct ReplyBlock {
    pub first_node_id: [u8; KAPPA_BYTES],
    pub header: Header,
    pub k_tilde: [u8; KAPPA_BYTES],
}

#[derive(Clone)]
pub struct ReplyState {
    pub identifier: [u8; KAPPA_BYTES],
    pub k_tilde: [u8; KAPPA_BYTES],
    pub pi_keys: PiKeys,
}

pub type ForwardBundle = (ForwardMessage, SiKeys, [u8; 32], PiKeys);

fn derive_si(shared_secret: &[u8; 32]) -> Si {
    let mut si = [0u8; 16];
    hop_key(shared_secret, OpLabel::Enc, &mut si);
    Si(si)
}

fn derive_mu_key(shared: &[u8; 32]) -> [u8; MU_LEN] {
    let mut key = [0u8; MU_LEN];
    hop_key(shared, OpLabel::Mac, &mut key);
    key
}

pub fn derive_pi_key(si: &Si) -> [u8; 16] {
    let mut key = [0u8; 16];
    hop_key(&si.0, OpLabel::Pi, &mut key);
    key
}

pub fn derive_tau_tag(si: &Si) -> [u8; TAU_TAG_BYTES] {
    let mut tag = [0u8; TAU_TAG_BYTES];
    hop_key(&si.0, OpLabel::Tau, &mut tag);
    tag
}

fn derive_rho_stream(shared: &[u8; 32], out: &mut [u8]) {
    prg::prg1(shared, out);
}

fn derive_blinding_scalar(alpha: &[u8; GROUP_LEN], shared: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(alpha);
    hasher.update(shared);
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn derive_node_id(pubkey: &[u8; 32]) -> [u8; KAPPA_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let mut id = [0u8; KAPPA_BYTES];
    id.copy_from_slice(&hash[..KAPPA_BYTES]);
    id
}

const STAR_DESTINATION: [u8; KAPPA_BYTES] = [0u8; KAPPA_BYTES];

fn create_header_internal(
    ephemeral_secret: &[u8; 32],
    node_pubs: &[[u8; 32]],
    rmax: usize,
    dest_override: Option<&[u8]>,
    id_override: Option<&[u8]>,
) -> core::result::Result<(Header, SiKeys, [u8; 32]), Error> {
    let hops = node_pubs.len();
    if hops == 0 || hops > rmax || rmax > R_MAX {
        return Err(Error::Length);
    }

    let dest = dest_override.unwrap_or(&STAR_DESTINATION);
    let ident = id_override.unwrap_or(&ZERO_KAPPA);

    let total_beta_len = (2 * rmax + 1) * KAPPA_BYTES;
    let rho_total_len = (2 * rmax + 3) * KAPPA_BYTES;
    if total_beta_len > MAX_BETA_LEN || rho_total_len > MAX_RHO_LEN {
        return Err(Error::Length);
    }

    let x_scalar = Scalar::from_bytes_mod_order(*ephemeral_secret);
    let mut scalar_cur = x_scalar;

    let mut alpha0 = [0u8; GROUP_LEN];
    let mut shared_list = [[0u8; 32]; R_MAX];
    let mut sis = SiKeys::empty();
    let mut node_ids = [[0u8; KAPPA_BYTES]; R_MAX];

    for (idx, pub_bytes) in node_pubs.iter().enumerate() {
        let pub_pt = MontgomeryPoint(*pub_bytes);
        let alpha_pt: MontgomeryPoint = X25519_BASEPOINT * scalar_cur;
        let alpha_bytes = alpha_pt.to_bytes();
        if idx == 0 {
            alpha0 = alpha_bytes;
        }

        let shared_pt: MontgomeryPoint = pub_pt * scalar_cur;
        let shared = shared_pt.to_bytes();
        shared_list[idx] = shared;
        let si = derive_si(&shared);
        sis.push(si)?;
        node_ids[idx] = derive_node_id(pub_bytes);

        if idx + 1 < hops {
            let blind = derive_blinding_scalar(&alpha_bytes, &shared);
            scalar_cur *= blind;
        }
    }

    let eph_pub = (x_scalar * X25519_BASEPOINT).to_bytes();

    let mut rho_buf = [0u8; MAX_RHO_LEN];
    let mut filler = [0u8; MAX_BETA_LEN];
    let mut filler_len = 0usize;
    for i in 1..hops {
        // prg1 XORs into the buffer, so zero it before reuse.
        rho_buf[..rho_total_len].fill(0);
        derive_rho_stream(&shared_list[i - 1], &mut rho_buf[..rho_total_len]);
        let start = (2 * (rmax - i) + 3) * KAPPA_BYTES;
        let needed = 2 * i * KAPPA_BYTES;
        let slice = &rho_buf[start..start + needed];
        let new_len = filler_len + 2 * KAPPA_BYTES;
        if new_len != needed || new_len > MAX_BETA_LEN {
            return Err(Error::Length);
        }
        for idx in 0..filler_len {
            filler[idx] ^= slice[idx];
        }
        for idx in filler_len..new_len {
            filler[idx] = slice[idx];
        }
        filler_len = new_len;
    }

    let last = hops - 1;
    let front_len = (2 * (rmax - hops) + 3) * KAPPA_BYTES;
    if dest.len() + ident.len() > front_len {
        return Err(Error::Length);
    }

    let mut front = [0u8; MAX_BETA_LEN];
    front[..dest.len()].copy_from_slice(dest);
    front[dest.len()..dest.len() + ident.len()].copy_from_slice(ident);

    rho_buf[..rho_total_len].fill(0);
    derive_rho_stream(&shared_list[last], &mut rho_buf[..rho_total_len]);
    for idx in 0..front_len {
        front[idx] ^= rho_buf[idx];
    }

    if front_len + filler_len != total_beta_len {
        return Err(Error::Length);
    }

    let mut beta_next = [0u8; MAX_BETA_LEN];
    beta_next[..front_len].copy_from_slice(&front[..front_len]);
    if filler_len > 0 {
        beta_next[front_len..front_len + filler_len].copy_from_slice(&filler[..filler_len]);
    }
    let mu_key_last = derive_mu_key(&shared_list[last]);
    let mut gamma_next = mac::mac_trunc16(&mu_key_last, &beta_next[..total_beta_len]).0;

    for idx in (0..last).rev() {
        let mut base = [0u8; MAX_BETA_LEN];
        base[..KAPPA_BYTES].copy_from_slice(&node_ids[idx + 1]);
        base[KAPPA_BYTES..2 * KAPPA_BYTES].copy_from_slice(&gamma_next);
        let tail_len = total_beta_len - 2 * KAPPA_BYTES;
        base[2 * KAPPA_BYTES..2 * KAPPA_BYTES + tail_len]
            .copy_from_slice(&beta_next[..tail_len]);

        rho_buf[..total_beta_len].fill(0);
        derive_rho_stream(&shared_list[idx], &mut rho_buf[..total_beta_len]);
        for (b, m) in base[..total_beta_len]
            .iter_mut()
            .zip(rho_buf[..total_beta_len].iter())
        {
            *b ^= *m;
        }

        beta_next[..total_beta_len].copy_from_slice(&base[..total_beta_len]);
        let mu_key = derive_mu_key(&shared_list[idx]);
        gamma_next = mac::mac_trunc16(&mu_key, &beta_next[..total_beta_len]).0;
    }

    let mut beta = BetaBytes::empty();
    beta.set(&beta_next[..total_beta_len])?;

    let header = Header {
        alpha: alpha0,
        beta,
        gamma: gamma_next,
        rmax,
        hops,
        stage: 0,
    };

    Ok((header, sis, eph_pub))
}

pub fn source_create_forward(
    ephemeral_secret: &[u8; 32],
    node_pubs: &[[u8; 32]],
    rmax: usize,
) -> core::result::Result<(Header, SiKeys, [u8; 32]), Error> {
    let (header, sis, eph) = create_header_internal(ephemeral_secret, node_pubs, rmax, None, None)?;
    Ok((header, sis, eph))
}

pub fn node_process_forward(
    h: &mut Header,
    node_secret: &[u8; 32],
) -> core::result::Result<Si, Error> {
    if h.stage >= h.hops {
        return Err(Error::Length);
    }

    let mut sk_bytes = *node_secret;
    sk_bytes[0] &= 248;
    sk_bytes[31] &= 127;
    sk_bytes[31] |= 64;
    let sk = Scalar::from_bytes_mod_order(sk_bytes);
    let alpha_pt = MontgomeryPoint(h.alpha);
    let shared_pt: MontgomeryPoint = sk * alpha_pt;
    let shared = shared_pt.to_bytes();

    let mu_key = derive_mu_key(&shared);
    let expected = mac::mac_trunc16(&mu_key, h.beta.as_slice());
    if expected.0 != h.gamma {
        return Err(Error::InvalidMac);
    }

    let beta_len = h.beta.len();
    let beta_ext_len = beta_len + 2 * KAPPA_BYTES;
    if beta_ext_len > MAX_BETA_EXT_LEN {
        return Err(Error::Length);
    }
    let mut beta_extended = [0u8; MAX_BETA_EXT_LEN];
    beta_extended[..beta_len].copy_from_slice(h.beta.as_slice());
    let mut rho_stream = [0u8; MAX_BETA_EXT_LEN];
    derive_rho_stream(&shared, &mut rho_stream[..beta_ext_len]);
    for (b, m) in beta_extended[..beta_ext_len]
        .iter_mut()
        .zip(rho_stream[..beta_ext_len].iter())
    {
        *b ^= *m;
    }

    if beta_ext_len < 2 * KAPPA_BYTES {
        return Err(Error::Length);
    }
    let gamma_next_slice = &beta_extended[KAPPA_BYTES..2 * KAPPA_BYTES];
    let beta_next_slice = &beta_extended[2 * KAPPA_BYTES..beta_ext_len];

    let blind = derive_blinding_scalar(&h.alpha, &shared);
    let new_alpha_pt: MontgomeryPoint = alpha_pt * blind;
    h.alpha = new_alpha_pt.to_bytes();
    h.beta.set(beta_next_slice)?;
    let mut gamma_next = [0u8; MU_LEN];
    gamma_next.copy_from_slice(&gamma_next_slice[..MU_LEN]);
    h.gamma = gamma_next;
    h.stage = h.stage.saturating_add(1);

    Ok(derive_si(&shared))
}

pub fn create_forward_message(
    ephemeral_secret: &[u8; 32],
    node_pubs: &[[u8; 32]],
    rmax: usize,
    dest: &[u8],
    payload: &[u8],
) -> core::result::Result<ForwardBundle, Error> {
    if dest.len() > MAX_DEST_LEN {
        return Err(Error::Length);
    }
    if payload.len() > MAX_FORWARD_PAYLOAD_LEN {
        return Err(Error::Length);
    }
    let body_len = KAPPA_BYTES + dest.len() + payload.len();
    if body_len > MAX_FORWARD_BODY_LEN {
        return Err(Error::Length);
    }
    let (header, sis, eph) = create_header_internal(
        ephemeral_secret,
        node_pubs,
        rmax,
        Some(dest),
        Some(&ZERO_KAPPA),
    )?;

    let mut body = BodyBytes::empty();
    body.resize(body_len, 0)?;
    body[..KAPPA_BYTES].copy_from_slice(&ZERO_KAPPA);
    body[KAPPA_BYTES..KAPPA_BYTES + dest.len()].copy_from_slice(dest);
    body[KAPPA_BYTES + dest.len()..].copy_from_slice(payload);

    let mut pi_keys = PiKeys::empty();
    for si in sis.iter() {
        pi_keys.push(derive_pi_key(si))?;
    }
    for key in pi_keys.iter().rev() {
        prp::lioness_encrypt(key, &mut body);
    }

    Ok((ForwardMessage { header, body }, sis, eph, pi_keys))
}

pub fn create_reply_block(
    ephemeral_secret: &[u8; 32],
    node_pubs: &[[u8; 32]],
    rmax: usize,
    dest: &[u8],
    rng: &mut dyn RngCore,
) -> core::result::Result<(ReplyBlock, ReplyState, SiKeys, [u8; 32]), Error> {
    if dest.len() > MAX_DEST_LEN {
        return Err(Error::Length);
    }
    let mut identifier = [0u8; KAPPA_BYTES];
    rng.fill_bytes(&mut identifier);
    let mut k_tilde = [0u8; KAPPA_BYTES];
    rng.fill_bytes(&mut k_tilde);

    let (header, sis, eph) = create_header_internal(
        ephemeral_secret,
        node_pubs,
        rmax,
        Some(dest),
        Some(&identifier),
    )?;

    let first_node_id = derive_node_id(&node_pubs[0]);
    let block = ReplyBlock {
        first_node_id,
        header: header.clone(),
        k_tilde,
    };
    let mut pi_keys = PiKeys::empty();
    for si in sis.iter() {
        pi_keys.push(derive_pi_key(si))?;
    }
    let state = ReplyState {
        identifier,
        k_tilde,
        pi_keys,
    };
    Ok((block, state, sis, eph))
}

pub fn prepare_reply_message(
    rb: &ReplyBlock,
    state: &ReplyState,
    message: &[u8],
) -> core::result::Result<ForwardMessage, Error> {
    let body_len = KAPPA_BYTES + message.len();
    if body_len > MAX_FORWARD_BODY_LEN {
        return Err(Error::Length);
    }
    let mut enc = BodyBytes::empty();
    enc.resize(body_len, 0)?;
    enc[..KAPPA_BYTES].copy_from_slice(&ZERO_KAPPA);
    enc[KAPPA_BYTES..].copy_from_slice(message);
    for key in state.pi_keys.iter().rev() {
        prp::lioness_encrypt(key, &mut enc);
    }
    prp::lioness_encrypt(&rb.k_tilde, &mut enc);
    Ok(ForwardMessage {
        header: rb.header.clone(),
        body: enc,
    })
}

pub fn decrypt_reply(
    state: &ReplyState,
    mut body: BodyBytes,
) -> core::result::Result<BodyBytes, Error> {
    prp::lioness_decrypt(&state.k_tilde, &mut body);
    for key in state.pi_keys.iter() {
        prp::lioness_decrypt(key, &mut body);
    }
    if body.len() < KAPPA_BYTES {
        return Err(Error::Length);
    }
    if body[..KAPPA_BYTES] != ZERO_KAPPA {
        return Err(Error::Crypto);
    }
    body.truncate_front(KAPPA_BYTES)?;
    Ok(body)
}

/// Encode a `Header` into bytes for transport over the setup channel.
pub fn encode_header(header: &Header) -> Result<Vec<u8>, Error> {
    if header.rmax > u8::MAX as usize || header.hops > u8::MAX as usize {
        return Err(Error::Length);
    }
    if header.stage > u8::MAX as usize {
        return Err(Error::Length);
    }
    let expected_beta = (2 * header.rmax + 1) * KAPPA_BYTES;
    if header.beta.len() != expected_beta {
        return Err(Error::Length);
    }
    let mut encoded = Vec::with_capacity(
        GROUP_LEN + MU_LEN + 4 + core::mem::size_of::<u32>() + header.beta.len(),
    );
    encoded.extend_from_slice(&header.alpha);
    encoded.extend_from_slice(&header.gamma);
    encoded.push(header.rmax as u8);
    encoded.push(header.hops as u8);
    encoded.push(header.stage as u8);
    encoded.push(0); // reserved for future use / alignment
    encoded.extend_from_slice(&(header.beta.len() as u32).to_le_bytes());
    encoded.extend_from_slice(header.beta.as_slice());
    Ok(encoded)
}

/// Decode a transport-level header back into the in-memory representation.
pub fn decode_header(bytes: &[u8]) -> Result<Header, Error> {
    const FIXED_PREFIX: usize = GROUP_LEN + MU_LEN + 4;
    if bytes.len() < FIXED_PREFIX + core::mem::size_of::<u32>() {
        return Err(Error::Length);
    }
    let mut alpha = [0u8; GROUP_LEN];
    alpha.copy_from_slice(&bytes[..GROUP_LEN]);
    let mut gamma = [0u8; MU_LEN];
    gamma.copy_from_slice(&bytes[GROUP_LEN..GROUP_LEN + MU_LEN]);
    let meta_start = GROUP_LEN + MU_LEN;
    let rmax = bytes[meta_start] as usize;
    let hops = bytes[meta_start + 1] as usize;
    let stage = bytes[meta_start + 2] as usize;
    let beta_len_offset = meta_start + 4;
    let beta_len = u32::from_le_bytes(
        bytes[beta_len_offset..beta_len_offset + 4]
            .try_into()
            .map_err(|_| Error::Length)?,
    ) as usize;
    let expected_beta = (2 * rmax + 1) * KAPPA_BYTES;
    if beta_len != expected_beta {
        return Err(Error::Length);
    }
    let total = beta_len_offset + 4 + beta_len;
    if bytes.len() != total {
        return Err(Error::Length);
    }
    let beta = BetaBytes::new(&bytes[beta_len_offset + 4..])?;
    Ok(Header {
        alpha,
        beta,
        gamma,
        rmax,
        hops,
        stage,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use rand_core::{CryptoRng, RngCore};

    use super::KAPPA_BYTES;
    use super::ZERO_KAPPA;
    use super::*;
    use crate::crypto::prp;

    struct XorShift64(u64);
    impl RngCore for XorShift64 {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap()
        }
        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> core::result::Result<(), rand_core::Error> {
            let mut n = 0;
            while n < dest.len() {
                let v = self.next_u64().to_le_bytes();
                let take = core::cmp::min(8, dest.len() - n);
                dest[n..n + take].copy_from_slice(&v[..take]);
                n += take;
            }
            Ok(())
        }
    }
    impl CryptoRng for XorShift64 {}

    fn gen_nodes(rng: &mut XorShift64, count: usize) -> Vec<([u8; 32], [u8; 32])> {
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            nodes.push((sk, pk));
        }
        nodes
    }

    #[test]
    fn header_roundtrip_serialization() {
        let rmax = 3usize;
        let beta_len = (2 * rmax + 1) * KAPPA_BYTES;
        let beta = BetaBytes::new(&vec![0x22; beta_len]).expect("beta");
        let header = Header {
            alpha: [0x11; GROUP_LEN],
            beta,
            gamma: [0x33; MU_LEN],
            rmax,
            hops: 2,
            stage: 1,
        };
        let encoded = encode_header(&header).expect("encode");
        let decoded = decode_header(&encoded).expect("decode");
        assert_eq!(decoded.alpha, header.alpha);
        assert_eq!(decoded.beta, header.beta);
        assert_eq!(decoded.gamma, header.gamma);
        assert_eq!(decoded.rmax, header.rmax);
        assert_eq!(decoded.hops, header.hops);
        assert_eq!(decoded.stage, header.stage);
    }

    #[test]
    fn header_decode_rejects_bad_lengths() {
        let mut header = Header {
            alpha: [0u8; GROUP_LEN],
            beta: BetaBytes::new(&vec![0u8; (2 * 1 + 1) * KAPPA_BYTES]).expect("beta"),
            gamma: [0u8; MU_LEN],
            rmax: 1,
            hops: 1,
            stage: 0,
        };
        // remove a byte to trigger encode error
        header
            .beta
            .set(&vec![0u8; (2 * 1 + 1) * KAPPA_BYTES - 1])
            .expect("beta resize");
        assert!(matches!(encode_header(&header), Err(Error::Length)));
        header
            .beta
            .set(&vec![0u8; (2 * 1 + 1) * KAPPA_BYTES])
            .expect("beta resize");
        let mut encoded = encode_header(&header).expect("encode");
        // tamper with beta length field
        let beta_len_offset = GROUP_LEN + MU_LEN + 4;
        encoded[beta_len_offset] = 0xFF;
        assert!(matches!(decode_header(&encoded), Err(Error::Length)));
    }

    #[test]
    fn forward_message_roundtrip_recovers_payload() {
        let mut rng = XorShift64(0x1010_2020_3030_4040);
        let hops = 3usize;
        let rmax = 4usize;
        let nodes = gen_nodes(&mut rng, hops);
        let pubs: vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let dest = b"dest@example";
        let payload = b"hello sphinx";
        let (forward, _sis, _eph, pi_keys) =
            create_forward_message(&x_s, &pubs, rmax, dest, payload).expect("forward message");
        let mut body = forward.body.clone();
        for key in pi_keys.iter() {
            prp::lioness_decrypt(key, &mut body);
        }
        assert_eq!(&body[..KAPPA_BYTES], &ZERO_KAPPA);
        assert_eq!(&body[KAPPA_BYTES..KAPPA_BYTES + dest.len()], dest);
        assert_eq!(&body[KAPPA_BYTES + dest.len()..], payload);
    }

    #[test]
    fn forward_header_tamper_detected() {
        let mut rng = XorShift64(0x2222_3333_4444_5555);
        let nodes = gen_nodes(&mut rng, 2);
        let pubs: vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let (forward, _, _) = source_create_forward(&x_s, &pubs, 2).unwrap();
        let mut header = forward;
        header.beta[0] ^= 0xAA;
        let res = node_process_forward(&mut header, &nodes[0].0);
        assert!(res.is_err());
    }

    #[test]
    fn reply_block_roundtrip() {
        let mut rng = XorShift64(0xabc1_def2_3456_7890);
        let hops = 2usize;
        let nodes = gen_nodes(&mut rng, hops);
        let pubs: vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let dest = b"user@example";
        let message = b"reply payload";
        let (block, state, _sis, _eph) =
            create_reply_block(&x_s, &pubs, hops, dest, &mut rng).expect("reply block");
        let reply = prepare_reply_message(&block, &state, message).expect("reply message");
        let recovered = decrypt_reply(&state, reply.body.clone()).expect("decrypt");
        assert_eq!(recovered.as_slice(), message);
    }

    #[test]
    fn surb_end_to_end_roundtrip() {
        let mut rng = XorShift64(0xfeed_beef_cafe_babe);
        let hops = 3usize;
        let nodes = gen_nodes(&mut rng, hops);
        let pubs: vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let dest = b"surb-dest";
        let message = b"SURB reply body";
        let (block, state, sis, _eph) =
            create_reply_block(&x_s, &pubs, hops, dest, &mut rng).expect("reply block");
        let reply = prepare_reply_message(&block, &state, message).expect("reply message");

        let mut header = reply.header.clone();
        let mut pi_keys_from_nodes = Vec::with_capacity(hops);
        for (idx, node) in nodes.iter().enumerate() {
            let si = node_process_forward(&mut header, &node.0).expect("node process");
            assert_eq!(si.0, sis[idx].0);
            let pi = derive_pi_key(&si);
            pi_keys_from_nodes.push(pi);
        }
        assert_eq!(header.stage, hops);
        assert_eq!(pi_keys_from_nodes.as_slice(), state.pi_keys.as_slice());

        let recovered = decrypt_reply(&state, reply.body.clone()).expect("decrypt");
        assert_eq!(recovered.as_slice(), message);
    }
}
