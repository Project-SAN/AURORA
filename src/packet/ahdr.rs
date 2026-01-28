use crate::crypto::{
    kdf::{hop_key, OpLabel},
    mac, prg,
};
use crate::packet::core::open;
use crate::types::{Ahdr, Error, Exp, Fs, Result, RoutingSegment, Si, Sv, C_BLOCK, FS_LEN};
use alloc::vec;
use alloc::vec::Vec;
use rand_core::RngCore;

pub struct ProcResult {
    pub s: Si,
    pub r: RoutingSegment,
    pub ahdr_next: Ahdr,
}

// Algorithm 3: Process an AHDR at a hop
pub fn proc_ahdr(sv: &Sv, ahdr: &Ahdr, now: Exp) -> Result<ProcResult> {
    let rc = ahdr.bytes.len();
    if !rc.is_multiple_of(C_BLOCK) {
        return Err(Error::Length);
    }
    // number of blocks r = rc / C_BLOCK (not needed explicitly)
    // Parse head block
    let head = &ahdr.bytes[0..C_BLOCK];
    let fs_bytes = &head[0..FS_LEN];
    let gamma = &head[FS_LEN..C_BLOCK];
    let beta = &ahdr.bytes[C_BLOCK..];
    let fs = Fs(<[u8; FS_LEN]>::try_from(fs_bytes).map_err(|_| Error::Length)?);
    let (s, rseg, exp) = open(sv, &fs)?;
    if now.0 >= exp.0 {
        return Err(Error::Expired);
    }

    // Verify MAC: gamma == MAC(hMAC(s); FS || beta)
    let mut mac_key = [0u8; 16];
    hop_key(&s.0, OpLabel::Mac, &mut mac_key);
    let mut mac_input = Vec::with_capacity(FS_LEN + beta.len());
    mac_input.extend_from_slice(&fs.0);
    mac_input.extend_from_slice(beta);
    let tag = mac::mac_trunc16(&mac_key, &mac_input);
    if tag.0.as_slice() != gamma {
        return Err(Error::InvalidMac);
    }
    // Compute next header: (beta || 0^c) XOR PRG2(s)
    let mut next = Vec::with_capacity(rc);
    next.extend_from_slice(beta);
    next.resize(rc, 0u8);
    let mut mask = vec![0u8; rc];
    prg::prg2(&s.0, &mut mask);
    for (b, m) in next.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
    Ok(ProcResult {
        s,
        r: rseg,
        ahdr_next: Ahdr { bytes: next },
    })
}

// Algorithm 4: Create AHDR from {si},{FSi}
pub fn create_ahdr(keys: &[Si], fses: &[Fs], rmax: usize, rng: &mut dyn RngCore) -> Result<Ahdr> {
    let l = keys.len();
    if l == 0 || l != fses.len() {
        return Err(Error::Length);
    }
    if rmax == 0 || l > rmax {
        return Err(Error::Length);
    }
    let rc = rmax * C_BLOCK;
    // Compute paddings phi
    let mut phi: Vec<u8> = Vec::new(); // length i*c at step i
    for (i, key) in keys.iter().enumerate().take(l.saturating_sub(1)) {
        let mut mask = vec![0u8; rc];
        prg::prg2(&key.0, &mut mask);
        let start = (rmax - 1 - i) * C_BLOCK;
        let end = rc;
        let slice = &mask[start..end]; // length (i+1)*c
                                       // new_phi = (phi || 0^c) XOR slice
        let mut new_phi = Vec::with_capacity(phi.len() + C_BLOCK);
        new_phi.extend_from_slice(&phi);
        new_phi.resize(phi.len() + C_BLOCK, 0);
        for (b, m) in new_phi.iter_mut().zip(slice.iter()) {
            *b ^= *m;
        }
        phi = new_phi;
    }
    // beta_{l-1} = RAND((r-l)c) || phi
    let mut beta = Vec::with_capacity((rmax - 1) * C_BLOCK);
    let rand_len = (rmax - l) * C_BLOCK;
    if rand_len > 0 {
        let mut rnd = vec![0u8; rand_len];
        rng.fill_bytes(&mut rnd);
        beta.extend_from_slice(&rnd);
    }
    beta.extend_from_slice(&phi);
    // gamma_{l-1}
    let mut hkey = [0u8; 16];
    hop_key(&keys[l - 1].0, OpLabel::Mac, &mut hkey);
    let mut mac_input = Vec::with_capacity(FS_LEN + beta.len());
    mac_input.extend_from_slice(&fses[l - 1].0);
    mac_input.extend_from_slice(&beta);
    let mut gamma = mac::mac_trunc16(&hkey, &mac_input).0.to_vec();
    // iterate i = l-2 .. 0 (only if l >= 2)
    for (i, key) in keys.iter().enumerate().take(l.saturating_sub(1)).rev() {
        // base = FSi+1 || gamma_{i+1} || beta_{i+1}[0..(r-2)c]
        let mut base = Vec::with_capacity((rmax - 1) * C_BLOCK);
        base.extend_from_slice(&fses[i + 1].0);
        base.extend_from_slice(&gamma);
        let tail_len = (rmax - 2) * C_BLOCK;
        base.extend_from_slice(&beta[0..tail_len.min(beta.len())]);
        // mask = PRG2(s_i)[0..(r-1)c]
        let mut mask = vec![0u8; (rmax - 1) * C_BLOCK];
        prg::prg2(&key.0, &mut mask);
        // beta_i = base XOR mask
        for (b, m) in base.iter_mut().zip(mask.iter()) {
            *b ^= *m;
        }
        beta = base;
        // gamma_i = MAC(hMAC(s_i); FS_i || beta_i)
        let mut hkey_i = [0u8; 16];
        hop_key(&key.0, OpLabel::Mac, &mut hkey_i);
        let mut mac_input_i = Vec::with_capacity(FS_LEN + beta.len());
        mac_input_i.extend_from_slice(&fses[i].0);
        mac_input_i.extend_from_slice(&beta);
        gamma = mac::mac_trunc16(&hkey_i, &mac_input_i).0.to_vec();
    }
    // Compose AHDR: FS0 || gamma0 || beta0
    let mut bytes = Vec::with_capacity(rc);
    bytes.extend_from_slice(&fses[0].0);
    bytes.extend_from_slice(&gamma);
    // beta length should be (r-1)c; ensure size
    if beta.len() != (rmax - 1) * C_BLOCK {
        beta.resize((rmax - 1) * C_BLOCK, 0);
    }
    bytes.extend_from_slice(&beta);
    Ok(Ahdr { bytes })
}

// Algorithm 5: Nested AHDR construction (outer includes inner)
pub fn create_nested_ahdr(
    keys: &[Si],
    fses: &[Fs],
    inner: &Ahdr,
    rmax: usize,
    rng: &mut dyn RngCore,
) -> Result<Ahdr> {
    // Algorithm 5: Nested AHDR construction
    let l = keys.len();
    if l == 0 || l != fses.len() {
        return Err(Error::Length);
    }
    let rc = rmax * C_BLOCK;
    if inner.bytes.len() != rc {
        return Err(Error::Length);
    }
    // φ computation
    let mut phi: Vec<u8> = Vec::new();
    for (offset, key) in keys.iter().enumerate().take(l.saturating_sub(1)) {
        let i = offset + 1;
        let mut mask = vec![0u8; 2 * rc];
        prg::prg0(&key.0, &mut mask);
        let start = (2 * rmax - i) * C_BLOCK;
        let slice = &mask[start..]; // length = i*c
        let mut new_phi = Vec::with_capacity(phi.len() + C_BLOCK);
        new_phi.extend_from_slice(&phi);
        new_phi.resize(phi.len() + C_BLOCK, 0);
        for (b, m) in new_phi.iter_mut().zip(slice.iter()) {
            *b ^= *m;
        }
        phi = new_phi;
    }
    // β_{l-1} = {A || RAND(c(r-l))} XOR PRG0(s_{l-1})[0..c(2r-l)-1] || φ_{l-1}
    let mut beta_first = Vec::with_capacity(rc + (rmax - l) * C_BLOCK);
    beta_first.extend_from_slice(&inner.bytes);
    if rmax > l {
        let mut rnd = vec![0u8; (rmax - l) * C_BLOCK];
        rng.fill_bytes(&mut rnd);
        beta_first.extend_from_slice(&rnd);
    }
    // Mask length c(2r - l)
    let mut mask = vec![0u8; rc + (rmax - l) * C_BLOCK];
    prg::prg0(&keys[l - 1].0, &mut mask);
    for (b, m) in beta_first.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
    let mut beta = Vec::with_capacity(2 * rc - C_BLOCK);
    beta.extend_from_slice(&beta_first);
    beta.extend_from_slice(&phi);
    // γ_{l-1}
    let mut hkey = [0u8; 16];
    hop_key(&keys[l - 1].0, OpLabel::Mac, &mut hkey);
    let mut mac_input = Vec::with_capacity(FS_LEN + beta.len());
    mac_input.extend_from_slice(&fses[l - 1].0);
    mac_input.extend_from_slice(&beta);
    let mut gamma = mac::mac_trunc16(&hkey, &mac_input).0.to_vec();
    // Iterate i = l-2 .. 0
    for (i, key) in keys.iter().enumerate().take(l.saturating_sub(1)).rev() {
        // base = FS_{i+1} || gamma_{i+1} || beta_{i+1}[0 .. c(2r-1)-1]
        let mut base = Vec::with_capacity(2 * rc);
        base.extend_from_slice(&fses[i + 1].0);
        base.extend_from_slice(&gamma);
        let slice_len = 2 * rc - C_BLOCK; // c(2r-1)
        base.extend_from_slice(&beta[0..slice_len.min(beta.len())]);
        // XOR first c(2r - l) bytes with PRG0(s_i)
        let xor_len = rc + (rmax - l) * C_BLOCK; // c(2r - l)
        let mut mask_i = vec![0u8; xor_len];
        prg::prg0(&key.0, &mut mask_i);
        for (b, m) in base.iter_mut().take(xor_len).zip(mask_i.iter()) {
            *b ^= *m;
        }
        beta = base;
        // gamma_i
        let mut hkey_i = [0u8; 16];
        hop_key(&key.0, OpLabel::Mac, &mut hkey_i);
        let mut mac_input_i = Vec::with_capacity(FS_LEN + beta.len());
        mac_input_i.extend_from_slice(&fses[i].0);
        mac_input_i.extend_from_slice(&beta);
        gamma = mac::mac_trunc16(&hkey_i, &mac_input_i).0.to_vec();
    }
    // Compose outer AHDR: FS0 || gamma0 || beta0 (length 2rc)
    let mut bytes = Vec::with_capacity(2 * rc);
    bytes.extend_from_slice(&fses[0].0);
    bytes.extend_from_slice(&gamma);
    // Ensure beta length is c(2r-1)
    if beta.len() != 2 * rc - C_BLOCK {
        beta.resize(2 * rc - C_BLOCK, 0);
    }
    bytes.extend_from_slice(&beta);
    Ok(Ahdr { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, RngCore};

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

    #[test]
    fn ahdr_expiry_check() {
        let mut rng = XorShift64(0x0f0e_0d0c_0b0a_0908);
        let rmax = 1usize;
        let mut svb = [0u8; 16];
        rng.fill_bytes(&mut svb);
        let sv = Sv(svb);
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        let si = Si(key);
        let rseg = RoutingSegment(alloc::vec![0u8; 8]);
        let exp = Exp(1_234_567);
        let fs = crate::packet::core::create(&sv, &si, &rseg, exp).expect("fs");
        let mut rng2 = XorShift64(0x0102_0304_0506_0708);
        let ahdr = create_ahdr(&[si], &[fs], rmax, &mut rng2).expect("ahdr");
        let _pr = proc_ahdr(&sv, &ahdr, Exp(exp.0 - 1)).expect("proc ok before exp");
        let err = proc_ahdr(&sv, &ahdr, Exp(exp.0))
            .err()
            .expect("must error at exp");
        assert!(matches!(err, Error::Expired));
    }
}
