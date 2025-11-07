use crate::crypto::prp;
use crate::types::{Chdr, Error, Exp, Fs, PacketType, Result, RoutingSegment, Si, Sv, FS_LEN};
use alloc::vec::Vec;

// Encode {s || EXP || R[0..12]} into 32 bytes, then PRP-enc with key from SV
pub fn create(sv: &Sv, s: &Si, r: &RoutingSegment, exp: Exp) -> Result<Fs> {
    if r.0.len() > 12 {
        return Err(Error::Length);
    }
    let mut plain = [0u8; FS_LEN];
    plain[0..16].copy_from_slice(&s.0);
    plain[16..20].copy_from_slice(&exp.0.to_be_bytes());
    plain[20..20 + r.0.len()].copy_from_slice(&r.0);
    let mut buf = plain;
    prp::prp_enc_bytes(&sv.0, &mut buf);
    Ok(Fs(buf))
}

pub fn open(sv: &Sv, fs: &Fs) -> Result<(Si, RoutingSegment, Exp)> {
    let mut buf = fs.0;
    prp::prp_dec_bytes(&sv.0, &mut buf);
    let mut k = [0u8; 16];
    k.copy_from_slice(&buf[0..16]);
    let mut exp_bytes = [0u8; 4];
    exp_bytes.copy_from_slice(&buf[16..20]);
    let exp = Exp(u32::from_be_bytes(exp_bytes));
    let r = RoutingSegment(Vec::from(&buf[20..32]));
    Ok((Si(k), r, exp))
}

// Convenience: derive EXP from a setup CHDR, validate type, and create FS
pub fn create_from_chdr(sv: &Sv, s: &Si, r: &RoutingSegment, chdr: &Chdr) -> Result<Fs> {
    match chdr.typ {
        PacketType::Setup => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&chdr.specific[0..4]);
            let exp = Exp(u32::from_be_bytes(b));
            create(sv, s, r, exp)
        }
        _ => Err(Error::Length),
    }
}
