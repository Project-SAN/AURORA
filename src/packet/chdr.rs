use crate::types::{Chdr, Exp, Nonce, PacketType};

// Utilities to build and manipulate the common header (CHDR)

pub fn setup_header(hops: u8, exp: Exp) -> Chdr {
    let mut specific = [0u8; 16];
    specific[0..4].copy_from_slice(&exp.0.to_be_bytes());
    Chdr {
        typ: PacketType::Setup,
        hops,
        specific,
    }
}

pub fn data_header(hops: u8, nonce: Nonce) -> Chdr {
    Chdr {
        typ: PacketType::Data,
        hops,
        specific: nonce.0,
    }
}

pub fn chdr_exp(chdr: &Chdr) -> Option<Exp> {
    match chdr.typ {
        PacketType::Setup => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&chdr.specific[0..4]);
            Some(Exp(u32::from_be_bytes(b)))
        }
        _ => None,
    }
}

pub fn chdr_nonce(chdr: &Chdr) -> Option<Nonce> {
    match chdr.typ {
        PacketType::Data => Some(Nonce(chdr.specific)),
        _ => None,
    }
}

pub fn set_chdr_nonce(chdr: &mut Chdr, nonce: &Nonce) {
    chdr.specific = nonce.0;
}

// HORNET paper recommends coarse-grained EXP and limited set of durations to avoid linkability
#[derive(Clone, Copy)]
pub enum ExpBucket {
    S10,
    S30,
    M1,
    M10,
}

impl ExpBucket {
    pub fn secs(self) -> u32 {
        match self {
            ExpBucket::S10 => 10,
            ExpBucket::S30 => 30,
            ExpBucket::M1 => 60,
            ExpBucket::M10 => 600,
        }
    }
}

// Compute expiration as now + bucket, returning coarse time window end
pub fn bucket_exp(now_secs: u32, bucket: ExpBucket) -> Exp {
    Exp(now_secs.saturating_add(bucket.secs()))
}

pub fn is_expired(now_secs: u32, exp: Exp) -> bool {
    now_secs >= exp.0
}
