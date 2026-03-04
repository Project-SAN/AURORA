use crate::types::{Chdr, Exp, HopCount, Nonce, Result};

// Utilities to build and manipulate the common header (CHDR)

pub fn setup_header(hops: HopCount, exp: Exp) -> Chdr {
    Chdr::setup(hops, exp)
}

pub fn data_header(hops: HopCount, nonce: Nonce) -> Chdr {
    Chdr::data(hops, nonce)
}

pub fn chdr_exp(chdr: &Chdr) -> Option<Exp> {
    chdr.exp()
}

pub fn chdr_nonce(chdr: &Chdr) -> Option<Nonce> {
    chdr.nonce()
}

pub fn set_chdr_nonce(chdr: &mut Chdr, nonce: &Nonce) -> Result<()> {
    chdr.set_nonce(*nonce)
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
