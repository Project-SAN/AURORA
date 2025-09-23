use crate::packet::ahdr::proc_ahdr;
use crate::packet::onion;
use crate::types::{Ahdr, Chdr, Exp, Result, RoutingSegment, Sv};

pub struct NodeCtx<'a> {
    pub sv: Sv,
    pub now: &'a dyn crate::time::TimeProvider,
    // User supplies a forwarding function that knows how to send to next hop
    pub forward: &'a mut dyn FnMut(&RoutingSegment, &Chdr, &Ahdr, &mut [u8]) -> Result<()>,
}

pub fn process_data_forward(
    ctx: &mut NodeCtx,
    chdr: &mut Chdr,
    ahdr: &mut Ahdr,
    payload: &mut [u8],
) -> Result<()> {
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    // Remove one onion layer and mutate IV in CHDR.specific
    let mut iv = chdr.specific;
    onion::remove_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    // Forward to next hop using routing segment
    (ctx.forward)(&res.r, chdr, &res.ahdr_next, payload)
}

pub fn process_data_backward(
    ctx: &mut NodeCtx,
    chdr: &mut Chdr,
    ahdr: &mut Ahdr,
    payload: &mut [u8],
) -> Result<()> {
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    // Add one onion layer and mutate IV in CHDR.specific
    let mut iv = chdr.specific;
    onion::add_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    (ctx.forward)(&res.r, chdr, &res.ahdr_next, payload)
}

// Optional helpers for setup path (per paper 4.3.4):
// Given CHDR (with EXP) and per-hop symmetric key, create FS using EXP from CHDR.
pub fn create_fs_from_setup(
    chdr: &Chdr,
    sv: &Sv,
    s: &crate::types::Si,
    r: &RoutingSegment,
) -> Result<crate::types::Fs> {
    crate::packet::fs_create_from_chdr(sv, s, r, chdr)
}
