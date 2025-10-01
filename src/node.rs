use alloc::collections::BTreeSet;

use crate::packet::ahdr::proc_ahdr;
use crate::packet::onion;
use crate::sphinx::*;
use crate::types::{Ahdr, Chdr, Exp, Result, RoutingSegment, Sv};

pub trait ReplayFilter {
    fn check_and_insert(&mut self, tag: [u8; TAU_TAG_BYTES]) -> bool;
}

pub struct ReplayCache {
    seen: BTreeSet<[u8; TAU_TAG_BYTES]>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
        }
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayFilter for ReplayCache {
    fn check_and_insert(&mut self, tag: [u8; crate::sphinx::TAU_TAG_BYTES]) -> bool {
        self.seen.insert(tag)
    }
}

pub struct NoReplay;

impl ReplayFilter for NoReplay {
    fn check_and_insert(&mut self, _tag: [u8; crate::sphinx::TAU_TAG_BYTES]) -> bool {
        true
    }
}

pub struct NodeCtx<'a> {
    pub sv: Sv,
    pub now: &'a dyn crate::time::TimeProvider,
    // Forwarding abstraction: implementor sends to next hop
    pub forward: &'a mut dyn crate::forward::Forward,
    pub replay: &'a mut dyn ReplayFilter,
}

pub fn process_data_forward(
    ctx: &mut NodeCtx,
    chdr: &mut Chdr,
    ahdr: &mut Ahdr,
    payload: &mut [u8],
) -> Result<()> {
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    let tau = derive_tau_tag(&res.s);
    if !ctx.replay.check_and_insert(tau) {
        return Err(crate::types::Error::Replay);
    }
    let mut iv = chdr.specific;
    onion::remove_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload)
}

pub fn process_data_backward(
    ctx: &mut NodeCtx,
    chdr: &mut Chdr,
    ahdr: &mut Ahdr,
    payload: &mut [u8],
) -> Result<()> {
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    let tau = derive_tau_tag(&res.s);
    if !ctx.replay.check_and_insert(tau) {
        return Err(crate::types::Error::Replay);
    }
    let mut iv = chdr.specific;
    onion::add_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload)
}

// Optional helpers for setup path (per paper 4.3.4):
// Given CHDR (with EXP) and per-hop symmetric key, create FS using EXP from CHDR.
pub fn create_fs_from_setup(
    chdr: &Chdr,
    sv: &Sv,
    s: &crate::types::Si,
    r: &RoutingSegment,
) -> Result<crate::types::Fs> {
    crate::packet::create_from_chdr(sv, s, r, chdr)
}
