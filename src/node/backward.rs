use alloc::vec::Vec;

use crate::{
    node::NodeCtx,
    packet::{ahdr::proc_ahdr, onion},
    policy::PolicyCapsule,
    sphinx::derive_tau_tag,
    types::{Ahdr, Chdr, Error, Exp},
};
pub type Result<T> = core::result::Result<T, Error>;

pub fn process_data(
    ctx: &mut NodeCtx,
    chdr: &mut Chdr,
    ahdr: &mut Ahdr,
    payload: &mut Vec<u8>,
) -> Result<()> {
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    let tau = derive_tau_tag(&res.s);
    if !ctx.replay.insert(tau) {
        return Err(crate::types::Error::Replay);
    }
    let capsule_len = if let Some(policy) = ctx.policy {
        policy
            .forward
            .enforce(policy.registry, payload, policy.validator)?
            .map(|(_, consumed)| consumed)
    } else {
        None
    }
    .or_else(|| {
        PolicyCapsule::decode(payload.as_slice())
            .ok()
            .map(|(_, len)| len)
    })
    .unwrap_or(0);

    let mut iv = chdr.specific;
    if capsule_len >= payload.len() {
        chdr.specific = iv;
        return ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload);
    }

    let tail = &mut payload[capsule_len..];
    onion::add_layer(&res.s, &mut iv, tail)?;
    chdr.specific = iv;
    ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload)
}
