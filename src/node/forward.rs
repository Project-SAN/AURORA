use alloc::vec::Vec;

use crate::{
    node::NodeCtx,
    packet::{ahdr::proc_ahdr, onion},
    policy::PolicyCapsule,
    sphinx::derive_tau_tag,
    types::{Ahdr, Chdr, Error, Exp, RoutingSegment, Sv},
};
pub type Result<T> = core::result::Result<T, Error>;

pub fn process_data(
    ctx: &mut NodeCtx,
    chdr: &mut Chdr,
    ahdr: &mut Ahdr,
    payload: &mut Vec<u8>,
) -> Result<()> {
    eprintln!(
        "[FORWARD] Processing forward packet: ahdr_len={}, payload_len={}",
        ahdr.bytes.len(),
        payload.len()
    );
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    eprintln!("[FORWARD] proc_ahdr succeeded, r_len={}", res.r.0.len());
    let tau = derive_tau_tag(&res.s);
    if !ctx.replay.insert(tau) {
        eprintln!("[FORWARD] replay detected");
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
    eprintln!("[FORWARD] capsule_len={}", capsule_len);

    use crate::types::PacketDirection;

    let mut iv = chdr.specific;
    if capsule_len >= payload.len() {
        // nothing beyond the capsule to decrypt for the next hop
        chdr.specific = iv;
        eprintln!("[FORWARD] forwarding capsule-only payload");
        return ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload, PacketDirection::Forward);
    }

    let tail = &mut payload[capsule_len..];
    onion::remove_layer(&res.s, &mut iv, tail)?;
    chdr.specific = iv;
    eprintln!(
        "[FORWARD] removed onion layer, forwarding tail_len={}",
        tail.len()
    );
    ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload, PacketDirection::Forward)
}

// Optional helpers for setup path (per paper 4.3.4):
// Given CHDR (with EXP) and per-hop symmetric key, create FS using EXP from CHDR.
pub fn create_fs_from_setup(
    chdr: &Chdr,
    sv: &Sv,
    s: &crate::types::Si,
    r: &RoutingSegment,
) -> Result<crate::types::Fs> {
    crate::packet::core::create_from_chdr(sv, s, r, chdr)
}
