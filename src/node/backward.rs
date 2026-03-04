use alloc::vec::Vec;

use crate::{
    node::NodeCtx,
    packet::{ahdr::proc_ahdr, onion},
    sphinx::derive_tau_tag,
    types::{Ahdr, Chdr, Error, Exp},
};
pub type Result<T> = core::result::Result<T, Error>;

pub fn process_data(
    ctx: &mut NodeCtx<'_, '_, '_>,
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

    // Backward packets don't have policy capsules - they contain encrypted responses
    // from the exit node. We just need to add our onion layer and forward.
    use crate::types::PacketDirection;

    let mut iv = chdr.nonce().ok_or(Error::Length)?.0;
    onion::add_layer(&res.s, &mut iv, payload)?;
    chdr.set_nonce(crate::types::Nonce(iv))?;
    ctx.forward.send(
        &res.r,
        chdr,
        &res.ahdr_next,
        payload,
        PacketDirection::Backward,
    )
}
