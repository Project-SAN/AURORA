use alloc::vec::Vec;

use crate::{
    node::NodeCtx,
    packet::{ahdr::proc_ahdr, onion},
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
    #[cfg(feature = "std")]
    eprintln!(
        "[BACKWARD] Processing backward packet: ahdr_len={}, payload_len={}",
        ahdr.bytes.len(),
        payload.len()
    );
    let now = Exp(ctx.now.now_coarse());
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    #[cfg(feature = "std")]
    eprintln!("[BACKWARD] proc_ahdr succeeded, r_len={}", res.r.0.len());
    let tau = derive_tau_tag(&res.s);
    if !ctx.replay.insert(tau) {
        return Err(crate::types::Error::Replay);
    }

    // Backward packets don't have policy capsules - they contain encrypted responses
    // from the exit node. We just need to add our onion layer and forward.
    use crate::types::PacketDirection;

    let mut iv = chdr.specific;
    onion::add_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    #[cfg(feature = "std")]
    eprintln!(
        "[BACKWARD] Added onion layer, forwarding {} bytes",
        payload.len()
    );
    ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload, PacketDirection::Backward)
}
