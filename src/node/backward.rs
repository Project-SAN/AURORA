use alloc::vec::Vec;

use crate::{
    node::NodeCtx,
    packet::{ahdr::proc_ahdr, onion},
    sphinx::derive_tau_tag,
    types::{Ahdr, Chdr, Error, Exp},
};
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(feature = "hornet-log")]
macro_rules! hlog {
    ($($tt:tt)*) => {
        crate::log::emit(core::format_args!($($tt)*));
    };
}

#[cfg(not(feature = "hornet-log"))]
macro_rules! hlog {
    ($($tt:tt)*) => {};
}

pub fn process_data(
    ctx: &mut NodeCtx<'_, '_, '_>,
    chdr: &mut Chdr,
    ahdr: &mut Ahdr,
    payload: &mut Vec<u8>,
) -> Result<()> {
    hlog!(
        "backward: begin ahdr_len={} payload_len={}",
        ahdr.bytes.len(),
        payload.len()
    );
    let now = Exp(ctx.now.now_coarse());
    hlog!("backward: now={}", now.0);
    let res = proc_ahdr(&ctx.sv, ahdr, now)?;
    hlog!("backward: proc_ahdr ok r_len={}", res.r.0.len());
    let tau = derive_tau_tag(&res.s);
    if !ctx.replay.insert(tau) {
        hlog!("backward: replay detected");
        return Err(crate::types::Error::Replay);
    }
    hlog!("backward: replay ok");

    // Backward packets don't have policy capsules - they contain encrypted responses
    // from the exit node. We just need to add our onion layer and forward.
    use crate::types::PacketDirection;

    let mut iv = chdr.specific;
    hlog!("backward: add_layer payload_len={}", payload.len());
    onion::add_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    hlog!("backward: added onion layer payload_len={}", payload.len());
    ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload, PacketDirection::Backward)
}
