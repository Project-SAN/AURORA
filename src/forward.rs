use crate::policy::encoder::PolicySection;
use crate::types::{Ahdr, Chdr, Result, RoutingSegment};

// Minimal forwarding abstraction for no_std environments.
// Implementors encapsulate how to transmit a packet to the next hop.
pub trait Forward {
    fn send(
        &mut self,
        rseg: &RoutingSegment,
        chdr: &Chdr,
        policy: Option<&PolicySection>,
        ahdr: &Ahdr,
        payload: &mut [u8],
    ) -> Result<()>;
}

// Minimal no-op forwarder useful for testing pipelines without I/O.
pub struct NoopForward;
impl Forward for NoopForward {
    fn send(
        &mut self,
        _rseg: &RoutingSegment,
        _chdr: &Chdr,
        _policy: Option<&PolicySection>,
        _ahdr: &Ahdr,
        _payload: &mut [u8],
    ) -> Result<()> {
        Ok(())
    }
}
