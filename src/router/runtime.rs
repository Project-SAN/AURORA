use crate::router::Router;
use crate::types::{Ahdr, Chdr, Result};
use crate::{forward::Forward, node::ReplayFilter, time::TimeProvider};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDirection {
    Forward,
    Backward,
}

/// Runtime helper that wires Router policy state into node processing loops.
pub struct RouterRuntime<'a> {
    router: &'a Router,
    time: &'a dyn TimeProvider,
    forward: &'a mut dyn Forward,
    replay: &'a mut dyn ReplayFilter,
}

impl<'a> RouterRuntime<'a> {
    pub fn new(
        router: &'a Router,
        time: &'a dyn TimeProvider,
        forward: &'a mut dyn Forward,
        replay: &'a mut dyn ReplayFilter,
    ) -> Self {
        Self {
            router,
            time,
            forward,
            replay,
        }
    }

    pub fn process(
        &mut self,
        direction: PacketDirection,
        sv: crate::types::Sv,
        mut chdr: &mut Chdr,
        mut ahdr: &mut Ahdr,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        match direction {
            PacketDirection::Forward => self.router.process_forward_packet(
                sv,
                self.time,
                self.forward,
                self.replay,
                &mut chdr,
                &mut ahdr,
                payload,
            ),
            PacketDirection::Backward => self.router.process_backward_packet(
                sv,
                self.time,
                self.forward,
                self.replay,
                &mut chdr,
                &mut ahdr,
                payload,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::NoopForward;
    use crate::node::NoReplay;
    use crate::router::Router;
    use crate::time::TimeProvider;

    struct FixedTime(u32);
    impl TimeProvider for FixedTime {
        fn now_coarse(&self) -> u32 {
            self.0
        }
    }

    #[test]
    fn runtime_constructs() {
        let router = Router::new();
        let time = FixedTime(0);
        let mut forward = NoopForward;
        let mut replay = NoReplay;
        let _runtime = RouterRuntime::new(&router, &time, &mut forward, &mut replay);
    }
}
