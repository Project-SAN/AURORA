use crate::router::Router;
use crate::types::{Ahdr, Chdr, Result, PacketDirection};
use crate::{forward::Forward, node::ReplayFilter, time::TimeProvider};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;

/// Runtime helper that wires Router policy state into node processing loops.
pub struct RouterRuntime<'a> {
    router: &'a Router,
    time: &'a dyn TimeProvider,
    forward_factory: Rc<dyn Fn() -> Box<dyn Forward + 'a> + 'a>,
    replay_factory: Rc<dyn Fn() -> Box<dyn ReplayFilter + 'a> + 'a>,
}

impl<'a> RouterRuntime<'a> {
    pub fn new<FwdFactory, RepFactory>(
        router: &'a Router,
        time: &'a dyn TimeProvider,
        forward_factory: FwdFactory,
        replay_factory: RepFactory,
    ) -> Self
    where
        FwdFactory: Fn() -> Box<dyn Forward + 'a> + 'a,
        RepFactory: Fn() -> Box<dyn ReplayFilter + 'a> + 'a,
    {
        Self {
            router,
            time,
            forward_factory: Rc::new(forward_factory),
            replay_factory: Rc::new(replay_factory),
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
        let mut forward = (self.forward_factory)();
        let mut replay = (self.replay_factory)();
        match direction {
            PacketDirection::Forward => self.router.process_forward_packet(
                sv,
                self.time,
                forward.as_mut(),
                replay.as_mut(),
                &mut chdr,
                &mut ahdr,
                payload,
            ),
            PacketDirection::Backward => self.router.process_backward_packet(
                sv,
                self.time,
                forward.as_mut(),
                replay.as_mut(),
                &mut chdr,
                &mut ahdr,
                payload,
            ),
        }
    }

    pub fn drain_pending(&mut self) -> Result<Vec<crate::policy::PolicyCapsule>> {
        self.router.drain_pending()
    }

    pub fn handle_async_violations(&mut self) -> Result<crate::router::penalty::AsyncActions> {
        self.router.handle_async_violations()
    }
}

pub mod forward {
    use super::Forward;
    use crate::types::{Ahdr, Chdr, Result, RoutingSegment};
    use alloc::collections::VecDeque;
    use alloc::vec::Vec;

    /// Simple in-memory forwarder useful for tests and simulations.
    pub struct LoopbackForward {
        queue: VecDeque<Vec<u8>>,
    }

    impl LoopbackForward {
        pub fn new() -> Self {
            Self {
                queue: VecDeque::new(),
            }
        }

        pub fn pop(&mut self) -> Option<Vec<u8>> {
            self.queue.pop_front()
        }
    }

    impl Forward for LoopbackForward {
        fn send(
            &mut self,
            _rseg: &RoutingSegment,
            _chdr: &Chdr,
            _ahdr: &Ahdr,
            payload: &mut Vec<u8>,
            _direction: crate::types::PacketDirection,
        ) -> Result<()> {
            let mut owned = Vec::with_capacity(payload.len());
            owned.extend_from_slice(payload);
            self.queue.push_back(owned);
            Ok(())
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::node::NoReplay;
    use crate::router::runtime::forward::LoopbackForward;
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
        let _runtime = RouterRuntime::new(
            &router,
            &time,
            || Box::new(LoopbackForward::new()),
            || Box::new(NoReplay),
        );
    }
}
