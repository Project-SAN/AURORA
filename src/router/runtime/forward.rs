use crate::forward::Forward;
use crate::types::{Ahdr, Chdr, Result, RoutingSegment};
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// In-memory Forward implementation used for testing or single-node simulations.
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
    ) -> Result<()> {
        let mut owned = Vec::with_capacity(payload.len());
        owned.extend_from_slice(payload);
        self.queue.push_back(owned);
        Ok(())
    }
}
