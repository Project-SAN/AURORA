pub mod backward;
pub mod forward;

use alloc::collections::BTreeSet;

use crate::application::forward::ForwardPipeline;
use crate::sphinx::*;
use crate::types::{Chdr, Result, RoutingSegment, Sv};

pub trait ReplayFilter {
    fn insert(&mut self, tag: [u8; TAU_TAG_BYTES]) -> bool;
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
    fn insert(&mut self, tag: [u8; crate::sphinx::TAU_TAG_BYTES]) -> bool {
        self.seen.insert(tag)
    }
}

pub struct NoReplay;

impl ReplayFilter for NoReplay {
    fn insert(&mut self, _tag: [u8; crate::sphinx::TAU_TAG_BYTES]) -> bool {
        true
    }
}

#[derive(Clone, Copy)]
pub struct PolicyRuntime<'a> {
    pub registry: &'a crate::policy::PolicyRegistry,
    pub validator: &'a dyn crate::policy::CapsuleValidator,
    pub forward: &'a dyn ForwardPipeline,
}

pub struct NodeCtx<'a> {
    pub sv: Sv,
    pub now: &'a dyn crate::time::TimeProvider,
    // Forwarding abstraction: implementor sends to next hop
    pub forward: &'a mut dyn crate::forward::Forward,
    pub replay: &'a mut dyn ReplayFilter,
    pub policy: Option<PolicyRuntime<'a>>,
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
