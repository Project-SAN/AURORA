pub mod backward;
pub mod exit;
pub mod forward;
pub mod pipeline;

use alloc::collections::BTreeSet;

use crate::node::pipeline::ForwardPipeline;
use crate::policy::{PolicyId, PolicyRole};
use crate::sphinx::*;
use crate::types::{Chdr, Result, RoutingSegment, Sv};
use alloc::collections::BTreeMap;
pub use exit::ExitTransport;

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
    pub roles: &'a BTreeMap<PolicyId, PolicyRole>,
}

pub struct NodeCtx<'p, 'io, 'e> {
    pub sv: Sv,
    pub now: &'io dyn crate::time::TimeProvider,
    // Forwarding abstraction: implementor sends to next hop
    pub forward: &'io mut dyn crate::forward::Forward,
    pub replay: &'io mut dyn ReplayFilter,
    pub policy: Option<PolicyRuntime<'p>>,
    pub exit: Option<&'e mut dyn ExitTransport>,
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
