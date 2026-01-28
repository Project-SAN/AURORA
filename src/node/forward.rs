use alloc::vec::Vec;

use crate::{crypto::prg, types::PacketType};
use crate::{
    node::NodeCtx,
    packet::{ahdr::proc_ahdr, onion},
    policy::PolicyCapsule,
    routing::{self, RouteElem},
    sphinx::derive_tau_tag,
    types::{Ahdr, Chdr, Error, Exp, RoutingSegment, Sv},
};
pub type Result<T> = core::result::Result<T, Error>;

const TAG_EXACT: u8 = 0x01;
const TAG_PREFIX: u8 = 0x02;
const TAG_CIDR: u8 = 0x03;
const TAG_RANGE: u8 = 0x04;

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
    let capsule_len = if let Some(policy) = ctx.policy {
        let role = match PolicyCapsule::decode(payload.as_slice()) {
            Ok((capsule, _)) => policy
                .roles
                .get(&capsule.policy_id)
                .copied()
                .ok_or(Error::PolicyViolation)?,
            Err(_) => return Err(Error::PolicyViolation),
        };
        policy
            .forward
            .enforce(policy.registry, payload, policy.validator, role)?
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

    use crate::types::PacketDirection;

    let mut iv = chdr.specific;
    if capsule_len >= payload.len() {
        // nothing beyond the capsule to decrypt for the next hop
        chdr.specific = iv;
        return ctx.forward.send(
            &res.r,
            chdr,
            &res.ahdr_next,
            payload,
            PacketDirection::Forward,
        );
    }

    let tail = &mut payload[capsule_len..];
    onion::remove_layer(&res.s, &mut iv, tail)?;
    chdr.specific = iv;

    if let Ok(elems) = routing::elems_from_segment(&res.r) {
        if let Some(RouteElem::ExitTcp { addr, port, tls }) = elems.first() {
            let mut exit = ctx.exit.take();
            let res = if let Some(exit) = exit.as_deref_mut() {
                handle_exit(ctx, exit, addr, *port, *tls, chdr.hops, tail)
            } else {
                Err(Error::NotImplemented)
            };
            ctx.exit = exit;
            return res;
        }
    }

    ctx.forward.send(
        &res.r,
        chdr,
        &res.ahdr_next,
        payload,
        PacketDirection::Forward,
    )
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

fn handle_exit(
    ctx: &mut NodeCtx<'_, '_, '_>,
    exit: &mut dyn crate::node::ExitTransport,
    addr: &crate::routing::IpAddr,
    port: u16,
    tls: bool,
    hops: u8,
    tail: &mut [u8],
) -> Result<()> {
    let canonical_len = leaf_len(tail)?;
    let mut cursor = canonical_len;
    if cursor + 4 > tail.len() {
        return Err(Error::Length);
    }
    let ahdr_len = u32::from_le_bytes([
        tail[cursor],
        tail[cursor + 1],
        tail[cursor + 2],
        tail[cursor + 3],
    ]) as usize;
    cursor += 4;
    if cursor + ahdr_len > tail.len() {
        return Err(Error::Length);
    }
    let ahdr_bytes = tail[cursor..cursor + ahdr_len].to_vec();
    cursor += ahdr_len;
    let request = &tail[cursor..];

    let mut response = exit.send(addr, port, tls, request)?;

    let mut ahdr_b = Ahdr { bytes: ahdr_bytes };
    let mut chdr_b = Chdr {
        typ: PacketType::Data,
        hops,
        specific: derive_exit_iv(ctx, &ahdr_b),
    };

    crate::node::backward::process_data(ctx, &mut chdr_b, &mut ahdr_b, &mut response)
}

fn derive_exit_iv(ctx: &NodeCtx<'_, '_, '_>, ahdr: &Ahdr) -> [u8; 16] {
    let now = Exp(ctx.now.now_coarse());
    if let Ok(res) = proc_ahdr(&ctx.sv, ahdr, now) {
        let mut iv = [0u8; 16];
        prg::prg1(&res.s.0, &mut iv);
        iv
    } else {
        [0u8; 16]
    }
}

fn leaf_len(bytes: &[u8]) -> Result<usize> {
    if bytes.is_empty() {
        return Err(Error::Length);
    }
    match bytes[0] {
        TAG_EXACT | TAG_PREFIX => {
            if bytes.len() < 5 {
                return Err(Error::Length);
            }
            let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
            Ok(1 + 4 + len)
        }
        TAG_CIDR => {
            if bytes.len() < 3 {
                return Err(Error::Length);
            }
            let version = bytes[1];
            let ip_len = match version {
                4 => 4,
                6 => 16,
                _ => return Err(Error::Length),
            };
            Ok(1 + 1 + 1 + ip_len)
        }
        TAG_RANGE => {
            if bytes.len() < 5 {
                return Err(Error::Length);
            }
            let len_a = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
            let start = 1 + 4;
            let mid = start + len_a;
            if bytes.len() < mid + 4 {
                return Err(Error::Length);
            }
            let len_b =
                u32::from_be_bytes([bytes[mid], bytes[mid + 1], bytes[mid + 2], bytes[mid + 3]])
                    as usize;
            Ok(1 + 4 + len_a + 4 + len_b)
        }
        _ => Err(Error::Length),
    }
}
