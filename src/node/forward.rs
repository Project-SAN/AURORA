use alloc::vec::Vec;

use crate::{
    node::NodeCtx,
    packet::{ahdr::proc_ahdr, onion},
    routing::{self, RouteElem},
    sphinx::derive_tau_tag,
    types::{Ahdr, Chdr, Error, Exp, PacketType, RoutingSegment, Sv},
};
#[cfg(feature = "std")]
use std::io::{Read, Write};
#[cfg(feature = "std")]
use std::net::TcpStream;
pub type Result<T> = core::result::Result<T, Error>;

pub fn process_data(
    ctx: &mut NodeCtx,
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
    let policy = ctx.policy.ok_or(Error::PolicyViolation)?;
    let (capsule, capsule_len) = policy
        .forward
        .enforce(policy.registry, payload, policy.validator)?
        .ok_or(Error::PolicyViolation)?;
    if let Some(expected) = policy.expected_policy_id {
        if capsule.policy_id != expected {
            return Err(Error::PolicyViolation);
        }
    }

    use crate::types::PacketDirection;

    let mut iv = chdr.specific;
    if capsule_len >= payload.len() {
        // nothing beyond the capsule to decrypt for the next hop
        chdr.specific = iv;
        return ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload, PacketDirection::Forward);
    }

    let tail = &mut payload[capsule_len..];
    onion::remove_layer(&res.s, &mut iv, tail)?;
    chdr.specific = iv;
    if let Ok(elems) = routing::elems_from_segment(&res.r) {
        if let Some(RouteElem::ExitTcp { addr, port, .. }) = elems.first() {
            if let Some((ahdr_bytes, request)) = parse_exit_payload(tail) {
                #[cfg(feature = "std")]
                {
                    return handle_exit_tcp(ctx, chdr, addr, *port, ahdr_bytes, request);
                }
                #[cfg(not(feature = "std"))]
                {
                    let _ = addr;
                    let _ = port;
                    let _ = ahdr_bytes;
                    let _ = request;
                    return Err(Error::NotImplemented);
                }
            }
        }
    }

    ctx.forward.send(&res.r, chdr, &res.ahdr_next, payload, PacketDirection::Forward)
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

#[cfg(feature = "std")]
fn handle_exit_tcp(
    ctx: &mut NodeCtx,
    chdr: &mut Chdr,
    addr: &crate::routing::IpAddr,
    port: u16,
    ahdr_bytes: Vec<u8>,
    request: &[u8],
) -> Result<()> {
    let mut stream = TcpStream::connect(format_exit_addr(addr, port)).map_err(|_| Error::Crypto)?;
    stream.write_all(request).map_err(|_| Error::Crypto)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|_| Error::Crypto)?;

    let mut ahdr_b = Ahdr { bytes: ahdr_bytes };
    let mut chdr_b = Chdr {
        typ: PacketType::Data,
        hops: chdr.hops,
        specific: chdr.specific,
    };

    crate::node::backward::process_data(ctx, &mut chdr_b, &mut ahdr_b, &mut response)
}

fn parse_blocklist_leaf_len(bytes: &[u8]) -> Result<usize> {
    if bytes.is_empty() {
        return Err(Error::Length);
    }
    match bytes[0] {
        0x01 | 0x02 => {
            if bytes.len() < 1 + 4 {
                return Err(Error::Length);
            }
            let mut len_buf = [0u8; 4];
            len_buf.copy_from_slice(&bytes[1..5]);
            let len = u32::from_be_bytes(len_buf) as usize;
            let total = 1 + 4 + len;
            if bytes.len() < total {
                return Err(Error::Length);
            }
            Ok(total)
        }
        0x03 => {
            if bytes.len() < 3 {
                return Err(Error::Length);
            }
            let net_len = match bytes[1] {
                4 => 4,
                6 => 16,
                _ => return Err(Error::Length),
            };
            let total = 1 + 1 + 1 + net_len;
            if bytes.len() < total {
                return Err(Error::Length);
            }
            Ok(total)
        }
        0x04 => {
            if bytes.len() < 1 + 4 {
                return Err(Error::Length);
            }
            let mut len_buf = [0u8; 4];
            len_buf.copy_from_slice(&bytes[1..5]);
            let start_len = u32::from_be_bytes(len_buf) as usize;
            let cursor = 1 + 4 + start_len;
            if bytes.len() < cursor + 4 {
                return Err(Error::Length);
            }
            len_buf.copy_from_slice(&bytes[cursor..cursor + 4]);
            let end_len = u32::from_be_bytes(len_buf) as usize;
            let total = cursor + 4 + end_len;
            if bytes.len() < total {
                return Err(Error::Length);
            }
            Ok(total)
        }
        _ => Err(Error::Length),
    }
}

fn parse_exit_payload(tail: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let (leaf_len, offset) = if let Ok(len) = parse_blocklist_leaf_len(tail) {
        (len, 0usize)
    } else {
        if tail.len() < 4 {
            return None;
        }
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&tail[..4]);
        let len = u32::from_le_bytes(len_buf) as usize;
        (len, 4usize)
    };
    let leaf_end = offset + leaf_len;
    if tail.len() < leaf_end + 4 {
        return None;
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&tail[leaf_end..leaf_end + 4]);
    let ahdr_len = u32::from_le_bytes(len_buf) as usize;
    let ahdr_start = leaf_end + 4;
    let ahdr_end = ahdr_start + ahdr_len;
    if tail.len() < ahdr_end {
        return None;
    }
    let ahdr_bytes = tail[ahdr_start..ahdr_end].to_vec();
    let request = &tail[ahdr_end..];
    Some((ahdr_bytes, request))
}

#[cfg(feature = "std")]
fn format_exit_addr(addr: &crate::routing::IpAddr, port: u16) -> String {
    match addr {
        crate::routing::IpAddr::V4(octets) => format!(
            "{}.{}.{}.{}:{}",
            octets[0], octets[1], octets[2], octets[3], port
        ),
        crate::routing::IpAddr::V6(bytes) => {
            let mut buf = String::new();
            buf.push('[');
            for (i, chunk) in bytes.chunks(2).enumerate() {
                if i > 0 {
                    buf.push(':');
                }
                let value = u16::from_be_bytes([chunk[0], chunk[1]]);
                let _ = core::fmt::Write::write_fmt(&mut buf, format_args!("{:x}", value));
            }
            buf.push(']');
            let _ = core::fmt::Write::write_fmt(&mut buf, format_args!(":{}", port));
            buf
        }
    }
}
