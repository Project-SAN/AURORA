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
    if capsule_len <= payload.len() {
        payload.drain(0..capsule_len);
    }
    let prefix_len = capsule_prefix_len(payload);
    if prefix_len < payload.len() {
        let tail = &mut payload[prefix_len..];
        onion::remove_layer(&res.s, &mut iv, tail)?;
    }
    chdr.specific = iv;
    if let Ok(elems) = routing::elems_from_segment(&res.r) {
        if let Some(RouteElem::ExitTcp { addr, port, .. }) = elems.first() {
            if let Some((ahdr_bytes, request)) = parse_exit_payload(&payload[prefix_len..]) {
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

fn capsule_prefix_len(payload: &[u8]) -> usize {
    let mut offset = 0usize;
    while offset < payload.len() {
        match crate::policy::PolicyCapsule::decode(&payload[offset..]) {
            Ok((_capsule, consumed)) if consumed > 0 => {
                offset = offset.saturating_add(consumed);
            }
            _ => break,
        }
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rand::rngs::SmallRng;
    use rand::{RngCore, SeedableRng};

    use crate::application::forward::RegistryForwardPipeline;
    use crate::policy::{CapsuleValidator, PolicyCapsule, PolicyMetadata, PolicyRegistry};
    use crate::routing::{self, IpAddr, RouteElem};
    use crate::types::{Chdr, Nonce, PacketDirection, RoutingSegment};

    struct AllowAllValidator;

    impl CapsuleValidator for AllowAllValidator {
        fn validate(&self, _capsule: &PolicyCapsule, _metadata: &PolicyMetadata) -> Result<()> {
            Ok(())
        }
    }

    struct FixedTimeProvider {
        now: u32,
    }

    impl crate::time::TimeProvider for FixedTimeProvider {
        fn now_coarse(&self) -> u32 {
            self.now
        }
    }

    struct RecordingForward {
        expected_policy_id: [u8; 32],
        expected_message: Vec<u8>,
        called: bool,
    }

    impl RecordingForward {
        fn new(expected_policy_id: [u8; 32], expected_message: Vec<u8>) -> Self {
            Self {
                expected_policy_id,
                expected_message,
                called: false,
            }
        }
    }

    impl crate::forward::Forward for RecordingForward {
        fn send(
            &mut self,
            _rseg: &RoutingSegment,
            _chdr: &Chdr,
            _ahdr: &Ahdr,
            payload: &mut Vec<u8>,
            _direction: PacketDirection,
        ) -> Result<()> {
            let (capsule, consumed) =
                PolicyCapsule::decode(payload.as_slice()).expect("capsule decode");
            assert_eq!(capsule.policy_id, self.expected_policy_id);
            assert_eq!(&payload[consumed..], self.expected_message.as_slice());
            self.called = true;
            Ok(())
        }
    }

    struct PanicForward;

    impl crate::forward::Forward for PanicForward {
        fn send(
            &mut self,
            _rseg: &RoutingSegment,
            _chdr: &Chdr,
            _ahdr: &Ahdr,
            _payload: &mut Vec<u8>,
            _direction: PacketDirection,
        ) -> Result<()> {
            panic!("forward should not be called");
        }
    }

    fn deliver_route() -> RoutingSegment {
        routing::segment_from_elems(&[RouteElem::NextHop {
            addr: IpAddr::V4([127, 0, 0, 1]),
            port: 9999,
        }])
    }

    fn build_single_hop_packet(
        message_plain: &[u8],
        exp: crate::types::Exp,
    ) -> (crate::types::Sv, Ahdr, Chdr, Vec<u8>, crate::types::Si) {
        let mut rng = SmallRng::seed_from_u64(0xA55A_5AA5);
        let mut sv_bytes = [0u8; 16];
        rng.fill_bytes(&mut sv_bytes);
        let sv = crate::types::Sv(sv_bytes);

        let mut si_bytes = [0u8; 16];
        rng.fill_bytes(&mut si_bytes);
        let si = crate::types::Si(si_bytes);

        let route = deliver_route();
        let fs = crate::packet::core::create(&sv, &si, &route, exp).expect("fs create");
        let mut rng_ahdr = SmallRng::seed_from_u64(0x1CEB_00DA);
        let ahdr =
            crate::packet::ahdr::create_ahdr(&[si], &[fs], crate::types::R_MAX, &mut rng_ahdr)
                .expect("create ahdr");

        let mut nonce_bytes = [0u8; 16];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce(nonce_bytes);
        let mut chdr = crate::packet::chdr::data_header(1, nonce);

        let mut encrypted_tail = message_plain.to_vec();
        let mut iv_for_build = nonce;
        crate::source::build(&mut chdr, &ahdr, &[si], &mut iv_for_build, &mut encrypted_tail)
            .expect("build payload");

        (sv, Ahdr { bytes: ahdr.bytes }, chdr, encrypted_tail, si)
    }

    #[test]
    fn expected_policy_id_mismatch_rejects() {
        let policy_id = [0x11; 32];
        let mut registry = PolicyRegistry::new();
        registry
            .register(PolicyMetadata {
                policy_id,
                version: 1,
                expiry: 0,
                flags: 0,
                verifier_blob: vec![],
            })
            .expect("register");
        let validator = AllowAllValidator;
        let forward_pipeline = RegistryForwardPipeline::new();

        let exp = crate::types::Exp(1_700_000_600);
        let (sv, mut ahdr, mut chdr, encrypted_tail, _si) =
            build_single_hop_packet(b"test", exp);
        let capsule = PolicyCapsule {
            policy_id,
            version: 1,
            proof: vec![1, 2],
            commitment: vec![],
            aux: vec![],
        };
        let mut payload = capsule.encode();
        payload.extend_from_slice(&encrypted_tail);

        let mut forward = PanicForward;
        let mut replay = crate::node::NoReplay;
        let time = FixedTimeProvider { now: 1_700_000_000 };
        let mut ctx = crate::node::NodeCtx {
            sv,
            now: &time,
            forward: &mut forward,
            replay: &mut replay,
            policy: Some(crate::node::PolicyRuntime {
                registry: &registry,
                validator: &validator,
                forward: &forward_pipeline,
                expected_policy_id: Some([0x22; 32]),
            }),
        };

        let err = process_data(&mut ctx, &mut chdr, &mut ahdr, &mut payload)
            .expect_err("expected policy violation");
        assert!(matches!(err, Error::PolicyViolation));
    }

    #[test]
    fn strips_first_capsule_and_preserves_next() {
        let policy_open = [0x11; 32];
        let policy_next = [0x22; 32];

        let mut registry = PolicyRegistry::new();
        registry
            .register(PolicyMetadata {
                policy_id: policy_open,
                version: 1,
                expiry: 0,
                flags: 0,
                verifier_blob: vec![],
            })
            .expect("register");
        let validator = AllowAllValidator;
        let forward_pipeline = RegistryForwardPipeline::new();

        let message_plain = b"hello-next-hop";
        let exp = crate::types::Exp(1_700_000_600);
        let (sv, mut ahdr, mut chdr, encrypted_tail, _si) =
            build_single_hop_packet(message_plain, exp);

        let capsule_open = PolicyCapsule {
            policy_id: policy_open,
            version: 1,
            proof: vec![0xAA],
            commitment: vec![],
            aux: vec![],
        };
        let capsule_next = PolicyCapsule {
            policy_id: policy_next,
            version: 1,
            proof: vec![0xBB],
            commitment: vec![],
            aux: vec![],
        };

        let mut payload = capsule_open.encode();
        payload.extend_from_slice(&capsule_next.encode());
        payload.extend_from_slice(&encrypted_tail);

        let mut forward = RecordingForward::new(policy_next, message_plain.to_vec());
        let mut replay = crate::node::NoReplay;
        let time = FixedTimeProvider { now: 1_700_000_000 };
        let mut ctx = crate::node::NodeCtx {
            sv,
            now: &time,
            forward: &mut forward,
            replay: &mut replay,
            policy: Some(crate::node::PolicyRuntime {
                registry: &registry,
                validator: &validator,
                forward: &forward_pipeline,
                expected_policy_id: Some(policy_open),
            }),
        };

        process_data(&mut ctx, &mut chdr, &mut ahdr, &mut payload)
            .expect("process forward");
        assert!(forward.called);
    }
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
