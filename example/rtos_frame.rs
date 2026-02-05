use hornet::core::policy::PolicyMetadata;
use hornet::forward::Forward;
use hornet::policy::blocklist::{BlocklistEntry, ValueBytes};
use hornet::policy::plonk::PlonkPolicy;
use hornet::router::frame;
use hornet::router::Router;
use hornet::time::TimeProvider;
use hornet::types::{
    Ahdr, Chdr, Exp, Nonce, PacketDirection, Result, RoutingSegment, Si, Sv, R_MAX,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
struct FixedTime(u32);
impl TimeProvider for FixedTime {
    fn now_coarse(&self) -> u32 {
        self.0
    }
}

#[derive(Default)]
struct RecordingForward {
    sent: Option<(RoutingSegment, PacketDirection, Vec<u8>)>,
}

impl RecordingForward {
    fn take(&mut self) -> Option<(RoutingSegment, PacketDirection, Vec<u8>)> {
        self.sent.take()
    }
}

impl Forward for RecordingForward {
    fn send(
        &mut self,
        rseg: &RoutingSegment,
        _chdr: &Chdr,
        _ahdr: &Ahdr,
        payload: &mut Vec<u8>,
        direction: PacketDirection,
    ) -> Result<()> {
        let mut cloned = Vec::with_capacity(payload.len());
        cloned.extend_from_slice(payload);
        self.sent = Some((rseg.clone(), direction, cloned));
        Ok(())
    }
}

struct PacketFixture {
    sv: Sv,
    chdr: Chdr,
    ahdr: Ahdr,
    payload: Vec<u8>,
    capsule_len: usize,
    capsule: Vec<u8>,
    body_plain: Vec<u8>,
}

fn build_single_hop_packet(capsule: Vec<u8>, body_plain: Vec<u8>, now: u32) -> PacketFixture {
    let mut rng = ChaCha20Rng::seed_from_u64(0xACCE55ED);
    let mut sv_bytes = [0u8; 16];
    rng.fill_bytes(&mut sv_bytes);
    let sv = Sv(sv_bytes);

    let mut si_bytes = [0u8; 16];
    rng.fill_bytes(&mut si_bytes);
    let si = Si(si_bytes);

    let mut route_bytes = vec![0xAA, 0xBB, 0xCC];
    route_bytes.resize(12, 0);
    let route = RoutingSegment(route_bytes);
    let exp = Exp(now.saturating_add(600));
    let fs = hornet::packet::core::create(&sv, &si, &route, exp).expect("fs create");

    let mut ahdr_rng = ChaCha20Rng::seed_from_u64(0xBEEF);
    let ahdr =
        hornet::packet::ahdr::create_ahdr(&[si], &[fs], R_MAX, &mut ahdr_rng).expect("ahdr");

    let mut iv0 = [0u8; 16];
    rng.fill_bytes(&mut iv0);
    let nonce = Nonce(iv0);
    let mut chdr = hornet::packet::chdr::data_header(1, nonce);

    let capsule_bytes = capsule.clone();
    let mut payload = capsule;
    let capsule_len = payload.len();
    payload.extend_from_slice(&body_plain);

    // Encrypt only the body so the capsule stays in the clear for policy checks.
    let mut iv = nonce.0;
    hornet::packet::onion::add_layer(&si, &mut iv, &mut payload[capsule_len..])
        .expect("encrypt body");
    chdr.specific = iv;

    PacketFixture {
        sv,
        chdr,
        ahdr,
        payload,
        capsule_len,
        capsule: capsule_bytes,
        body_plain,
    }
}

fn demo_policy() -> (PlonkPolicy, PolicyMetadata) {
    let blocklist = vec![
        BlocklistEntry::Exact(ValueBytes::new(b"blocked.router.test").unwrap()).leaf_bytes(),
        BlocklistEntry::Exact(ValueBytes::new(b"deny.router.test").unwrap()).leaf_bytes(),
    ];
    let policy = PlonkPolicy::new_with_blocklist(b"router-test", &blocklist).unwrap();
    let metadata = policy.metadata(1_700_000_600, 0);
    (policy, metadata)
}

fn process_one_frame(
    router: &Router,
    sv: Sv,
    rx: &[u8],
    now: u32,
) -> Result<(Vec<u8>, Option<(RoutingSegment, PacketDirection, Vec<u8>)>)> {
    let mut decoded = frame::decode_frame(rx)?;

    let time = FixedTime(now);
    let mut forward = RecordingForward::default();
    let mut replay = hornet::node::NoReplay;

    match decoded.direction {
        PacketDirection::Forward => {
            router.process_forward_packet(
                sv,
                &time,
                &mut forward,
                &mut replay,
                &mut decoded.chdr,
                &mut decoded.ahdr,
                &mut decoded.payload,
            )?;
        }
        PacketDirection::Backward => {
            router.process_backward_packet(
                sv,
                &time,
                &mut forward,
                &mut replay,
                &mut decoded.chdr,
                &mut decoded.ahdr,
                &mut decoded.payload,
            )?;
        }
    }

    let forwarded = forward.take();

    Ok((
        frame::encode_frame(
            decoded.direction,
            &decoded.chdr,
            &decoded.ahdr,
            &decoded.payload,
        ),
        forwarded,
    ))
}

fn main() -> Result<()> {
    let router = Router::new();
    let now = 1_700_000_000u32;
    let (policy, metadata) = demo_policy();
    let leaf = BlocklistEntry::Exact(ValueBytes::new(b"ok.router.test").unwrap()).leaf_bytes();
    let capsule = policy.prove_payload(leaf.as_slice()).expect("prove payload");

    let mut body_plain = leaf.to_vec();
    body_plain.extend_from_slice(b"::payload");

    let packet = build_single_hop_packet(capsule.encode(), body_plain, now);
    let mut router = router;
    router
        .install_policies(&[metadata.clone()])
        .expect("install policy");

    let rx_forward = frame::encode_frame(
        PacketDirection::Forward,
        &packet.chdr,
        &packet.ahdr,
        &packet.payload,
    );
    let (_tx_forward, forwarded) = process_one_frame(&router, packet.sv, &rx_forward, now)?;
    if let Some((rseg, direction, forwarded_payload)) = forwarded {
        let expected_body = packet.body_plain.as_slice();
        let expected_capsule = packet.capsule.as_slice();
        let capsule = if forwarded_payload.len() >= packet.capsule_len {
            &forwarded_payload[..packet.capsule_len]
        } else {
            &[]
        };
        let capsule_ok = capsule == expected_capsule;
        let body = if forwarded_payload.len() >= packet.capsule_len {
            &forwarded_payload[packet.capsule_len..]
        } else {
            &[]
        };
        let body_ok = body == expected_body;
        println!(
            "forward sent: direction={:?} route_len={} payload_len={} capsule_match={} body_match={}",
            direction,
            rseg.0.len(),
            forwarded_payload.len(),
            capsule_ok,
            body_ok
        );
        if !capsule_ok || !body_ok {
            println!(
                "forward mismatch: capsule_expected={} capsule_actual={} body_expected={} body_actual={}",
                expected_capsule.len(),
                capsule.len(),
                expected_body.len(),
                body.len()
            );
        }
    } else {
        println!("forward sent: none");
    }

    let rx_backward = frame::encode_frame(
        PacketDirection::Backward,
        &packet.chdr,
        &packet.ahdr,
        &packet.payload,
    );
    let (_tx_backward, forwarded_back) = process_one_frame(&router, packet.sv, &rx_backward, now)?;
    if let Some((rseg, direction, forwarded_payload)) = forwarded_back {
        println!(
            "backward sent: direction={:?} route_len={} payload_len={}",
            direction,
            rseg.0.len(),
            forwarded_payload.len()
        );
    } else {
        println!("backward sent: none");
    }

    Ok(())
}
