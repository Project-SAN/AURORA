use hornet::core::policy::PolicyMetadata;
use hornet::forward::Forward;
use hornet::policy::blocklist::{BlocklistEntry, ValueBytes};
use hornet::policy::plonk::PlonkPolicy;
use hornet::router::Router;
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::time::TimeProvider;
use hornet::types::{
    Ahdr, Chdr, Exp, Nonce, PacketDirection, Result, RoutingSegment, Si, Sv, R_MAX,
};
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::cell::RefCell;

struct FixedTime(u32);

impl TimeProvider for FixedTime {
    fn now_coarse(&self) -> u32 {
        self.0
    }
}

#[derive(Default)]
struct RecordingForward {
    sent: RefCell<Option<(RoutingSegment, PacketDirection, Vec<u8>)>>,
}

impl RecordingForward {
    fn take(&self) -> Option<(RoutingSegment, PacketDirection, Vec<u8>)> {
        self.sent.borrow_mut().take()
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
        self.sent
            .replace(Some((rseg.clone(), direction, cloned)));
        Ok(())
    }
}

struct PacketFixture {
    sv: Sv,
    chdr: Chdr,
    ahdr: Ahdr,
    payload: Vec<u8>,
    route: RoutingSegment,
    capsule_len: usize,
    capsule: Vec<u8>,
    body_plain: Vec<u8>,
}

fn build_single_hop_packet(
    capsule: Vec<u8>,
    body_plain: Vec<u8>,
    now: u32,
) -> PacketFixture {
    let mut rng = SmallRng::seed_from_u64(0xACCE55ED);
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

    let mut ahdr_rng = SmallRng::seed_from_u64(0xBEEF);
    let ahdr =
        hornet::packet::ahdr::create_ahdr(&[si], &[fs], R_MAX, &mut ahdr_rng).expect("ahdr");

    let mut iv0 = [0u8; 16];
    rng.fill_bytes(&mut iv0);
    let nonce = Nonce(iv0);
    let mut chdr = hornet::packet::chdr::data_header(1, nonce);

    let capsule_len = capsule.len();
    let mut payload = capsule;
    payload.extend_from_slice(&body_plain);
    let capsule_bytes = payload[..capsule_len].to_vec();

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
        route,
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

fn install_role_routes(router: &mut Router, policy_id: [u8; 32], node_id: &str) {
    router.set_node_id(Some(node_id.to_string()));
    let routes = vec![
        hornet::setup::directory::RouteAnnouncement {
            policy_id,
            interface: Some("router-entry".to_string()),
            segment: routing::segment_from_elems(&[RouteElem::NextHop {
                addr: IpAddr::V4([127, 0, 0, 1]),
                port: 7001,
            }]),
        },
        hornet::setup::directory::RouteAnnouncement {
            policy_id,
            interface: Some("router-middle".to_string()),
            segment: routing::segment_from_elems(&[RouteElem::NextHop {
                addr: IpAddr::V4([127, 0, 0, 1]),
                port: 7002,
            }]),
        },
        hornet::setup::directory::RouteAnnouncement {
            policy_id,
            interface: Some("router-exit".to_string()),
            segment: routing::segment_from_elems(&[RouteElem::ExitTcp {
                addr: IpAddr::V4([127, 0, 0, 1]),
                port: 7003,
                tls: false,
            }]),
        },
    ];
    router.install_routes(&routes).expect("install routes");
}

fn encode_capsule(capsule: &hornet::policy::PolicyCapsule) -> Vec<u8> {
    let mut buf = [0u8; hornet::core::policy::MAX_CAPSULE_LEN];
    let len = capsule.encode_into(&mut buf).expect("encode capsule");
    buf[..len].to_vec()
}

#[test]
fn router_forwards_valid_capsule_and_decrypts_body() {
    let now = 1_700_000_000u32;
    let (policy, metadata) = demo_policy();
    let leaf = BlocklistEntry::Exact(ValueBytes::new(b"ok.router.test").unwrap()).leaf_bytes();
    let capsule = policy.prove_payload(leaf.as_slice()).expect("prove payload");

    let mut body_plain = leaf.to_vec();
    body_plain.extend_from_slice(b"::payload");

    let mut packet = build_single_hop_packet(encode_capsule(&capsule), body_plain.clone(), now);

    let mut router = Router::new();
    install_role_routes(&mut router, metadata.policy_id, "router-exit");
    router
        .install_policies(&[metadata.clone()])
        .expect("install policy");

    let time = FixedTime(now);
    let mut forward = RecordingForward::default();
    let mut replay = hornet::node::NoReplay;

    router
        .process_forward_packet(
            packet.sv,
            &time,
            &mut forward,
            &mut replay,
            &mut packet.chdr,
            &mut packet.ahdr,
            &mut packet.payload,
        )
        .expect("forward packet");

    let (rseg, direction, forwarded) = forward.take().expect("payload forwarded");
    assert_eq!(direction, PacketDirection::Forward);
    assert_eq!(rseg.0, packet.route.0);
    assert_eq!(&forwarded[..packet.capsule_len], packet.capsule.as_slice());
    assert_eq!(
        &forwarded[packet.capsule_len..],
        packet.body_plain.as_slice()
    );
}

#[test]
fn router_rejects_capsule_with_unknown_policy_id() {
    let now = 1_700_000_000u32;
    let (policy, metadata) = demo_policy();
    let leaf = BlocklistEntry::Exact(ValueBytes::new(b"ok.router.test").unwrap()).leaf_bytes();
    let capsule = policy.prove_payload(leaf.as_slice()).expect("prove payload");
    let mut capsule_bytes = encode_capsule(&capsule);
    capsule_bytes[4] ^= 0xFF; // flip a bit in the policy ID to break lookup

    let mut packet = build_single_hop_packet(capsule_bytes, leaf.to_vec(), now);

    let mut router = Router::new();
    install_role_routes(&mut router, metadata.policy_id, "router-exit");
    router
        .install_policies(&[metadata.clone()])
        .expect("install policy");

    let time = FixedTime(now);
    let mut forward = RecordingForward::default();
    let mut replay = hornet::node::NoReplay;

    let err = router
        .process_forward_packet(
            packet.sv,
            &time,
            &mut forward,
            &mut replay,
            &mut packet.chdr,
            &mut packet.ahdr,
            &mut packet.payload,
        )
        .expect_err("policy violation expected");
    assert!(matches!(err, hornet::types::Error::PolicyViolation));
    assert!(forward.take().is_none(), "forwarder should not run");
}
