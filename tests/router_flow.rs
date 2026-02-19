use hornet::core::policy::{PolicyMetadata, ProofKind, VerifierEntry};
use hornet::core::policy::{encode_extensions_into, CapsuleExtensionRef, AUX_MAX, EXT_TAG_PCD_KEY_HASH};
use hornet::forward::Forward;
use hornet::policy::zkboo::ZkBooPolicy;
use hornet::policy::zkboo::ZkBooProofService;
use hornet::router::Router;
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::time::TimeProvider;
use hornet::types::{
    Ahdr, Chdr, Exp, Nonce, PacketDirection, Result, RoutingSegment, Si, Sv, R_MAX,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
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
        self.sent.replace(Some((rseg.clone(), direction, cloned)));
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
    let ahdr = hornet::packet::ahdr::create_ahdr(&[si], &[fs], R_MAX, &mut ahdr_rng).expect("ahdr");

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
            }]),
        },
    ];
    router.install_routes(&routes).expect("install routes");
}

fn encode_capsule(capsule: &hornet::policy::PolicyCapsule) -> Vec<u8> {
    capsule.encode().expect("encode capsule")
}

fn demo_zkboo_policy() -> (hornet::crypto::zkp::Circuit, PolicyMetadata) {
    // KeyBinding circuit: expose 32 bytes (256 bits) as public output.
    let mut keybinding = hornet::crypto::zkp::Circuit::new(256);
    let outputs: Vec<usize> = (0..256).collect();
    keybinding.set_outputs(&outputs);
    let mut consistency = hornet::crypto::zkp::Circuit::new(8);
    consistency.set_outputs(&[1]);
    let mut policy_circuit = hornet::crypto::zkp::Circuit::new(8);
    policy_circuit.set_outputs(&[2]);
    let policy = ZkBooPolicy::new(policy_circuit.clone());
    let mut metadata = policy.metadata(1_700_000_600, 0);
    metadata.verifiers = vec![
        VerifierEntry {
            kind: ProofKind::KeyBinding as u8,
            verifier_blob: keybinding.encode(),
        },
        VerifierEntry {
            kind: ProofKind::Consistency as u8,
            verifier_blob: consistency.encode(),
        },
        VerifierEntry {
            kind: ProofKind::Policy as u8,
            verifier_blob: policy_circuit.encode(),
        },
    ];
    (policy_circuit, metadata)
}

#[test]
fn router_forwards_valid_capsule_and_decrypts_body() {
    let now = 1_700_000_000u32;
    let (circuit, metadata) = demo_zkboo_policy();
    let policy = ZkBooPolicy::with_policy_id(circuit, metadata.policy_id);
    let mut rng = ChaCha20Rng::seed_from_u64(0xCAFE_BEEF);
    // Policy circuit output == input bit 2.
    let capsule = policy
        .prove_with_rng(&[0, 0, 1, 0, 0, 0, 0, 0], 16, &mut rng)
        .expect("prove zkboo");

    let body_plain = b"opaque-body::payload".to_vec();

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
            None,
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
    let (circuit, metadata) = demo_zkboo_policy();
    let policy = ZkBooPolicy::with_policy_id(circuit, metadata.policy_id);
    let mut rng = ChaCha20Rng::seed_from_u64(0x1234_0001);
    let capsule = policy
        .prove_with_rng(&[0, 0, 1, 0, 0, 0, 0, 0], 16, &mut rng)
        .expect("prove zkboo");
    let mut capsule_bytes = encode_capsule(&capsule);
    capsule_bytes[4] ^= 0xFF; // flip a bit in the policy ID to break lookup

    let mut packet = build_single_hop_packet(capsule_bytes, b"opaque-body".to_vec(), now);

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
            None,
            &mut replay,
            &mut packet.chdr,
            &mut packet.ahdr,
            &mut packet.payload,
        )
        .expect_err("policy violation expected");
    assert!(matches!(err, hornet::types::Error::PolicyViolation));
    assert!(forward.take().is_none(), "forwarder should not run");
}

#[test]
fn router_entry_rejects_capsule_without_keybinding_part() {
    let now = 1_700_000_000u32;
    let (circuit, metadata) = demo_zkboo_policy();
    let policy = ZkBooPolicy::with_policy_id(circuit, metadata.policy_id);
    let mut rng = ChaCha20Rng::seed_from_u64(0x1234_5678);
    let capsule = policy
        .prove_with_rng(&[0, 0, 1, 0, 0, 0, 0, 0], 16, &mut rng)
        .expect("prove zkboo");

    let body_plain = b"opaque-body".to_vec();
    let mut packet = build_single_hop_packet(encode_capsule(&capsule), body_plain.clone(), now);

    let mut router = Router::new();
    install_role_routes(&mut router, metadata.policy_id, "router-entry");
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
            None,
            &mut replay,
            &mut packet.chdr,
            &mut packet.ahdr,
            &mut packet.payload,
        )
        .expect_err("policy violation expected");
    assert!(matches!(err, hornet::types::Error::PolicyViolation));
    assert!(forward.take().is_none(), "forwarder should not run");
}

#[test]
fn router_entry_rejects_invalid_zkboo_proof() {
    let now = 1_700_000_000u32;
    let (_circuit, metadata) = demo_zkboo_policy();

    // Entry expects KeyBinding part; an invalid/empty proof should be rejected.
    let bad_capsule = hornet::policy::PolicyCapsule {
        policy_id: metadata.policy_id,
        version: hornet::core::policy::POLICY_CAPSULE_VERSION,
        part_count: 1,
        parts: [
            hornet::policy::ProofPart {
                kind: hornet::core::policy::ProofKind::KeyBinding,
                proof: Vec::new(),
                commitment: [0u8; hornet::core::policy::COMMIT_LEN],
                aux: Vec::new(),
            },
            hornet::policy::ProofPart::default(),
            hornet::policy::ProofPart::default(),
            hornet::policy::ProofPart::default(),
        ],
    };

    let body_plain = b"opaque-body".to_vec();
    let mut packet = build_single_hop_packet(encode_capsule(&bad_capsule), body_plain, now);

    let mut router = Router::new();
    install_role_routes(&mut router, metadata.policy_id, "router-entry");
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
            None,
            &mut replay,
            &mut packet.chdr,
            &mut packet.ahdr,
            &mut packet.payload,
        )
        .expect_err("policy violation expected");
    assert!(matches!(err, hornet::types::Error::PolicyViolation));
    assert!(forward.take().is_none(), "forwarder should not run");
}

#[test]
fn router_entry_accepts_valid_keybinding_part() {
    let now = 1_700_000_000u32;
    let (_circuit, metadata) = demo_zkboo_policy();

    // The demo KeyBinding circuit exposes 32 bytes of input as the public output (hkey).
    let payload = [0xAAu8; 32];
    let hkey = payload;
    let aux = {
        let exts = [CapsuleExtensionRef {
            tag: EXT_TAG_PCD_KEY_HASH,
            data: &hkey,
        }];
        let mut buf = [0u8; AUX_MAX];
        let len = encode_extensions_into(&exts, &mut buf).expect("encode exts");
        buf[..len].to_vec()
    };
    let service = ZkBooProofService::new_with_policy_id(
        hornet::crypto::zkp::Circuit::decode(
            metadata
                .verifiers
                .iter()
                .find(|e| e.kind == ProofKind::KeyBinding as u8)
                .unwrap()
                .verifier_blob
                .as_slice(),
        )
        .unwrap(),
        metadata.policy_id,
        16,
    );
    let capsule_one = service
        .prove_payload_lsb_first(&payload, &aux)
        .expect("prove keybinding");
    let mut part = capsule_one.parts[0].clone();
    part.kind = ProofKind::KeyBinding;
    part.set_aux(&aux).expect("set aux");
    let capsule = hornet::policy::PolicyCapsule {
        policy_id: metadata.policy_id,
        version: hornet::core::policy::POLICY_CAPSULE_VERSION,
        part_count: 1,
        parts: [part, hornet::policy::ProofPart::default(), hornet::policy::ProofPart::default(), hornet::policy::ProofPart::default()],
    };

    let body_plain = b"opaque-body".to_vec();
    let mut packet = build_single_hop_packet(encode_capsule(&capsule), body_plain.clone(), now);

    let mut router = Router::new();
    install_role_routes(&mut router, metadata.policy_id, "router-entry");
    router.install_policies(&[metadata.clone()]).expect("install policy");

    let time = FixedTime(now);
    let mut forward = RecordingForward::default();
    let mut replay = hornet::node::NoReplay;

    router
        .process_forward_packet(
            packet.sv,
            &time,
            &mut forward,
            None,
            &mut replay,
            &mut packet.chdr,
            &mut packet.ahdr,
            &mut packet.payload,
        )
        .expect("forward packet");
    assert!(forward.take().is_some(), "payload forwarded");
}
