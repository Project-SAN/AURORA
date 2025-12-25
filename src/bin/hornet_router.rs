use hornet::node::NoReplay;
use hornet::policy::{decode_metadata_tlv, PolicyMetadata, POLICY_METADATA_TLV};
use hornet::router::config::RouterConfig;
use hornet::router::io::{
    IncomingPacket, PacketListener, RejectReason, TcpForward, TcpPacketListener,
    write_reject_frame,
};
use hornet::router::runtime::RouterRuntime;
use hornet::router::storage::{FileRouterStorage, RouterStorage, StoredState};
use hornet::router::sync::client::{sync_once, DirectoryClient};
use hornet::router::Router;
use hornet::setup::wire;
use hornet::time::SystemTimeProvider;
use hornet::types::{self, PacketType, Result as HornetResult};
use std::env;

fn main() {
    let config = RouterConfig::from_env().unwrap_or_else(|err| {
        eprintln!("invalid config: {:?}", err);
        std::process::exit(1);
    });
    if let Err(err) = config.validate() {
        eprintln!("invalid config: {:?}", err);
        std::process::exit(1);
    }
    let storage = FileRouterStorage::new(&config.storage_path);
    let mut router = Router::new();
    let secrets = load_state(&storage, &mut router);
    let directory_path =
        env::var("HORNET_DIRECTORY_PATH").unwrap_or_else(|_| "directory.json".into());
    let file_client = LocalFileClient::new(directory_path);
    if let Err(err) = sync_once(&mut router, &config, &file_client) {
        eprintln!("directory sync failed: {:?}", err);
    } else {
        persist_state(&storage, &router, &secrets);
    }
    let time = SystemTimeProvider;
    let bind_addr = env::var("HORNET_ROUTER_BIND").unwrap_or_else(|_| "127.0.0.1:7000".into());
    let mut listener = TcpPacketListener::bind(&bind_addr, secrets.sv).expect("bind listener");
    loop {
        match listener.next() {
            Ok(mut connection) => {
                if connection.packet.chdr.typ == PacketType::Setup {
                    if let Err(err) =
                        handle_setup_packet(&connection.packet, &mut router, &storage, &secrets)
                    {
                        eprintln!("setup packet handling failed: {:?}", err);
                        if err == types::Error::PolicyViolation {
                            let _ = write_reject_frame(
                                &mut connection.stream,
                                RejectReason::PolicyViolation,
                                None,
                            );
                        }
                    }
                    continue;
                }
                let mut runtime = RouterRuntime::new(
                    &router,
                    &time,
                    move || Box::new(TcpForward::new()),
                    || Box::new(NoReplay),
                );
                if let Err(err) = runtime.process(
                    connection.packet.direction,
                    connection.packet.sv,
                    &mut connection.packet.chdr,
                    &mut connection.packet.ahdr,
                    &mut connection.packet.payload,
                ) {
                    eprintln!("packet processing failed: {:?}", err);
                    eprintln!("  direction: {:?}, hops: {}, ahdr_len: {}, payload_len: {}", 
                              connection.packet.direction, connection.packet.chdr.hops, 
                              connection.packet.ahdr.bytes.len(), connection.packet.payload.len());
                    if err == types::Error::PolicyViolation {
                        let _ = write_reject_frame(
                            &mut connection.stream,
                            RejectReason::PolicyViolation,
                            None,
                        );
                    }
                }
            }
            Err(err) => {
                eprintln!("listener error: {err:?}");
                break;
            }
        }
    }
}

struct RouterSecrets {
    sv: types::Sv,
    node_secret: [u8; 32],
}

impl RouterSecrets {
    fn new(sv: types::Sv, node_secret: [u8; 32]) -> Self {
        Self { sv, node_secret }
    }
}

fn load_state(storage: &dyn RouterStorage, router: &mut Router) -> RouterSecrets {
    match storage.load() {
        Ok(state) => {
            let (policies, routes, sv, node_secret) = state.into_parts();
            if let Err(err) = router.install_policies(&policies) {
                eprintln!("failed to install stored policies: {:?}", err);
            }
            if let Err(err) = router.install_routes(&routes) {
                eprintln!("failed to install stored routes: {:?}", err);
            }
            RouterSecrets::new(sv, node_secret)
        }
        Err(_) => RouterSecrets::new(types::Sv([0xAA; 16]), [0x11; 32]),
    }
}

fn persist_state(storage: &dyn RouterStorage, router: &Router, secrets: &RouterSecrets) {
    let state = StoredState::new(
        router.policies(),
        router.routes(),
        secrets.sv,
        secrets.node_secret,
    );
    if let Err(err) = storage.save(&state) {
        eprintln!("failed to persist router state: {:?}", err);
    }
}

fn handle_setup_packet(
    packet: &IncomingPacket,
    router: &mut Router,
    storage: &dyn RouterStorage,
    secrets: &RouterSecrets,
) -> HornetResult<()> {
    if packet.chdr.typ != PacketType::Setup {
        return Err(types::Error::Length);
    }
    let mut setup_packet = wire::decode(
        packet.chdr,
        &packet.ahdr.bytes,
        &packet.payload,
    )?;
    let policy_meta =
        select_policy_metadata(&setup_packet).ok_or(types::Error::PolicyViolation)?;
    let registry_meta = router
        .registry()
        .get(&policy_meta.policy_id)
        .ok_or(types::Error::PolicyViolation)?;
    if registry_meta != &policy_meta {
        return Err(types::Error::PolicyViolation);
    }
    let route_segment = router
        .route_for_policy(&policy_meta.policy_id)
        .cloned()
        .map(|route| route.segment)
        .ok_or(types::Error::NotImplemented)?;
    hornet::setup::node_process_with_policy(
        &mut setup_packet,
        &secrets.node_secret,
        &secrets.sv,
        &route_segment,
        None,
    )?;
    persist_state(storage, router, secrets);
    Ok(())
}

fn select_policy_metadata(packet: &hornet::setup::SetupPacket) -> Option<PolicyMetadata> {
    for tlv in &packet.tlvs {
        if tlv.first().copied() != Some(POLICY_METADATA_TLV) {
            continue;
        }
        if let Ok(meta) = decode_metadata_tlv(tlv) {
            return Some(meta);
        }
    }
    None
}

struct LocalFileClient {
    path: String,
}

impl LocalFileClient {
    fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl DirectoryClient for LocalFileClient {
    fn fetch_signed(&self) -> hornet::types::Result<String> {
        std::fs::read_to_string(&self.path).map_err(|_| hornet::types::Error::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hornet::policy::PolicyMetadata;
    use hornet::setup::directory::RouteAnnouncement;
    use hornet::types::{self, PacketDirection, RoutingSegment};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::RngCore;
    use serde_json;
    use std::sync::Mutex;
    use x25519_dalek::x25519;

    #[derive(Default)]
    struct MemoryStorage {
        blob: Mutex<Option<Vec<u8>>>,
    }

    impl RouterStorage for MemoryStorage {
        fn load(&self) -> HornetResult<StoredState> {
            let guard = self.blob.lock().unwrap();
            match guard.as_ref() {
                Some(bytes) => serde_json::from_slice(bytes).map_err(|_| types::Error::Crypto),
                None => Err(types::Error::Crypto),
            }
        }

        fn save(&self, state: &StoredState) -> HornetResult<()> {
            let data = serde_json::to_vec(state).map_err(|_| types::Error::Crypto)?;
            let mut guard = self.blob.lock().unwrap();
            *guard = Some(data);
            Ok(())
        }
    }

    #[test]
    fn setup_packet_installs_policy_and_persists_state() {
        let mut router = Router::new();
        let policy = PolicyMetadata {
            policy_id: [0x42; 32],
            version: 1,
            expiry: 1_700_000_000,
            flags: 0,
            verifier_blob: vec![0xAA, 0xBB],
        };
        let route = RouteAnnouncement {
            policy_id: policy.policy_id,
            segment: RoutingSegment(vec![0x01, 0x02, 0x03]),
            interface: None,
        };
        router.install_policies(&[policy.clone()]).expect("install policy");
        router.install_routes(&[route]).expect("install route");

        let mut node_secret = [0x55; 32];
        node_secret[0] &= 248;
        node_secret[31] &= 127;
        node_secret[31] |= 64;
        let node_pub = x25519(node_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut rng = ChaCha20Rng::seed_from_u64(0xDEADBEEF);
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let mut state =
            hornet::setup::source_init(&x_s, &[node_pub], 1, types::Exp(1234), &mut rng);
        state.attach_policy_metadata(&policy);
        let encoded = wire::encode(&state.packet).expect("encode setup");
        let chdr = types::Chdr {
            typ: PacketType::Setup,
            hops: state.packet.chdr.hops,
            specific: state.packet.chdr.specific,
        };
        let incoming = IncomingPacket {
            direction: PacketDirection::Forward,
            sv: types::Sv([0x33; 16]),
            chdr,
            ahdr: types::Ahdr {
                bytes: encoded.header,
            },
            payload: encoded.payload,
        };
        let secrets = RouterSecrets::new(types::Sv([0x33; 16]), node_secret);
        let storage = MemoryStorage::default();

        handle_setup_packet(&incoming, &mut router, &storage, &secrets).expect("setup");
        assert!(router.registry().get(&policy.policy_id).is_some());
        assert!(storage.blob.lock().unwrap().is_some());
    }
}
