#![allow(dead_code)]

extern crate alloc;

use hornet::application::setup::RegistrySetupPipeline;
use hornet::node::ReplayCache;
use hornet::policy::{decode_metadata_tlv, PolicyId, POLICY_METADATA_TLV};
use hornet::router::io::PacketListener;
use hornet::router::storage::{RouterStorage, StoredState};
use hornet::router::Router;
use hornet::setup::wire;
use hornet::types::{self, PacketDirection, PacketType, Result as HornetResult};

use crate::router_io::{UserlandForward, UserlandPacketListener};
use crate::router_storage::UserlandRouterStorage;
use crate::sys;

#[cfg(feature = "hornet-time")]
use crate::time_provider::SysTimeProvider;

const ROUTER_LISTEN_PORT: u16 = 7000;
const ROUTER_STORAGE_PATH: &str = "/router_state.json";

pub fn run_router() -> ! {
    let storage = UserlandRouterStorage::new(ROUTER_STORAGE_PATH);
    let mut router = Router::new();
    let secrets = load_state(&storage, &mut router);
    let mut listener = match UserlandPacketListener::listen(ROUTER_LISTEN_PORT, secrets.sv) {
        Ok(listener) => listener,
        Err(_) => loop {
            sys::sleep(1000);
        },
    };
    let time = time_provider();
    let mut forward = UserlandForward::new();
    let mut replay = ReplayCache::new();

    loop {
        match listener.next() {
            Ok(Some(mut packet)) => {
                if packet.chdr.typ == PacketType::Setup {
                    let _ = handle_setup_packet(packet, &mut router, &storage, &secrets);
                    continue;
                }
                let res = match packet.direction {
                    PacketDirection::Forward => router.process_forward_packet(
                        packet.sv,
                        &time,
                        &mut forward,
                        &mut replay,
                        &mut packet.chdr,
                        &mut packet.ahdr,
                        &mut packet.payload,
                    ),
                    PacketDirection::Backward => router.process_backward_packet(
                        packet.sv,
                        &time,
                        &mut forward,
                        &mut replay,
                        &mut packet.chdr,
                        &mut packet.ahdr,
                        &mut packet.payload,
                    ),
                };
                let _ = res;
                let _ = router.handle_async_violations();
            }
            Ok(None) => {
                sys::sleep(1);
            }
            Err(_) => {
                sys::sleep(10);
            }
        }
    }
}

fn time_provider() -> impl hornet::time::TimeProvider {
    #[cfg(feature = "hornet-time")]
    {
        SysTimeProvider
    }
    #[cfg(not(feature = "hornet-time"))]
    {
        struct DummyTime;
        impl hornet::time::TimeProvider for DummyTime {
            fn now_coarse(&self) -> u32 {
                0
            }
        }
        DummyTime
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
            let _ = router.install_policies(&policies);
            let _ = router.install_routes(&routes);
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
    let _ = storage.save(&state);
}

fn handle_setup_packet(
    packet: hornet::router::io::IncomingPacket,
    router: &mut Router,
    storage: &dyn RouterStorage,
    secrets: &RouterSecrets,
) -> HornetResult<()> {
    if packet.chdr.typ != PacketType::Setup {
        return Err(types::Error::Length);
    }
    let mut setup_packet = wire::decode(packet.chdr, &packet.ahdr.bytes, &packet.payload)?;
    let policy_id = select_policy_id(&setup_packet).ok_or(types::Error::PolicyViolation)?;
    let route_segment = router
        .route_for_policy(&policy_id)
        .cloned()
        .map(|route| route.segment)
        .ok_or(types::Error::NotImplemented)?;
    let mut pipeline = RegistrySetupPipeline::new(router.registry_mut());
    hornet::setup::node_process_with_policy(
        &mut setup_packet,
        &secrets.node_secret,
        &secrets.sv,
        &route_segment,
        Some(&mut pipeline),
    )?;
    persist_state(storage, router, secrets);
    Ok(())
}

fn select_policy_id(packet: &hornet::setup::SetupPacket) -> Option<PolicyId> {
    for tlv in &packet.tlvs {
        if tlv.first().copied() != Some(POLICY_METADATA_TLV) {
            continue;
        }
        if let Ok(meta) = decode_metadata_tlv(tlv) {
            return Some(meta.policy_id);
        }
    }
    None
}
