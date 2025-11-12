use hornet::node::NoReplay;
use hornet::router::config::RouterConfig;
use hornet::router::io::{PacketListener, TcpForward, TcpPacketListener};
use hornet::router::runtime::RouterRuntime;
use hornet::router::storage::{FileRouterStorage, RouterStorage, StoredState};
use hornet::router::sync::client::{sync_once, DirectoryClient};
use hornet::router::Router;
use hornet::time::SystemTimeProvider;

fn main() {
    let mut config = RouterConfig::from_env().unwrap_or_else(|err| {
        eprintln!("invalid config: {:?}", err);
        std::process::exit(1);
    });
    if let Err(err) = config.validate() {
        eprintln!("invalid config: {:?}", err);
        std::process::exit(1);
    }
    let storage = FileRouterStorage::new(&config.storage_path);
    let mut router = Router::new();
    let (sv, si) = load_state(&storage, &mut router);
    let file_client = LocalFileClient::new("directory.json");
    if let Err(err) = sync_once(&mut router, &config, &file_client) {
        eprintln!("directory sync failed: {:?}", err);
    } else {
        persist_state(&storage, &router, sv, si);
    }
    let time = SystemTimeProvider;
    let mut runtime = RouterRuntime::new(
        &router,
        &time,
        || Box::new(TcpForward::new()),
        || Box::new(NoReplay),
    );
    let mut listener = TcpPacketListener::bind("127.0.0.1:7000", sv).expect("bind listener");
    loop {
        match listener.next() {
            Ok(mut packet) => {
                if packet.chdr.typ == hornet::types::PacketType::Setup {
                    if let Err(err) = handle_setup_packet(&packet.payload, &storage, &mut listener)
                    {
                        eprintln!("setup packet handling failed: {:?}", err);
                    }
                    continue;
                }
                if let Err(err) = runtime.process(
                    packet.direction,
                    packet.sv,
                    &mut packet.chdr,
                    &mut packet.ahdr,
                    &mut packet.payload,
                ) {
                    eprintln!("packet processing failed: {:?}", err);
                }
            }
            Err(err) => {
                eprintln!("listener error: {err:?}");
                break;
            }
        }
    }
}

fn load_state(
    storage: &FileRouterStorage,
    router: &mut Router,
) -> (hornet::types::Sv, Option<[u8; 16]>) {
    match storage.load() {
        Ok(state) => {
            let (policies, sv, si) = state.into_parts();
            if let Err(err) = router.install_policies(&policies) {
                eprintln!("failed to install stored policies: {:?}", err);
            }
            (sv, si)
        }
        Err(_) => (hornet::types::Sv([0xAA; 16]), None),
    }
}

fn persist_state(
    storage: &FileRouterStorage,
    router: &Router,
    sv: hornet::types::Sv,
    si: Option<[u8; 16]>,
) {
    let state = StoredState::new(router.policies(), sv, si);
    if let Err(err) = storage.save(&state) {
        eprintln!("failed to persist router state: {:?}", err);
    }
}

fn handle_setup_packet(
    payload: &[u8],
    storage: &FileRouterStorage,
    listener: &mut TcpPacketListener,
) -> hornet::types::Result<()> {
    if payload.len() < 16 {
        return Err(hornet::types::Error::Length);
    }
    let mut sv_bytes = [0u8; 16];
    sv_bytes.copy_from_slice(&payload[..16]);
    let si_bytes = if payload.len() >= 32 {
        let mut si = [0u8; 16];
        si.copy_from_slice(&payload[16..32]);
        Some(si)
    } else {
        None
    };
    let sv = hornet::types::Sv(sv_bytes);
    listener.update_sv(sv);
    let policies = match storage.load() {
        Ok(state) => state.policies().to_vec(),
        Err(_) => Vec::new(),
    };
    let state = StoredState::new(policies, sv, si_bytes);
    storage.save(&state)?;
    Ok(())
}

struct LocalFileClient<'a> {
    path: &'a str,
}

impl<'a> LocalFileClient<'a> {
    fn new(path: &'a str) -> Self {
        Self { path }
    }
}

impl<'a> DirectoryClient for LocalFileClient<'a> {
    fn fetch_signed(&self) -> hornet::types::Result<String> {
        std::fs::read_to_string(self.path).map_err(|_| hornet::types::Error::Crypto)
    }
}
