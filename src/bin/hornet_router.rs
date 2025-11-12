use hornet::node::NoReplay;
use hornet::router::config::RouterConfig;
use hornet::router::io::{PacketListener, TcpForward, TcpPacketListener};
use hornet::router::runtime::RouterRuntime;
use hornet::router::sync::client::{sync_once, DirectoryClient};
use hornet::router::Router;
use hornet::time::SystemTimeProvider;

fn main() {
    let config = RouterConfig::new("https://example.com/directory", "secret");
    if let Err(err) = config.validate() {
        eprintln!("invalid config: {:?}", err);
        std::process::exit(1);
    }

    let mut router = Router::new();
    let file_client = LocalFileClient::new("directory.json");
    if let Err(err) = sync_once(&mut router, &config, &file_client) {
        eprintln!("directory sync failed: {:?}", err);
    }
    let time = SystemTimeProvider;
    let mut runtime = RouterRuntime::new(
        &router,
        &time,
        || Box::new(TcpForward::new()),
        || Box::new(NoReplay),
    );
    let sv = hornet::types::Sv([0xAA; 16]);
    let mut listener = TcpPacketListener::bind("127.0.0.1:7000", sv).expect("bind listener");
    loop {
        match listener.next() {
            Ok(mut packet) => {
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
