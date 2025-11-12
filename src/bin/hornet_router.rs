use hornet::node::NoReplay;
use hornet::router::config::RouterConfig;
use hornet::router::runtime::forward::LoopbackForward;
use hornet::router::runtime::{PacketDirection, RouterRuntime};
use hornet::router::Router;
use hornet::time::SystemTimeProvider;

fn main() {
    let config = RouterConfig::new("https://example.com/directory", "secret");
    if let Err(err) = config.validate() {
        eprintln!("invalid config: {:?}", err);
        std::process::exit(1);
    }

    let router = Router::new();
    let time = SystemTimeProvider;
    let mut runtime = RouterRuntime::new(
        &router,
        &time,
        || Box::new(LoopbackForward::new()),
        || Box::new(NoReplay),
    );
    let mut payload = Vec::new();
    let mut chdr = hornet::types::Chdr {
        typ: hornet::types::PacketType::Data,
        hops: 0,
        specific: [0u8; 16],
    };
    let mut ahdr = hornet::types::Ahdr { bytes: Vec::new() };
    let _ = runtime.process(
        PacketDirection::Forward,
        hornet::types::Sv([0u8; 16]),
        &mut chdr,
        &mut ahdr,
        &mut payload,
    );
}
