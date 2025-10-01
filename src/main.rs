use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;

fn main() {
    if let Err(e) = run_demo() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run_demo() -> Result<(), AnyError> {
    println!("=== HORNET UDP  ===");

    // setting up two nodes for a 2-hop route
    let node1_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41001);
    let node2_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41002);

    // prepare UDP sockets for each node
    let socket_node1 = UdpSocket::bind(node1_addr)?;
    let socket_node2 = UdpSocket::bind(node2_addr)?;

    // Note: In production, use a secure RNG like `rand::rngs::OsRng`.
    let mut rng = SmallRng::seed_from_u64(0x1234_5678_9ABC_DEF0);

    // generate long-term node keys (Sv) and shared keys (Si)
    let sv1 = random_sv(&mut rng);
    let sv2 = random_sv(&mut rng);
    let si1 = random_si(&mut rng);
    let si2 = random_si(&mut rng);
    let keys_f = vec![si1, si2];

    // build routing segments for each hop
    let rseg_node1 = encode_route_ipv4(node2_addr);
    let rseg_node2 = encode_route_deliver();

    // setting EXP to current time + 60 seconds
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs() as u32;
    let exp = hornet::types::Exp(now_secs.saturating_add(60));

    // generate FS for each hop
    let fs1 = hornet::packet::fs_core::create(&sv1, &keys_f[0], &rseg_node1, exp)
        .map_err(|e| format!("fs create node1: {e:?}"))?;
    let fs2 = hornet::packet::fs_core::create(&sv2, &keys_f[1], &rseg_node2, exp)
        .map_err(|e| format!("fs create node2: {e:?}"))?;
    let fses = vec![fs1, fs2];

    // generate AHDR
    let mut ah_rng = SmallRng::seed_from_u64(0x9E37_79B9_7F4A_7C15);
    let ahdr = hornet::packet::ahdr::create_ahdr(&keys_f, &fses, keys_f.len(), &mut ah_rng)
        .map_err(|e| format!("create_ahdr: {e:?}"))?;

    // start node threads
    let (delivery_tx, delivery_rx) = mpsc::channel::<Vec<u8>>();
    let handle_node1 = spawn_node("node1", socket_node1, sv1, None);
    let handle_node2 = spawn_node("node2", socket_node2, sv2, Some(delivery_tx));

    // give nodes a moment to start up
    thread::sleep(Duration::from_millis(200));

    // prepare the sending payload
    let mut payload = b"HORNET over UDP demo".to_vec();
    let mut iv0_bytes = [0u8; 16];
    rng.fill_bytes(&mut iv0_bytes);
    let mut iv0 = hornet::types::Nonce(iv0_bytes);
    let mut chdr = hornet::packet::chdr::data_header(keys_f.len() as u8, iv0);

    // build a data packet（adapt onion encryption）
    hornet::source::build_data_packet(&mut chdr, &ahdr, &keys_f, &mut iv0, &mut payload)
        .map_err(|e| format!("build_data_packet: {e:?}"))?;
    let wire_bytes = hornet::wire::encode(&chdr, &ahdr, &payload);

    println!(
        "[source] Initial IV={} payload length={}",
        hex(&chdr.specific),
        payload.len()
    );

    // send to first node from source
    let source_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    source_socket.send_to(&wire_bytes, node1_addr)?;
    println!("[source] {} bytes sent to {}", wire_bytes.len(), node1_addr);

    // receive the reconstruction result at the final node
    let recovered = delivery_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "destination timeout".to_string())?;
    println!(
        "[dest] Received payload: {}",
        String::from_utf8_lossy(&recovered)
    );

    handle_node1.join().expect("node1 thread panicked");
    handle_node2.join().expect("node2 thread panicked");

    println!("=== Demo complete ===");
    Ok(())
}

fn random_sv(rng: &mut SmallRng) -> hornet::types::Sv {
    let mut buf = [0u8; 16];
    rng.fill_bytes(&mut buf);
    hornet::types::Sv(buf)
}

fn random_si(rng: &mut SmallRng) -> hornet::types::Si {
    let mut buf = [0u8; 16];
    rng.fill_bytes(&mut buf);
    hornet::types::Si(buf)
}

fn encode_route_ipv4(addr: SocketAddrV4) -> hornet::types::RoutingSegment {
    let mut bytes = Vec::with_capacity(12);
    bytes.push(0x01); // IPv4
    bytes.push(6); // length of following data
    bytes.extend_from_slice(&addr.ip().octets());
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    hornet::types::RoutingSegment(bytes)
}

fn encode_route_deliver() -> hornet::types::RoutingSegment {
    hornet::types::RoutingSegment(vec![0xFF, 0])
}

fn spawn_node(
    name: &'static str,
    socket: UdpSocket,
    sv: hornet::types::Sv,
    delivery: Option<mpsc::Sender<Vec<u8>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(e) = run_node(name, socket, sv, delivery) {
            eprintln!("[{name}] Error: {e}");
        }
    })
}

fn run_node(
    name: &'static str,
    socket: UdpSocket,
    sv: hornet::types::Sv,
    delivery: Option<mpsc::Sender<Vec<u8>>>,
) -> Result<(), AnyError> {
    let mut buf = vec![0u8; 2048];
    let (len, src) = socket.recv_from(&mut buf)?;
    buf.truncate(len);
    println!("[{name}] {len} bytes received from {src}");

    let (mut chdr, mut ahdr, mut payload) =
        hornet::wire::decode(&buf).map_err(|e| format!("wire decode: {e:?}"))?;

    let mut forward = UdpForward::new(name, socket, delivery);
    let mut replay = hornet::node::ReplayCache::new();
    let time = SystemTimeProvider;
    let mut ctx = hornet::node::NodeCtx {
        sv,
        now: &time,
        forward: &mut forward,
        replay: &mut replay,
    };

    hornet::node::process_data_forward(&mut ctx, &mut chdr, &mut ahdr, &mut payload)
        .map_err(|e| format!("process_data_forward: {e:?}"))?;

    println!("[{name}] Processing complete");
    Ok(())
}

struct UdpForward {
    name: &'static str,
    socket: UdpSocket,
    delivery: Option<mpsc::Sender<Vec<u8>>>,
}

impl UdpForward {
    fn new(name: &'static str, socket: UdpSocket, delivery: Option<mpsc::Sender<Vec<u8>>>) -> Self {
        Self {
            name,
            socket,
            delivery,
        }
    }
}

impl hornet::forward::Forward for UdpForward {
    fn send(
        &mut self,
        rseg: &hornet::types::RoutingSegment,
        chdr: &hornet::types::Chdr,
        ahdr: &hornet::types::Ahdr,
        payload: &mut [u8],
    ) -> hornet::types::Result<()> {
        match decode_route(rseg)? {
            RouteTarget::Udp(addr) => {
                let bytes = hornet::wire::encode(chdr, ahdr, payload);
                self.socket
                    .send_to(&bytes, addr)
                    .map(|_| ())
                    .map_err(|_| hornet::types::Error::NotImplemented)?;
                println!(
                    "[{}] Next hop {}: {} bytes forwarded",
                    self.name,
                    addr,
                    bytes.len()
                );
                Ok(())
            }
            RouteTarget::Deliver => {
                let trimmed = if payload.len() >= hornet::sphinx::KAPPA_BYTES
                    && payload[..hornet::sphinx::KAPPA_BYTES]
                        .iter()
                        .all(|&b| b == 0)
                {
                    &payload[hornet::sphinx::KAPPA_BYTES..]
                } else {
                    payload
                };
                println!(
                    "[{}] Reached final destination. App payload: {}",
                    self.name,
                    String::from_utf8_lossy(trimmed)
                );
                if let Some(tx) = &self.delivery {
                    let _ = tx.send(trimmed.to_vec());
                }
                Ok(())
            }
        }
    }
}

enum RouteTarget {
    Udp(SocketAddr),
    Deliver,
}

fn decode_route(rseg: &hornet::types::RoutingSegment) -> hornet::types::Result<RouteTarget> {
    if rseg.0.len() < 2 {
        return Err(hornet::types::Error::Length);
    }
    let kind = rseg.0[0];
    let len = rseg.0[1] as usize;
    if 2 + len > rseg.0.len() {
        return Err(hornet::types::Error::Length);
    }
    let data = &rseg.0[2..2 + len];
    match kind {
        0x01 => {
            if len != 6 {
                return Err(hornet::types::Error::Length);
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&data[0..4]);
            let port = u16::from_be_bytes([data[4], data[5]]);
            Ok(RouteTarget::Udp(SocketAddr::from((
                Ipv4Addr::from(ip),
                port,
            ))))
        }
        0xFF => Ok(RouteTarget::Deliver),
        _ => Err(hornet::types::Error::NotImplemented),
    }
}

struct SystemTimeProvider;

impl hornet::time::TimeProvider for SystemTimeProvider {
    fn now_coarse(&self) -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs() as u32
    }
}

fn hex(buf: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(buf.len() * 2);
    for &b in buf {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0F) as usize]);
    }
    String::from_utf8(out).unwrap()
}
