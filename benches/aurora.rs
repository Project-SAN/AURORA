use aurora::types::PacketDirection;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

const HOP_CASES: &[usize] = &[2, 3, 5, 7];
const PAYLOAD_CASES: &[usize] = &[256, 1024, 4096, 16 * 1024];
type BenchResult<T> = core::result::Result<T, aurora::types::Error>;

fn bench_create_ahdr(c: &mut Criterion) {
    let mut group = c.benchmark_group("ahdr/create");
    for &hops in HOP_CASES {
        let fixture = HornetFixture::new(hops, 1024);
        let keys = fixture.keys.clone();
        let fses = fixture.fses.clone();
        let rmax = aurora::types::R_MAX;
        let seed = 0xA11C_E5EED_u64 ^ (hops as u64);
        group.bench_function(BenchmarkId::from_parameter(format!("hops{hops}")), |b| {
            b.iter(|| {
                let mut rng = ChaCha20Rng::seed_from_u64(seed);
                let ahdr = aurora::packet::ahdr::create_ahdr(&keys, &fses, rmax, &mut rng)
                    .expect("ahdr create");
                black_box(ahdr);
            });
        });
    }
    group.finish();
}

fn bench_build_data_packet(c: &mut Criterion) {
    let mut group = c.benchmark_group("source/build_data_packet");
    for &hops in HOP_CASES {
        for &payload_len in PAYLOAD_CASES {
            let fixture = HornetFixture::new(hops, payload_len);
            let keys = fixture.keys.clone();
            let ahdr = clone_ahdr(&fixture.ahdr);
            let iv0 = fixture.iv0;
            let payload_template = fixture.payload_template.clone();
            let id = BenchmarkId::from_parameter(format!("hops{hops}_payload{payload_len}"));
            group.bench_function(id, |b| {
                b.iter_batched(
                    || {
                        let payload = payload_template.clone();
                        let chdr = aurora::packet::chdr::data_header(hop_count(hops), iv0);
                        let iv = iv0;
                        (chdr, iv, payload)
                    },
                    |(mut chdr, mut iv, mut payload)| {
                        aurora::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut payload)
                            .expect("build data packet");
                        black_box((chdr, payload));
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

fn bench_process_data_forward(c: &mut Criterion) {
    let mut group = c.benchmark_group("node/process_data_forward");
    for &hops in HOP_CASES {
        for &payload_len in PAYLOAD_CASES {
            let fixture = HornetFixture::new(hops, payload_len);
            let sv = fixture.svs[0];
            let now = fixture.now;
            let packet = fixture.forward_packet();
            let base_chdr = packet.chdr;
            let base_ahdr = packet.ahdr;
            let base_payload = packet.payload;
            let id = BenchmarkId::from_parameter(format!("hops{hops}_payload{payload_len}"));
            group.bench_function(id, |b| {
                b.iter_batched(
                    || {
                        let chdr = clone_chdr(&base_chdr);
                        let ahdr = clone_ahdr(&base_ahdr);
                        let payload = base_payload.clone();
                        let forward = aurora::forward::NoopForward;
                        let replay = aurora::node::NoReplay;
                        (chdr, ahdr, payload, forward, replay)
                    },
                    |(mut chdr, mut ahdr, mut payload, mut forward, mut replay)| {
                        let time = FixedTimeProvider { now };
                        let mut ctx = aurora::node::NodeCtx {
                            sv,
                            now: &time,
                            forward: &mut forward,
                            replay: &mut replay,
                            policy: None,
                            exit: None,
                            tunnels: None,
                        };
                        aurora::node::forward::process_data(
                            &mut ctx,
                            &mut chdr,
                            &mut ahdr,
                            &mut payload,
                        )
                        .expect("process data forward");
                        black_box((chdr, ahdr, payload));
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

fn bench_end_to_end_user_to_router(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end/user_to_last_router");
    for &hops in HOP_CASES {
        for &payload_len in PAYLOAD_CASES {
            let fixture = HornetFixture::new(hops, payload_len);
            let time = FixedTimeProvider { now: fixture.now };
            let id = BenchmarkId::from_parameter(format!("hops{hops}_payload{payload_len}"));
            group.bench_function(id, move |b| {
                b.iter_batched(
                    || {
                        let chdr =
                            aurora::packet::chdr::data_header(hop_count(fixture.hops), fixture.iv0);
                        let ahdr = clone_ahdr(&fixture.ahdr);
                        let payload = fixture.payload_template.clone();
                        (chdr, ahdr, payload, fixture.iv0)
                    },
                    |(mut chdr, mut ahdr, mut payload, mut iv)| {
                        aurora::source::build(
                            &mut chdr,
                            &ahdr,
                            &fixture.keys,
                            &mut iv,
                            &mut payload,
                        )
                        .expect("build data packet");
                        run_forward_chain(&fixture, &time, &mut chdr, &mut ahdr, &mut payload);
                        black_box((chdr.hops().get(), payload.len()));
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

fn bench_end_to_end_user_to_router_network(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end_network/user_to_exit");
    for &hops in HOP_CASES {
        for &payload_len in PAYLOAD_CASES {
            let mut harness = match NetworkHarness::new(hops, payload_len) {
                Ok(harness) => harness,
                Err(err) => {
                    eprintln!(
                        "skipping network harness benchmark (hops={hops}, payload={payload_len}): {err}"
                    );
                    group.finish();
                    return;
                }
            };
            let id = BenchmarkId::from_parameter(format!("hops{hops}_payload{payload_len}"));
            group.bench_function(id, |b| {
                b.iter(|| {
                    harness.run_once();
                });
            });
        }
    }
    group.finish();
}

fn bench_round_trip_example_com(c: &mut Criterion) {
    let mut group = c.benchmark_group("round_trip/example_com");
    for &hops in HOP_CASES {
        let fixture = RoundTripFixture::new(hops);
        let time = FixedTimeProvider {
            now: fixture.forward.now,
        };
        let id = BenchmarkId::from_parameter(format!("hops{hops}"));
        group.bench_function(id, move |b| {
            let fixture = fixture.clone();
            b.iter_batched(
                || {
                    let mut iv_fwd = fixture.forward.iv0;
                    let mut chdr_fwd = aurora::packet::chdr::data_header(hop_count(hops), iv_fwd);
                    let ahdr_fwd = clone_ahdr(&fixture.forward.ahdr);
                    let mut request = fixture.http_request.clone();
                    aurora::source::build(
                        &mut chdr_fwd,
                        &ahdr_fwd,
                        &fixture.forward.keys,
                        &mut iv_fwd,
                        &mut request,
                    )
                    .expect("build forward payload");
                    let chdr_bwd =
                        aurora::packet::chdr::data_header(hop_count(hops), fixture.iv_resp);
                    let ahdr_bwd = clone_ahdr(&fixture.backward_ahdr);
                    (chdr_fwd, ahdr_fwd, request, chdr_bwd, ahdr_bwd)
                },
                |(mut chdr_fwd, mut ahdr_fwd, mut request, mut chdr_bwd, mut ahdr_bwd)| {
                    let mut response = fixture.http_response.clone();
                    run_forward_chain(
                        &fixture.forward,
                        &time,
                        &mut chdr_fwd,
                        &mut ahdr_fwd,
                        &mut request,
                    );
                    assert!(
                        request
                            .windows(b"example.com".len())
                            .any(|w| w.eq_ignore_ascii_case(b"example.com")),
                        "forward payload missing host"
                    );

                    run_backward_chain(
                        &fixture.backward_keys,
                        &fixture.forward.svs,
                        &time,
                        &mut chdr_bwd,
                        &mut ahdr_bwd,
                        &mut response,
                    );
                    let mut iv = chdr_bwd.nonce().expect("backward data nonce").0;
                    let mut keys = fixture.backward_keys.clone();
                    keys.reverse();
                    aurora::source::decrypt_backward_payload(&keys, &mut iv, &mut response)
                        .expect("decrypt backward response");
                    assert!(
                        response.ends_with(fixture.example_body.as_bytes()),
                        "unexpected response body"
                    );
                    black_box(response.len());
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_create_ahdr,
    bench_build_data_packet,
    bench_process_data_forward,
    bench_end_to_end_user_to_router,
    bench_end_to_end_user_to_router_network,
    bench_round_trip_example_com
);
criterion_main!(benches);

struct FixedTimeProvider {
    now: u32,
}

impl aurora::time::TimeProvider for FixedTimeProvider {
    fn now_coarse(&self) -> u32 {
        self.now
    }
}

struct HornetFixture {
    hops: usize,
    now: u32,
    svs: Vec<aurora::types::Sv>,
    keys: Vec<aurora::types::Si>,
    fses: Vec<aurora::types::Fs>,
    ahdr: aurora::types::Ahdr,
    payload_template: Vec<u8>,
    iv0: aurora::types::Nonce,
}

impl HornetFixture {
    fn new(hops: usize, payload_len: usize) -> Self {
        Self::with_routing(hops, payload_len, |hop, total| {
            if hop + 1 == total {
                deliver_route()
            } else {
                let port = 41000 + hop as u16;
                udp_route(port)
            }
        })
    }

    fn with_routing<F>(hops: usize, payload_len: usize, mut route_fn: F) -> Self
    where
        F: FnMut(usize, usize) -> aurora::types::RoutingSegment,
    {
        assert!(hops > 0 && hops <= aurora::types::R_MAX);
        let mut rng = ChaCha20Rng::seed_from_u64(0x5EED_F00Du64 ^ hops as u64 ^ payload_len as u64);
        let now = 1_690_000_000u32;
        let exp = aurora::types::Exp(now.saturating_add(600));

        let mut svs = Vec::with_capacity(hops);
        let mut keys = Vec::with_capacity(hops);
        let mut routing = Vec::with_capacity(hops);
        for hop in 0..hops {
            let mut sv_bytes = [0u8; 16];
            rng.fill_bytes(&mut sv_bytes);
            svs.push(aurora::types::Sv(sv_bytes));

            let mut si_bytes = [0u8; 16];
            rng.fill_bytes(&mut si_bytes);
            keys.push(aurora::types::Si(si_bytes));

            routing.push(route_fn(hop, hops));
        }

        let fses = (0..hops)
            .map(|i| {
                aurora::packet::core::create(&svs[i], &keys[i], &routing[i], exp)
                    .expect("fs create")
            })
            .collect::<Vec<_>>();

        let mut rng_ahdr = ChaCha20Rng::seed_from_u64(0xA11C_E5EEDu64 ^ hops as u64);
        let ahdr =
            aurora::packet::ahdr::create_ahdr(&keys, &fses, aurora::types::R_MAX, &mut rng_ahdr)
                .expect("fixture ahdr");

        let mut iv0_bytes = [0u8; 16];
        rng.fill_bytes(&mut iv0_bytes);
        let iv0 = aurora::types::Nonce(iv0_bytes);

        let mut payload_template = vec![0u8; payload_len];
        rng.fill_bytes(&mut payload_template);

        Self {
            hops,
            now,
            svs,
            keys,
            fses,
            ahdr,
            payload_template,
            iv0,
        }
    }

    fn forward_packet(&self) -> ForwardPacket {
        let mut chdr = aurora::packet::chdr::data_header(hop_count(self.hops), self.iv0);
        let mut payload = self.payload_template.clone();
        let mut iv = self.iv0;
        aurora::source::build(&mut chdr, &self.ahdr, &self.keys, &mut iv, &mut payload)
            .expect("fixture build data packet");
        ForwardPacket {
            chdr,
            ahdr: clone_ahdr(&self.ahdr),
            payload,
        }
    }
}

impl Clone for HornetFixture {
    fn clone(&self) -> Self {
        Self {
            hops: self.hops,
            now: self.now,
            svs: self.svs.clone(),
            keys: self.keys.clone(),
            fses: self.fses.clone(),
            ahdr: clone_ahdr(&self.ahdr),
            payload_template: self.payload_template.clone(),
            iv0: self.iv0,
        }
    }
}

struct RoundTripFixture {
    forward: HornetFixture,
    backward_keys: Vec<aurora::types::Si>,
    backward_ahdr: aurora::types::Ahdr,
    iv_resp: aurora::types::Nonce,
    http_request: Vec<u8>,
    http_response: Vec<u8>,
    example_body: &'static str,
}

impl RoundTripFixture {
    fn new(hops: usize) -> Self {
        let example_body = "Example Domain";
        let http_request = example_request_bytes();
        let http_response = example_response_bytes(example_body);
        let forward = HornetFixture::new(hops, http_request.len());
        let mut rng = ChaCha20Rng::seed_from_u64(0xBEEF_5EEDu64 ^ hops as u64);
        let exp = aurora::types::Exp(forward.now.saturating_add(600));

        let mut backward_keys = Vec::with_capacity(hops);
        let mut backward_fses = Vec::with_capacity(hops);
        for idx in 0..hops {
            let mut si_bytes = [0u8; 16];
            rng.fill_bytes(&mut si_bytes);
            let key = aurora::types::Si(si_bytes);
            backward_keys.push(key);
            let sv = forward.svs[hops - 1 - idx];
            let fs = aurora::packet::core::create(&sv, &key, &deliver_route(), exp)
                .expect("backward fs create");
            backward_fses.push(fs);
        }

        let mut ahdr_rng = ChaCha20Rng::seed_from_u64(0xACCE_55EDu64 ^ hops as u64);
        let backward_ahdr = aurora::packet::ahdr::create_ahdr(
            &backward_keys,
            &backward_fses,
            aurora::types::R_MAX,
            &mut ahdr_rng,
        )
        .expect("backward ahdr");

        let mut iv_bytes = [0u8; 16];
        rng.fill_bytes(&mut iv_bytes);
        let iv_resp = aurora::types::Nonce(iv_bytes);

        Self {
            forward,
            backward_keys,
            backward_ahdr,
            iv_resp,
            http_request,
            http_response,
            example_body,
        }
    }
}

impl Clone for RoundTripFixture {
    fn clone(&self) -> Self {
        Self {
            forward: self.forward.clone(),
            backward_keys: self.backward_keys.clone(),
            backward_ahdr: clone_ahdr(&self.backward_ahdr),
            iv_resp: self.iv_resp,
            http_request: self.http_request.clone(),
            http_response: self.http_response.clone(),
            example_body: self.example_body,
        }
    }
}

fn example_request_bytes() -> Vec<u8> {
    b"GET /?q=example.com HTTP/1.1\r\nHost: example.com\r\nUser-Agent: hornet-bench\r\nConnection: close\r\n\r\n"
        .to_vec()
}

fn example_response_bytes(body: &str) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body.as_bytes());
    response
}

fn run_forward_chain(
    fixture: &HornetFixture,
    time: &FixedTimeProvider,
    chdr: &mut aurora::types::Chdr,
    ahdr: &mut aurora::types::Ahdr,
    payload: &mut Vec<u8>,
) {
    let slot: Rc<RefCell<Option<aurora::types::Ahdr>>> = Rc::new(RefCell::new(None));
    for &sv in &fixture.svs {
        slot.borrow_mut().take();
        let mut forward = CaptureForward::new(slot.clone());
        let mut replay = aurora::node::NoReplay;
        let mut ctx = aurora::node::NodeCtx {
            sv,
            now: time,
            forward: &mut forward,
            replay: &mut replay,
            policy: None,
            exit: None,
            tunnels: None,
        };
        aurora::node::forward::process_data(&mut ctx, chdr, ahdr, payload)
            .expect("process forward hop");
        if let Some(next) = slot.borrow_mut().take() {
            *ahdr = next;
        }
    }
}

fn run_backward_chain(
    backward_keys: &[aurora::types::Si],
    svs_forward_order: &[aurora::types::Sv],
    time: &FixedTimeProvider,
    chdr: &mut aurora::types::Chdr,
    ahdr: &mut aurora::types::Ahdr,
    payload: &mut Vec<u8>,
) {
    let slot: Rc<RefCell<Option<aurora::types::Ahdr>>> = Rc::new(RefCell::new(None));
    // Nodes add onion layers in exit -> entry order; keys are used later for decryption.
    for (sv, _key) in svs_forward_order.iter().rev().zip(backward_keys.iter()) {
        slot.borrow_mut().take();
        let mut forward = CaptureForward::new(slot.clone());
        let mut replay = aurora::node::NoReplay;
        let mut ctx = aurora::node::NodeCtx {
            sv: *sv,
            now: time,
            forward: &mut forward,
            replay: &mut replay,
            policy: None,
            exit: None,
            tunnels: None,
        };
        process_backward_silent(&mut ctx, chdr, ahdr, payload).expect("process backward hop");
        if let Some(next) = slot.borrow_mut().take() {
            *ahdr = next;
        }
    }
}

fn process_backward_silent(
    ctx: &mut aurora::node::NodeCtx<'_, '_, '_>,
    chdr: &mut aurora::types::Chdr,
    ahdr: &mut aurora::types::Ahdr,
    payload: &mut Vec<u8>,
) -> BenchResult<()> {
    use aurora::types::{Error, Exp, Nonce, PacketDirection};
    let now = Exp(ctx.now.now_coarse());
    let res = aurora::packet::ahdr::proc_ahdr(&ctx.sv, ahdr, now)?;
    let tau = aurora::sphinx::derive_tau_tag(&res.s);
    if !ctx.replay.insert(tau) {
        return Err(Error::Replay);
    }
    let mut iv = chdr.nonce().ok_or(Error::Length)?.0;
    aurora::packet::onion::add_layer(&res.s, &mut iv, payload)?;
    chdr.set_nonce(Nonce(iv))?;
    ctx.forward.send(
        &res.r,
        chdr,
        &res.ahdr_next,
        payload,
        PacketDirection::Backward,
    )
}

struct ForwardPacket {
    chdr: aurora::types::Chdr,
    ahdr: aurora::types::Ahdr,
    payload: Vec<u8>,
}

fn clone_chdr(chdr: &aurora::types::Chdr) -> aurora::types::Chdr {
    *chdr
}

fn clone_ahdr(ahdr: &aurora::types::Ahdr) -> aurora::types::Ahdr {
    aurora::types::Ahdr {
        bytes: ahdr.bytes.clone(),
    }
}

struct CaptureForward {
    slot: Rc<RefCell<Option<aurora::types::Ahdr>>>,
}

impl CaptureForward {
    fn new(slot: Rc<RefCell<Option<aurora::types::Ahdr>>>) -> Self {
        Self { slot }
    }
}

impl aurora::forward::Forward for CaptureForward {
    fn send(
        &mut self,
        _rseg: &aurora::types::RoutingSegment,
        _chdr: &aurora::types::Chdr,
        ahdr: &aurora::types::Ahdr,
        _payload: &mut Vec<u8>,
        _direction: aurora::types::PacketDirection,
    ) -> BenchResult<()> {
        *self.slot.borrow_mut() = Some(clone_ahdr(ahdr));
        Ok(())
    }
}

fn udp_route(port: u16) -> aurora::types::RoutingSegment {
    let mut bytes = Vec::with_capacity(8);
    bytes.push(0x01);
    bytes.push(6);
    bytes.extend_from_slice(&[127, 0, 0, 1]);
    bytes.extend_from_slice(&port.to_be_bytes());
    aurora::types::RoutingSegment(bytes)
}

fn deliver_route() -> aurora::types::RoutingSegment {
    aurora::types::RoutingSegment(vec![0xFF, 0x00])
}

fn tcp_next_hop_route(port: u16) -> aurora::types::RoutingSegment {
    use aurora::routing::{IpAddr, RouteElem};
    aurora::routing::segment_from_elems(&[RouteElem::NextHop {
        addr: IpAddr::V4([127, 0, 0, 1]),
        port,
    }])
}

struct NetworkHarness {
    fixture: HornetFixture,
    _routers: Vec<RouterWorker>,
    first_hop_addr: String,
    ingress: TcpStream,
    delivery_rx: mpsc::Receiver<()>,
    _sink: SinkServer,
}

impl NetworkHarness {
    fn new(hops: usize, payload_len: usize) -> io::Result<Self> {
        let sink_listener = TcpListener::bind("127.0.0.1:0")?;
        let sink_port = sink_listener.local_addr()?.port();

        let mut router_listeners = Vec::with_capacity(hops);
        let mut router_ports = Vec::with_capacity(hops);
        let mut router_addrs = Vec::with_capacity(hops);
        for _ in 0..hops {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            router_ports.push(addr.port());
            router_addrs.push(addr.to_string());
            router_listeners.push(listener);
        }

        let fixture = HornetFixture::with_routing(hops, payload_len, |idx, total| {
            if idx + 1 == total {
                tcp_next_hop_route(sink_port)
            } else {
                tcp_next_hop_route(router_ports[idx + 1])
            }
        });

        let (notify_tx, delivery_rx) = mpsc::channel();
        let sink = SinkServer::new(sink_listener, notify_tx)?;

        let mut routers = Vec::with_capacity(hops);
        for (idx, listener) in router_listeners.into_iter().enumerate() {
            routers.push(RouterWorker::new(listener, fixture.svs[idx], fixture.now)?);
        }
        thread::sleep(Duration::from_millis(10));

        let first_hop_addr = router_addrs
            .first()
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:0".to_string());
        let ingress = connect_with_retry(&first_hop_addr)?;
        let _ = ingress.set_nodelay(true);

        Ok(Self {
            fixture,
            _routers: routers,
            first_hop_addr,
            ingress,
            delivery_rx,
            _sink: sink,
        })
    }

    fn run_once(&mut self) {
        let chdr =
            aurora::packet::chdr::data_header(hop_count(self.fixture.hops), self.fixture.iv0);
        let ahdr = clone_ahdr(&self.fixture.ahdr);
        let payload = self.fixture.payload_template.clone();
        self.send_over_network(chdr, ahdr, payload, self.fixture.iv0);
    }

    fn send_over_network(
        &mut self,
        mut chdr: aurora::types::Chdr,
        ahdr: aurora::types::Ahdr,
        mut payload: Vec<u8>,
        mut iv: aurora::types::Nonce,
    ) {
        aurora::source::build(&mut chdr, &ahdr, &self.fixture.keys, &mut iv, &mut payload)
            .expect("network build data packet");

        let frame = aurora::router::io::encode_frame_bytes(
            PacketDirection::Forward,
            &chdr,
            &ahdr,
            &payload,
        );
        if self.ingress.write_all(&frame).is_err() {
            self.ingress = connect_with_retry(&self.first_hop_addr).expect("reconnect first hop");
            let _ = self.ingress.set_nodelay(true);
            self.ingress
                .write_all(&frame)
                .expect("write frame to first hop");
        }
        self.delivery_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("await sink delivery");
    }
}

struct SilentTcpForward {
    pool: Rc<RefCell<HashMap<String, TcpStream>>>,
}

impl SilentTcpForward {
    fn new(pool: Rc<RefCell<HashMap<String, TcpStream>>>) -> Self {
        Self { pool }
    }

    fn format_addr(addr: &aurora::routing::IpAddr, port: u16) -> String {
        match addr {
            aurora::routing::IpAddr::V4(octets) => {
                format!(
                    "{}.{}.{}.{}:{}",
                    octets[0], octets[1], octets[2], octets[3], port
                )
            }
            aurora::routing::IpAddr::V6(bytes) => {
                let mut out = String::from("[");
                for (i, chunk) in bytes.chunks(2).enumerate() {
                    if i > 0 {
                        out.push(':');
                    }
                    let value = u16::from_be_bytes([chunk[0], chunk[1]]);
                    out.push_str(&format!("{value:x}"));
                }
                out.push(']');
                out.push(':');
                out.push_str(&port.to_string());
                out
            }
        }
    }

    fn first_hop_addr(rseg: &aurora::types::RoutingSegment) -> BenchResult<String> {
        let elems =
            aurora::routing::elems_from_segment(rseg).map_err(|_| aurora::types::Error::Length)?;
        let hop = elems.first().ok_or(aurora::types::Error::Length)?;
        match hop {
            aurora::routing::RouteElem::NextHop { addr, port }
            | aurora::routing::RouteElem::ExitTcp { addr, port } => {
                Ok(Self::format_addr(addr, *port))
            }
        }
    }
}

impl aurora::forward::Forward for SilentTcpForward {
    fn send(
        &mut self,
        rseg: &aurora::types::RoutingSegment,
        chdr: &aurora::types::Chdr,
        ahdr: &aurora::types::Ahdr,
        payload: &mut Vec<u8>,
        direction: PacketDirection,
    ) -> BenchResult<()> {
        let addr = Self::first_hop_addr(rseg)?;
        let frame =
            aurora::router::io::encode_frame_bytes(direction, chdr, ahdr, payload.as_slice());
        {
            let mut pool = self.pool.borrow_mut();
            if let Some(stream) = pool.get_mut(&addr) {
                if stream.write_all(&frame).is_ok() {
                    return Ok(());
                }
                pool.remove(&addr);
            }
        }
        match connect_with_retry(&addr) {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true);
                stream
                    .write_all(&frame)
                    .map_err(|_| aurora::types::Error::Crypto)?;
                self.pool.borrow_mut().insert(addr.to_owned(), stream);
                Ok(())
            }
            Err(_) => Err(aurora::types::Error::Crypto),
        }
    }
}

struct TcpStreamReader<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> TcpStreamReader<'a> {
    fn new(stream: &'a mut TcpStream) -> Self {
        Self { stream }
    }
}

impl aurora::router::io::PacketReader for TcpStreamReader<'_> {
    fn read_exact(&mut self, buf: &mut [u8]) -> BenchResult<()> {
        self.stream
            .read_exact(buf)
            .map_err(|_| aurora::types::Error::Crypto)
    }
}

struct RouterWorker {
    addr: String,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl RouterWorker {
    fn new(listener: TcpListener, sv: aurora::types::Sv, now: u32) -> io::Result<Self> {
        let addr = listener.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_signal = stop.clone();
        let handle = thread::spawn(move || {
            let mut router = aurora::router::Router::new();
            let time = FixedTimeProvider { now };
            let forward_pool: Rc<RefCell<HashMap<String, TcpStream>>> =
                Rc::new(RefCell::new(HashMap::new()));
            let forward_pool_factory = forward_pool.clone();
            let mut runtime = aurora::router::runtime::RouterRuntime::new(
                &mut router,
                &time,
                move || Box::new(SilentTcpForward::new(forward_pool_factory.clone())),
                || Box::new(aurora::node::NoReplay),
            );

            let listener = listener;
            'accept_loop: loop {
                let (mut stream, _) = listener.accept().expect("router accept");
                if stop_signal.load(Ordering::SeqCst) {
                    break;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                loop {
                    let mut reader = TcpStreamReader::new(&mut stream);
                    let incoming = match aurora::router::io::read_incoming_packet(&mut reader, sv) {
                        Ok(incoming) => incoming,
                        Err(aurora::types::Error::Crypto) => {
                            if stop_signal.load(Ordering::SeqCst) {
                                break 'accept_loop;
                            }
                            break;
                        }
                        Err(err) => {
                            eprintln!("[bench router] decode error: {:?}", err);
                            break;
                        }
                    };
                    let result = match (incoming.direction, incoming.packet) {
                        (PacketDirection::Forward, aurora::types::Packet::Data(data_packet)) => {
                            runtime
                                .process_forward_data_packet(sv, data_packet)
                                .map(|_| ())
                        }
                        (PacketDirection::Backward, aurora::types::Packet::Data(data_packet)) => {
                            runtime
                                .process_backward_data_packet(sv, data_packet)
                                .map(|_| ())
                        }
                        (_, aurora::types::Packet::Setup(_)) => Ok(()),
                    };
                    if let Err(err) = result {
                        eprintln!("[bench router] process error: {:?}", err);
                        break;
                    }
                }
            }
        });

        Ok(Self {
            addr,
            stop,
            join: Some(handle),
        })
    }
}

impl Drop for RouterWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

struct SinkServer {
    addr: String,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl SinkServer {
    fn new(listener: TcpListener, notify: mpsc::Sender<()>) -> io::Result<Self> {
        let addr = listener.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_signal = stop.clone();
        let handle = thread::spawn(move || {
            let listener = listener;
            'accept_loop: loop {
                let (mut stream, _) = listener.accept().expect("sink accept");
                if stop_signal.load(Ordering::SeqCst) {
                    break;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                loop {
                    let mut reader = TcpStreamReader::new(&mut stream);
                    match aurora::router::io::read_incoming_packet(
                        &mut reader,
                        aurora::types::Sv([0u8; 16]),
                    ) {
                        Ok(_) => {
                            let _ = notify.send(());
                        }
                        Err(aurora::types::Error::Crypto) => {
                            if stop_signal.load(Ordering::SeqCst) {
                                break 'accept_loop;
                            }
                            break;
                        }
                        Err(err) => {
                            eprintln!("[bench sink] decode error: {:?}", err);
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            stop,
            join: Some(handle),
        })
    }
}

impl Drop for SinkServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

fn connect_with_retry(addr: &str) -> io::Result<TcpStream> {
    let mut last_err = None;
    for _ in 0..20 {
        match TcpStream::connect(addr) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_err = Some(err);
                thread::sleep(Duration::from_millis(2));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "connect failed")))
}

fn hop_count(hops: usize) -> aurora::types::HopCount {
    aurora::types::HopCount::try_from(hops).expect("valid benchmark hop count")
}
