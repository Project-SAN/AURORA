use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use hornet::types::PacketDirection;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

const HOP_CASES: &[usize] = &[2, 3, 5, 7];
const PAYLOAD_CASES: &[usize] = &[256, 1024, 4096, 16 * 1024];

fn bench_create_ahdr(c: &mut Criterion) {
    let mut group = c.benchmark_group("ahdr/create");
    for &hops in HOP_CASES {
        let fixture = HornetFixture::new(hops, 1024);
        let keys = fixture.keys.clone();
        let fses = fixture.fses.clone();
        let rmax = hornet::types::R_MAX;
        let seed = 0xA11C_E5EED_u64 ^ (hops as u64);
        group.bench_function(BenchmarkId::from_parameter(format!("hops{hops}")), |b| {
            b.iter(|| {
                let mut rng = SmallRng::seed_from_u64(seed);
                let ahdr = hornet::packet::ahdr::create_ahdr(&keys, &fses, rmax, &mut rng)
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
                        let chdr = hornet::packet::chdr::data_header(hops as u8, iv0);
                        let iv = iv0;
                        (chdr, iv, payload)
                    },
                    |(mut chdr, mut iv, mut payload)| {
                        hornet::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut payload)
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
                        let forward = hornet::forward::NoopForward;
                        let replay = hornet::node::NoReplay;
                        (chdr, ahdr, payload, forward, replay)
                    },
                    |(mut chdr, mut ahdr, mut payload, mut forward, mut replay)| {
                        let time = FixedTimeProvider { now };
                        let mut ctx = hornet::node::NodeCtx {
                            sv,
                            now: &time,
                            forward: &mut forward,
                            replay: &mut replay,
                            policy: None,
                        };
                        hornet::node::forward::process_data(
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
            let router = hornet::router::Router::new();
            let time = FixedTimeProvider { now: fixture.now };
            let id = BenchmarkId::from_parameter(format!("hops{hops}_payload{payload_len}"));
            group.bench_function(id, move |b| {
                b.iter_batched(
                    || {
                        let chdr =
                            hornet::packet::chdr::data_header(fixture.hops as u8, fixture.iv0);
                        let ahdr = clone_ahdr(&fixture.ahdr);
                        let payload = fixture.payload_template.clone();
                        (chdr, ahdr, payload, fixture.iv0)
                    },
                    |(mut chdr, mut ahdr, mut payload, mut iv)| {
                        hornet::source::build(
                            &mut chdr,
                            &ahdr,
                            &fixture.keys,
                            &mut iv,
                            &mut payload,
                        )
                        .expect("build data packet");
                        let capture_slot: Rc<RefCell<Option<hornet::types::Ahdr>>> =
                            Rc::new(RefCell::new(None));
                        let factory_slot = capture_slot.clone();
                        let mut runtime = hornet::router::runtime::RouterRuntime::new(
                            &router,
                            &time,
                            move || Box::new(CaptureForward::new(factory_slot.clone())),
                            || Box::new(hornet::node::NoReplay),
                        );
                        for &sv in &fixture.svs {
                            capture_slot.borrow_mut().take();
                            runtime
                                .process(
                                    hornet::types::PacketDirection::Forward,
                                    sv,
                                    &mut chdr,
                                    &mut ahdr,
                                    &mut payload,
                                )
                                .expect("forward hop");
                            if let Some(next) = capture_slot.borrow_mut().take() {
                                ahdr = next;
                            } else {
                                panic!("forwarder did not capture next AHDR");
                            }
                        }
                        black_box((chdr.hops, payload.len()));
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
            let mut harness = NetworkHarness::new(hops, payload_len).expect("network harness init");
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
        let time = FixedTimeProvider { now: fixture.forward.now };
        let id = BenchmarkId::from_parameter(format!("hops{hops}"));
        group.bench_function(id, move |b| {
            let fixture = fixture.clone();
            b.iter_batched(
                || {
                    let mut iv_fwd = fixture.forward.iv0;
                    let mut chdr_fwd = hornet::packet::chdr::data_header(hops as u8, iv_fwd);
                    let ahdr_fwd = clone_ahdr(&fixture.forward.ahdr);
                    let mut request = fixture.http_request.clone();
                    hornet::source::build(
                        &mut chdr_fwd,
                        &ahdr_fwd,
                        &fixture.forward.keys,
                        &mut iv_fwd,
                        &mut request,
                    )
                    .expect("build forward payload");
                    let chdr_bwd =
                        hornet::packet::chdr::data_header(hops as u8, fixture.iv_resp);
                    let ahdr_bwd = clone_ahdr(&fixture.backward_ahdr);
                    (chdr_fwd, ahdr_fwd, request, chdr_bwd, ahdr_bwd)
                },
                |(mut chdr_fwd, mut ahdr_fwd, mut request, mut chdr_bwd, mut ahdr_bwd)| {
                    let mut response = fixture.http_response.clone();
                    run_forward_chain(&fixture.forward, &time, &mut chdr_fwd, &mut ahdr_fwd, &mut request);
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
                    let mut iv = chdr_bwd.specific;
                    let mut keys = fixture.backward_keys.clone();
                    keys.reverse();
                    hornet::source::decrypt_backward_payload(&keys, &mut iv, &mut response)
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

impl hornet::time::TimeProvider for FixedTimeProvider {
    fn now_coarse(&self) -> u32 {
        self.now
    }
}

struct HornetFixture {
    hops: usize,
    now: u32,
    svs: Vec<hornet::types::Sv>,
    keys: Vec<hornet::types::Si>,
    fses: Vec<hornet::types::Fs>,
    ahdr: hornet::types::Ahdr,
    payload_template: Vec<u8>,
    iv0: hornet::types::Nonce,
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
        F: FnMut(usize, usize) -> hornet::types::RoutingSegment,
    {
        assert!(hops > 0 && hops <= hornet::types::R_MAX);
        let mut rng = SmallRng::seed_from_u64(0x5EED_F00Du64 ^ hops as u64 ^ payload_len as u64);
        let now = 1_690_000_000u32;
        let exp = hornet::types::Exp(now.saturating_add(600));

        let mut svs = Vec::with_capacity(hops);
        let mut keys = Vec::with_capacity(hops);
        let mut routing = Vec::with_capacity(hops);
        for hop in 0..hops {
            let mut sv_bytes = [0u8; 16];
            rng.fill_bytes(&mut sv_bytes);
            svs.push(hornet::types::Sv(sv_bytes));

            let mut si_bytes = [0u8; 16];
            rng.fill_bytes(&mut si_bytes);
            keys.push(hornet::types::Si(si_bytes));

            routing.push(route_fn(hop, hops));
        }

        let fses = (0..hops)
            .map(|i| {
                hornet::packet::core::create(&svs[i], &keys[i], &routing[i], exp)
                    .expect("fs create")
            })
            .collect::<Vec<_>>();

        let mut rng_ahdr = SmallRng::seed_from_u64(0xA11C_E5EEDu64 ^ hops as u64);
        let ahdr =
            hornet::packet::ahdr::create_ahdr(&keys, &fses, hornet::types::R_MAX, &mut rng_ahdr)
                .expect("fixture ahdr");

        let mut iv0_bytes = [0u8; 16];
        rng.fill_bytes(&mut iv0_bytes);
        let iv0 = hornet::types::Nonce(iv0_bytes);

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
        let mut chdr = hornet::packet::chdr::data_header(self.hops as u8, self.iv0);
        let mut payload = self.payload_template.clone();
        let mut iv = self.iv0;
        hornet::source::build(&mut chdr, &self.ahdr, &self.keys, &mut iv, &mut payload)
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
    backward_keys: Vec<hornet::types::Si>,
    backward_ahdr: hornet::types::Ahdr,
    iv_resp: hornet::types::Nonce,
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
        let mut rng = SmallRng::seed_from_u64(0xBEEF_5EEDu64 ^ hops as u64);
        let exp = hornet::types::Exp(forward.now.saturating_add(600));

        let mut backward_keys = Vec::with_capacity(hops);
        let mut backward_fses = Vec::with_capacity(hops);
        for idx in 0..hops {
            let mut si_bytes = [0u8; 16];
            rng.fill_bytes(&mut si_bytes);
            let key = hornet::types::Si(si_bytes);
            backward_keys.push(key);
            let sv = forward.svs[hops - 1 - idx];
            let fs = hornet::packet::core::create(&sv, &key, &deliver_route(), exp)
                .expect("backward fs create");
            backward_fses.push(fs);
        }

        let mut ahdr_rng = SmallRng::seed_from_u64(0xACCE_55EDu64 ^ hops as u64);
        let backward_ahdr = hornet::packet::ahdr::create_ahdr(
            &backward_keys,
            &backward_fses,
            hornet::types::R_MAX,
            &mut ahdr_rng,
        )
        .expect("backward ahdr");

        let mut iv_bytes = [0u8; 16];
        rng.fill_bytes(&mut iv_bytes);
        let iv_resp = hornet::types::Nonce(iv_bytes);

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
    chdr: &mut hornet::types::Chdr,
    ahdr: &mut hornet::types::Ahdr,
    payload: &mut Vec<u8>,
) {
    let slot: Rc<RefCell<Option<hornet::types::Ahdr>>> = Rc::new(RefCell::new(None));
    for &sv in &fixture.svs {
        slot.borrow_mut().take();
        let mut forward = CaptureForward::new(slot.clone());
        let mut replay = hornet::node::NoReplay;
        let mut ctx = hornet::node::NodeCtx {
            sv,
            now: time,
            forward: &mut forward,
            replay: &mut replay,
            policy: None,
        };
        hornet::node::forward::process_data(&mut ctx, chdr, ahdr, payload)
            .expect("process forward hop");
        if let Some(next) = slot.borrow_mut().take() {
            *ahdr = next;
        }
    }
}

fn run_backward_chain(
    backward_keys: &[hornet::types::Si],
    svs_forward_order: &[hornet::types::Sv],
    time: &FixedTimeProvider,
    chdr: &mut hornet::types::Chdr,
    ahdr: &mut hornet::types::Ahdr,
    payload: &mut Vec<u8>,
) {
    let slot: Rc<RefCell<Option<hornet::types::Ahdr>>> = Rc::new(RefCell::new(None));
    // Nodes add onion layers in exit -> entry order; keys are used later for decryption.
    for (sv, _key) in svs_forward_order.iter().rev().zip(backward_keys.iter()) {
        slot.borrow_mut().take();
        let mut forward = CaptureForward::new(slot.clone());
        let mut replay = hornet::node::NoReplay;
        let mut ctx = hornet::node::NodeCtx {
            sv: *sv,
            now: time,
            forward: &mut forward,
            replay: &mut replay,
            policy: None,
        };
        process_backward_silent(&mut ctx, chdr, ahdr, payload).expect("process backward hop");
        if let Some(next) = slot.borrow_mut().take() {
            *ahdr = next;
        }
    }
}

fn process_backward_silent(
    ctx: &mut hornet::node::NodeCtx,
    chdr: &mut hornet::types::Chdr,
    ahdr: &mut hornet::types::Ahdr,
    payload: &mut Vec<u8>,
) -> hornet::types::Result<()> {
    use hornet::types::{Error, Exp, PacketDirection};
    let now = Exp(ctx.now.now_coarse());
    let res = hornet::packet::ahdr::proc_ahdr(&ctx.sv, ahdr, now)?;
    let tau = hornet::sphinx::derive_tau_tag(&res.s);
    if !ctx.replay.insert(tau) {
        return Err(Error::Replay);
    }
    let mut iv = chdr.specific;
    hornet::packet::onion::add_layer(&res.s, &mut iv, payload)?;
    chdr.specific = iv;
    ctx.forward
        .send(&res.r, chdr, &res.ahdr_next, payload, PacketDirection::Backward)
}

struct ForwardPacket {
    chdr: hornet::types::Chdr,
    ahdr: hornet::types::Ahdr,
    payload: Vec<u8>,
}

fn clone_chdr(chdr: &hornet::types::Chdr) -> hornet::types::Chdr {
    hornet::types::Chdr {
        typ: chdr.typ,
        hops: chdr.hops,
        specific: chdr.specific,
    }
}

fn clone_ahdr(ahdr: &hornet::types::Ahdr) -> hornet::types::Ahdr {
    hornet::types::Ahdr {
        bytes: ahdr.bytes.clone(),
    }
}

struct CaptureForward {
    slot: Rc<RefCell<Option<hornet::types::Ahdr>>>,
}

impl CaptureForward {
    fn new(slot: Rc<RefCell<Option<hornet::types::Ahdr>>>) -> Self {
        Self { slot }
    }
}

impl hornet::forward::Forward for CaptureForward {
    fn send(
        &mut self,
        _rseg: &hornet::types::RoutingSegment,
        _chdr: &hornet::types::Chdr,
        ahdr: &hornet::types::Ahdr,
        _payload: &mut Vec<u8>,
        _direction: hornet::types::PacketDirection,
    ) -> hornet::types::Result<()> {
        *self.slot.borrow_mut() = Some(clone_ahdr(ahdr));
        Ok(())
    }
}

fn udp_route(port: u16) -> hornet::types::RoutingSegment {
    let mut bytes = Vec::with_capacity(8);
    bytes.push(0x01);
    bytes.push(6);
    bytes.extend_from_slice(&[127, 0, 0, 1]);
    bytes.extend_from_slice(&port.to_be_bytes());
    hornet::types::RoutingSegment(bytes)
}

fn deliver_route() -> hornet::types::RoutingSegment {
    hornet::types::RoutingSegment(vec![0xFF, 0x00])
}

fn tcp_next_hop_route(port: u16) -> hornet::types::RoutingSegment {
    use hornet::routing::{IpAddr, RouteElem};
    hornet::routing::segment_from_elems(&[RouteElem::NextHop {
        addr: IpAddr::V4([127, 0, 0, 1]),
        port,
    }])
}

fn tcp_exit_route(port: u16) -> hornet::types::RoutingSegment {
    use hornet::routing::{IpAddr, RouteElem};
    hornet::routing::segment_from_elems(&[RouteElem::ExitTcp {
        addr: IpAddr::V4([127, 0, 0, 1]),
        port,
        tls: false,
    }])
}

struct NetworkHarness {
    fixture: HornetFixture,
    _routers: Vec<RouterWorker>,
    first_hop_addr: String,
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
                tcp_exit_route(sink_port)
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

        let first_hop_addr = router_addrs
            .first()
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:0".to_string());

        Ok(Self {
            fixture,
            _routers: routers,
            first_hop_addr,
            delivery_rx,
            _sink: sink,
        })
    }

    fn run_once(&mut self) {
        let chdr = hornet::packet::chdr::data_header(self.fixture.hops as u8, self.fixture.iv0);
        let ahdr = clone_ahdr(&self.fixture.ahdr);
        let payload = self.fixture.payload_template.clone();
        self.send_over_network(chdr, ahdr, payload, self.fixture.iv0);
    }

    fn send_over_network(
        &mut self,
        mut chdr: hornet::types::Chdr,
        ahdr: hornet::types::Ahdr,
        mut payload: Vec<u8>,
        mut iv: hornet::types::Nonce,
    ) {
        hornet::source::build(&mut chdr, &ahdr, &self.fixture.keys, &mut iv, &mut payload)
            .expect("network build data packet");

        let frame = encode_frame_bytes(PacketDirection::Forward, &chdr, &ahdr, &payload);
        let mut stream = TcpStream::connect(&self.first_hop_addr).expect("connect to first router");
        stream.write_all(&frame).expect("write frame to first hop");
        self.delivery_rx.recv().expect("await sink delivery");
    }
}

struct RouterWorker {
    addr: String,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl RouterWorker {
    fn new(listener: TcpListener, sv: hornet::types::Sv, now: u32) -> io::Result<Self> {
        let addr = listener.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_signal = stop.clone();
        let handle = thread::spawn(move || {
            let router = hornet::router::Router::new();
            let time = FixedTimeProvider { now };
            let mut runtime = hornet::router::runtime::RouterRuntime::new(
                &router,
                &time,
                || Box::new(hornet::router::io::TcpForward::new()),
                || Box::new(hornet::node::NoReplay),
            );

            let listener = listener;
            loop {
                let (mut stream, _) = listener.accept().expect("router accept");
                if stop_signal.load(Ordering::SeqCst) {
                    break;
                }
                let mut packet = read_bench_packet(&mut stream).expect("router packet decode");
                if let Err(err) = runtime.process(
                    packet.direction,
                    sv,
                    &mut packet.chdr,
                    &mut packet.ahdr,
                    &mut packet.payload,
                ) {
                    eprintln!("[bench router] forward process error: {:?}", err);
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
            loop {
                let (mut stream, _) = listener.accept().expect("sink accept");
                if stop_signal.load(Ordering::SeqCst) {
                    break;
                }
                let _packet = read_bench_packet(&mut stream).expect("sink packet decode");
                let _ = notify.send(());
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

struct RawPacket {
    direction: PacketDirection,
    chdr: hornet::types::Chdr,
    ahdr: hornet::types::Ahdr,
    payload: Vec<u8>,
}

fn encode_frame_bytes(
    direction: PacketDirection,
    chdr: &hornet::types::Chdr,
    ahdr: &hornet::types::Ahdr,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + 16 + 8 + ahdr.bytes.len() + payload.len());
    frame.push(direction_to_u8(direction));
    frame.push(packet_type_to_u8(chdr.typ));
    frame.push(chdr.hops);
    frame.push(0);
    frame.extend_from_slice(&chdr.specific);
    frame.extend_from_slice(&(ahdr.bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&ahdr.bytes);
    frame.extend_from_slice(payload);
    frame
}

fn read_bench_packet(stream: &mut TcpStream) -> io::Result<RawPacket> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let direction = direction_from_u8(header[0])?;
    let pkt_type = packet_type_from_u8(header[1])?;
    let hops = header[2];

    let mut specific = [0u8; 16];
    stream.read_exact(&mut specific)?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let ahdr_len = u32::from_le_bytes(len_buf) as usize;
    stream.read_exact(&mut len_buf)?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    let mut ahdr_bytes = vec![0u8; ahdr_len];
    if ahdr_len > 0 {
        stream.read_exact(&mut ahdr_bytes)?;
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream.read_exact(&mut payload)?;
    }

    Ok(RawPacket {
        direction,
        chdr: hornet::types::Chdr {
            typ: pkt_type,
            hops,
            specific,
        },
        ahdr: hornet::types::Ahdr { bytes: ahdr_bytes },
        payload,
    })
}

fn packet_type_to_u8(pt: hornet::types::PacketType) -> u8 {
    match pt {
        hornet::types::PacketType::Setup => 0,
        hornet::types::PacketType::Data => 1,
    }
}

fn packet_type_from_u8(value: u8) -> io::Result<hornet::types::PacketType> {
    match value {
        0 => Ok(hornet::types::PacketType::Setup),
        1 => Ok(hornet::types::PacketType::Data),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown packet type",
        )),
    }
}

fn direction_to_u8(direction: PacketDirection) -> u8 {
    match direction {
        PacketDirection::Forward => 0,
        PacketDirection::Backward => 1,
    }
}

fn direction_from_u8(value: u8) -> io::Result<PacketDirection> {
    match value {
        0 => Ok(PacketDirection::Forward),
        1 => Ok(PacketDirection::Backward),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown direction",
        )),
    }
}
