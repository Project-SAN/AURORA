use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};

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
                            capsule_validator: None,
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

criterion_group!(
    benches,
    bench_create_ahdr,
    bench_build_data_packet,
    bench_process_data_forward
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

            if hop + 1 == hops {
                routing.push(deliver_route());
            } else {
                let port = 41000 + hop as u16;
                routing.push(udp_route(port));
            }
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
