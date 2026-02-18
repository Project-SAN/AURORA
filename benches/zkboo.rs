use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hornet::crypto::zkp::ascon_circuit;
use hornet::crypto::zkp::{Circuit, ProverConfig, VerifierConfig, ZkBooEngine};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn bits_lsb(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for bit in 0..8u8 {
            out.push((b >> bit) & 1);
        }
    }
    out
}

fn bench_zkboo_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkboo/prove");

    let mut small = Circuit::new(2);
    let and_wire = small.add_and(0, 1);
    small.set_outputs(&[and_wire]);
    let small_input = vec![1u8, 1u8];
    let small_output = vec![1u8];
    let small_cfg = ProverConfig { rounds: 16 };
    group.bench_function(BenchmarkId::from_parameter("and_rounds16"), |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::seed_from_u64(0x11AA_2233_4455_6677);
            let proof = ZkBooEngine
                .prove_circuit_with_rng(
                    &small,
                    black_box(&small_input),
                    black_box(&small_output),
                    small_cfg,
                    &mut rng,
                )
                .expect("prove");
            black_box(proof);
        });
    });

    let payload = vec![0xA5u8; 32];
    let payload_bits = bits_lsb(&payload);
    let hash_circuit = ascon_circuit::build_payload_hash_circuit(32);
    let hash_output = hash_circuit.eval(&payload_bits).expect("eval");
    let hash_cfg = ProverConfig { rounds: 16 };
    group.bench_function(BenchmarkId::from_parameter("payload_hash_32b_rounds16"), |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::seed_from_u64(0x88BB_99CC_DDEE_F011);
            let proof = ZkBooEngine
                .prove_circuit_with_rng(
                    &hash_circuit,
                    black_box(&payload_bits),
                    black_box(&hash_output),
                    hash_cfg,
                    &mut rng,
                )
                .expect("prove");
            black_box(proof);
        });
    });

    group.finish();
}

fn bench_zkboo_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkboo/verify");

    let mut small = Circuit::new(2);
    let and_wire = small.add_and(0, 1);
    small.set_outputs(&[and_wire]);
    let small_input = vec![1u8, 1u8];
    let small_output = vec![1u8];
    let small_rounds = 16u16;
    let mut small_rng = ChaCha20Rng::seed_from_u64(7);
    let small_proof = ZkBooEngine
        .prove_circuit_with_rng(
            &small,
            &small_input,
            &small_output,
            ProverConfig {
                rounds: small_rounds,
            },
            &mut small_rng,
        )
        .expect("prove");
    group.bench_function(BenchmarkId::from_parameter("and_rounds16"), |b| {
        b.iter(|| {
            ZkBooEngine
                .verify_circuit(
                    &small,
                    black_box(&small_output),
                    black_box(&small_proof),
                    VerifierConfig {
                        rounds: small_rounds,
                    },
                )
                .expect("verify");
        });
    });

    let mut payload = vec![0u8; 32];
    let mut payload_rng = ChaCha20Rng::seed_from_u64(19);
    payload_rng.fill_bytes(&mut payload);
    let payload_bits = bits_lsb(&payload);
    let hash_circuit = ascon_circuit::build_payload_hash_circuit(32);
    let hash_output = hash_circuit.eval(&payload_bits).expect("eval");
    let hash_rounds = 16u16;
    let mut hash_rng = ChaCha20Rng::seed_from_u64(27);
    let hash_proof = ZkBooEngine
        .prove_circuit_with_rng(
            &hash_circuit,
            &payload_bits,
            &hash_output,
            ProverConfig {
                rounds: hash_rounds,
            },
            &mut hash_rng,
        )
        .expect("prove");
    group.bench_function(BenchmarkId::from_parameter("payload_hash_32b_rounds16"), |b| {
        b.iter(|| {
            ZkBooEngine
                .verify_circuit(
                    &hash_circuit,
                    black_box(&hash_output),
                    black_box(&hash_proof),
                    VerifierConfig {
                        rounds: hash_rounds,
                    },
                )
                .expect("verify");
        });
    });

    group.finish();
}

criterion_group!(benches, bench_zkboo_prove, bench_zkboo_verify);
criterion_main!(benches);
