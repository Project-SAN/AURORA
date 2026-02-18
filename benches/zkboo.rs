use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hornet::crypto::zkp::ascon_circuit;
use hornet::crypto::zkp::{Proof, ProverConfig, VerifierConfig, ZkBooEngine};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const ROUND_CASES: &[u16] = &[1, 4, 8, 16, 32];

fn bits_lsb(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for bit in 0..8u8 {
            out.push((b >> bit) & 1);
        }
    }
    out
}

fn payload_hash_fixture_32b() -> (hornet::crypto::zkp::Circuit, Vec<u8>, Vec<u8>) {
    let payload = vec![0xA5u8; 32];
    let payload_bits = bits_lsb(&payload);
    let hash_circuit = ascon_circuit::build_payload_hash_circuit(32);
    let hash_output = hash_circuit.eval(&payload_bits).expect("eval");
    (hash_circuit, payload_bits, hash_output)
}

fn bench_zkboo_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkboo/eval");
    let (circuit, input, _) = payload_hash_fixture_32b();
    group.bench_function(BenchmarkId::from_parameter("payload_hash_32b"), |b| {
        b.iter(|| {
            let out = circuit.eval(black_box(&input)).expect("eval");
            black_box(out);
        });
    });
    group.finish();
}

fn bench_zkboo_prove_round_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkboo/prove_round_scaling");
    let (circuit, input, output) = payload_hash_fixture_32b();
    for &rounds in ROUND_CASES {
        group.bench_function(BenchmarkId::from_parameter(format!("rounds{rounds}")), |b| {
            let mut rng = ChaCha20Rng::seed_from_u64(0x88BB_99CC_DDEE_F011 + rounds as u64);
            b.iter(|| {
                let proof = ZkBooEngine
                    .prove_circuit_with_rng(
                        &circuit,
                        black_box(&input),
                        black_box(&output),
                        ProverConfig { rounds },
                        &mut rng,
                    )
                    .expect("prove");
                black_box(proof);
            });
        });
    }
    group.finish();
}

fn bench_zkboo_verify_round_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkboo/verify_round_scaling");
    let (circuit, input, output) = payload_hash_fixture_32b();
    for &rounds in ROUND_CASES {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FF_EE00 + rounds as u64);
        let proof = ZkBooEngine
            .prove_circuit_with_rng(&circuit, &input, &output, ProverConfig { rounds }, &mut rng)
            .expect("prove");
        group.bench_function(BenchmarkId::from_parameter(format!("rounds{rounds}")), |b| {
            b.iter(|| {
                ZkBooEngine
                    .verify_circuit(
                        &circuit,
                        black_box(&output),
                        black_box(&proof),
                        VerifierConfig { rounds },
                    )
                    .expect("verify");
            });
        });
    }
    group.finish();
}

fn bench_zkboo_proof_serdes(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkboo/proof_serdes");
    let (circuit, input, output) = payload_hash_fixture_32b();
    let rounds = 16u16;
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF_1234);
    let proof = ZkBooEngine
        .prove_circuit_with_rng(&circuit, &input, &output, ProverConfig { rounds }, &mut rng)
        .expect("prove");
    let encoded = proof.encode().expect("encode");

    group.bench_function(BenchmarkId::from_parameter("encode_rounds16"), |b| {
        b.iter(|| {
            let bytes = proof.encode().expect("encode");
            black_box(bytes);
        });
    });
    group.bench_function(BenchmarkId::from_parameter("decode_rounds16"), |b| {
        b.iter(|| {
            let (decoded, consumed) = Proof::decode(black_box(&encoded)).expect("decode");
            black_box(decoded);
            black_box(consumed);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_zkboo_eval,
    bench_zkboo_prove_round_scaling,
    bench_zkboo_verify_round_scaling,
    bench_zkboo_proof_serdes
);
criterion_main!(benches);
