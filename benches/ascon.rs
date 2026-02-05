use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hornet::crypto::ascon::hash256;

const CASES: &[usize] = &[0, 32, 64, 256, 1024, 16 * 1024];

fn bench_ascon_hash256(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto/ascon_hash256");
    for &size in CASES {
        let msg = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| {
                let digest = hash256(&msg);
                black_box(digest);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_ascon_hash256);
criterion_main!(benches);
