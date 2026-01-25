use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hornet::policy::blocklist::{Blocklist, BlocklistEntry, LeafBytes, ValueBytes};
use hornet::policy::plonk::PlonkPolicy;
use std::time::Duration;

fn build_policy() -> PlonkPolicy {
    let entries = vec![
        BlocklistEntry::Exact(ValueBytes::new(b"blocked.example").unwrap()),
        BlocklistEntry::Exact(ValueBytes::new(b"malicious.test").unwrap()),
    ];
    let blocklist = Blocklist::new(entries).expect("blocklist");
    let mut leaves = vec![LeafBytes::empty(); blocklist.len()];
    blocklist
        .canonical_leaves_into(&mut leaves)
        .expect("leaves");
    PlonkPolicy::new_with_blocklist(b"bench-policy", &leaves).expect("policy")
}

fn build_payloads(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|idx| format!("safe{idx}.example").into_bytes())
        .collect()
}

fn bench_prove_payload(c: &mut Criterion) {
    let policy = build_policy();
    let payload = ValueBytes::new(b"safe.example").unwrap();

    c.bench_function("policy/prove_payload", |b| {
        b.iter(|| {
            let capsule = policy.prove_payload(payload.as_slice()).expect("prove");
            black_box(capsule);
        });
    });
}

fn bench_prove_batch(c: &mut Criterion) {
    let policy = build_policy();
    let payloads = build_payloads(8);

    c.bench_function("policy/prove_batch", |b| {
        b.iter_batched(
            || payloads.clone(),
            |payloads| {
                let mut out = Vec::with_capacity(payloads.len());
                for payload in payloads {
                    out.push(policy.prove_payload(payload.as_slice()).expect("prove"));
                }
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_prove_batch_parallel_pool(c: &mut Criterion) {
    let policy = build_policy();
    let payloads = build_payloads(8);

    c.bench_function("policy/prove_batch_parallel_pool", |b| {
        b.iter_batched(
            || payloads.clone(),
            |payloads| {
                let mut out = Vec::with_capacity(payloads.len());
                for payload in payloads {
                    out.push(policy.prove_payload(payload.as_slice()).expect("prove"));
                }
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1));
    targets = bench_prove_payload, bench_prove_batch, bench_prove_batch_parallel_pool
}
criterion_main!(benches);
