use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hornet::api::prove::{bench_submit_batch, BenchJob, PolicyAuthorityState, ProofPipelineHandle};
use hornet::application::prove::{ProveInput, ProofPipeline};
use hornet::core::policy::PolicyId;
use hornet::policy::blocklist::{Blocklist, BlocklistEntry, LeafBytes, ValueBytes};
use hornet::policy::extract::HttpHostExtractor;
use hornet::policy::plonk::{self, PlonkPolicy};
use std::sync::Arc;
use std::time::Duration;

struct BenchContext {
    state: PolicyAuthorityState,
    policy_id: PolicyId,
}

fn build_context() -> BenchContext {
    let entries = vec![
        BlocklistEntry::Exact(ValueBytes::new(b"blocked.example").unwrap()),
        BlocklistEntry::Exact(ValueBytes::new(b"malicious.test").unwrap()),
    ];
    let blocklist = Blocklist::new(entries).expect("blocklist");
    let mut leaves = vec![LeafBytes::empty(); blocklist.len()];
    blocklist
        .canonical_leaves_into(&mut leaves)
        .expect("leaves");
    let policy = Arc::new(PlonkPolicy::new_with_blocklist(b"bench-policy", &leaves).unwrap());
    plonk::register_policy(policy.clone());

    let mut state = PolicyAuthorityState::new();
    let policy_id = state.register_policy(policy, HttpHostExtractor::default());
    BenchContext { state, policy_id }
}

fn build_context_shared() -> (Arc<PolicyAuthorityState>, Arc<ProofPipelineHandle>, PolicyId) {
    let entries = vec![
        BlocklistEntry::Exact(ValueBytes::new(b"blocked.example").unwrap()),
        BlocklistEntry::Exact(ValueBytes::new(b"malicious.test").unwrap()),
    ];
    let blocklist = Blocklist::new(entries).expect("blocklist");
    let mut leaves = vec![LeafBytes::empty(); blocklist.len()];
    blocklist
        .canonical_leaves_into(&mut leaves)
        .expect("leaves");
    let policy = Arc::new(PlonkPolicy::new_with_blocklist(b"bench-policy", &leaves).unwrap());
    plonk::register_policy(policy.clone());

    let mut state = PolicyAuthorityState::new();
    let policy_id = state.register_policy(policy, HttpHostExtractor::default());
    let state = Arc::new(state);
    let pipeline: Arc<ProofPipelineHandle> = state.clone();
    (state, pipeline, policy_id)
}

fn bench_prove_pipeline(c: &mut Criterion) {
    let ctx = build_context();
    let payload = b"GET / HTTP/1.1\r\nHost: safe.example\r\n\r\n";
    let aux: [u8; 0] = [];

    c.bench_function("api/prove_pipeline", |b| {
        b.iter(|| {
            let input = ProveInput {
                policy_id: ctx.policy_id,
                payload,
                aux: &aux,
            };
            let capsule = ctx.state.prove(input).expect("prove");
            black_box(capsule);
        });
    });
}

fn bench_prove_batch_pipeline(c: &mut Criterion) {
    let ctx = build_context();
    let payloads: Vec<Vec<u8>> = (0..8)
        .map(|idx| {
            format!(
                "GET / HTTP/1.1\r\nHost: safe{idx}.example\r\n\r\n"
            )
            .into_bytes()
        })
        .collect();
    let auxes: Vec<Vec<u8>> = vec![Vec::new(); payloads.len()];

    c.bench_function("api/prove_batch_pipeline", |b| {
        b.iter_batched(
            || {
                payloads
                    .iter()
                    .zip(auxes.iter())
                    .map(|(payload, aux)| ProveInput {
                        policy_id: ctx.policy_id,
                        payload,
                        aux,
                    })
                    .collect::<Vec<_>>()
            },
            |inputs| {
                let capsules = ctx.state.prove_batch(&inputs).expect("prove_batch");
                black_box(capsules);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_prove_batch_parallel_pool(c: &mut Criterion) {
    let (_state, pipeline, policy_id) = build_context_shared();
    let payloads: Vec<Vec<u8>> = (0..8)
        .map(|idx| {
            format!(
                "GET / HTTP/1.1\r\nHost: safe{idx}.example\r\n\r\n"
            )
            .into_bytes()
        })
        .collect();
    let auxes: Vec<Vec<u8>> = vec![Vec::new(); payloads.len()];

    c.bench_function("api/prove_batch_parallel_pool", |b| {
        b.iter_batched(
            || {
                payloads
                    .iter()
                    .zip(auxes.iter())
                    .map(|(payload, aux)| BenchJob {
                        policy_id,
                        payload: payload.clone(),
                        aux: aux.clone(),
                    })
                    .collect::<Vec<_>>()
            },
            |jobs| {
                let capsules =
                    bench_submit_batch(pipeline.clone(), jobs).expect("prove_batch parallel");
                black_box(capsules);
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
    targets = bench_prove_pipeline, bench_prove_batch_pipeline, bench_prove_batch_parallel_pool
}
criterion_main!(benches);
