use hornet::adapters::plonk::validator::PlonkCapsuleValidator;
use hornet::application::forward::RegistryForwardPipeline;
use hornet::node::{NodeCtx, PolicyRuntime};
use hornet::policy::blocklist::{BlocklistEntry, LeafBytes, ValueBytes};
use hornet::policy::plonk::{KeyBindingInputs, PlonkPolicy};
use hornet::policy::{PolicyCapsule, PolicyMetadata, PolicyRegistry};
use hornet::core::policy::{
    encode_extensions_into, CapsuleExtensionRef, PolicyRole, ProofKind, AUX_MAX,
    EXT_TAG_PCD_KEY_HASH,
    EXT_TAG_PCD_TARGET_HASH, EXT_TAG_ROUTE_ID, EXT_TAG_SESSION_NONCE,
    MAX_CAPSULE_LEN,
};
use hornet::types::{Ahdr, Chdr, Exp, Nonce, PacketDirection, Result, RoutingSegment};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

#[cfg(unix)]
fn cpu_time() -> Duration {
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return Duration::from_secs(0);
        }
        let user = Duration::new(usage.ru_utime.tv_sec as u64, (usage.ru_utime.tv_usec as u32) * 1000);
        let sys = Duration::new(usage.ru_stime.tv_sec as u64, (usage.ru_stime.tv_usec as u32) * 1000);
        user + sys
    }
}

#[cfg(not(unix))]
fn cpu_time() -> Duration {
    Duration::from_secs(0)
}

struct FixedTimeProvider {
    now: u32,
}

impl hornet::time::TimeProvider for FixedTimeProvider {
    fn now_coarse(&self) -> u32 {
        self.now
    }
}

struct CaptureForward {
    slot: Rc<RefCell<Option<Ahdr>>>,
}

impl CaptureForward {
    fn new(slot: Rc<RefCell<Option<Ahdr>>>) -> Self {
        Self { slot }
    }
}

impl hornet::forward::Forward for CaptureForward {
    fn send(
        &mut self,
        _rseg: &RoutingSegment,
        _chdr: &Chdr,
        ahdr: &Ahdr,
        _payload: &mut Vec<u8>,
        _direction: PacketDirection,
    ) -> Result<()> {
        self.slot.borrow_mut().replace(clone_ahdr(ahdr));
        Ok(())
    }
}

fn clone_ahdr(ahdr: &Ahdr) -> Ahdr {
    Ahdr {
        bytes: ahdr.bytes.clone(),
    }
}

fn udp_route(port: u16) -> RoutingSegment {
    let mut bytes = Vec::with_capacity(8);
    bytes.push(0x01);
    bytes.push(6);
    bytes.extend_from_slice(&[127, 0, 0, 1]);
    bytes.extend_from_slice(&port.to_be_bytes());
    RoutingSegment(bytes)
}

fn deliver_route() -> RoutingSegment {
    RoutingSegment(vec![0xFF, 0x00])
}

struct ForwardFixture {
    now: u32,
    svs: Vec<hornet::types::Sv>,
    keys: Vec<hornet::types::Si>,
    ahdr: Ahdr,
    iv0: Nonce,
}

impl ForwardFixture {
    fn new(hops: usize) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5EED_F00Du64 ^ hops as u64);
        let now = 1_690_000_000u32;
        let exp = Exp(now.saturating_add(600));

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
            .map(|i| hornet::packet::core::create(&svs[i], &keys[i], &routing[i], exp))
            .collect::<Result<Vec<_>>>()
            .expect("fs create");

        let mut rng_ahdr = ChaCha20Rng::seed_from_u64(0xA11C_E5EEDu64 ^ hops as u64);
        let ahdr =
            hornet::packet::ahdr::create_ahdr(&keys, &fses, hornet::types::R_MAX, &mut rng_ahdr)
                .expect("fixture ahdr");

        let mut iv0_bytes = [0u8; 16];
        rng.fill_bytes(&mut iv0_bytes);
        let iv0 = Nonce(iv0_bytes);

        Self {
            now,
            svs,
            keys,
            ahdr,
            iv0,
        }
    }
}

fn run_forward_chain(
    fixture: &ForwardFixture,
    time: &FixedTimeProvider,
    policy: Option<PolicyRuntime<'_>>,
    chdr: &mut Chdr,
    ahdr: &mut Ahdr,
    payload: &mut Vec<u8>,
) -> Result<()> {
    let slot: Rc<RefCell<Option<Ahdr>>> = Rc::new(RefCell::new(None));
    for &sv in &fixture.svs {
        slot.borrow_mut().take();
        let mut forward = CaptureForward::new(slot.clone());
        let mut replay = hornet::node::NoReplay;
        let mut ctx = NodeCtx {
            sv,
            now: time,
            forward: &mut forward,
            replay: &mut replay,
            policy,
            exit: None,
        };
        hornet::node::forward::process_data(&mut ctx, chdr, ahdr, payload)?;
        if let Some(next) = slot.borrow_mut().take() {
            *ahdr = next;
        }
    }
    Ok(())
}

fn canonical_leaf(host: &str) -> LeafBytes {
    let lower = host.to_ascii_lowercase();
    BlocklistEntry::Exact(ValueBytes::new(lower.as_bytes()).unwrap()).leaf_bytes()
}

fn build_blocklist(n: usize) -> Vec<LeafBytes> {
    (0..n)
        .map(|i| {
            let value = format!("blocked{idx}.example", idx = i);
            BlocklistEntry::Exact(ValueBytes::new(value.as_bytes()).unwrap()).leaf_bytes()
        })
        .collect()
}

fn build_keybinding_inputs() -> KeyBindingInputs {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBEEF_CAFE);
    let mut sender_secret = [0u8; 32];
    let mut htarget = [0u8; 32];
    let mut session_nonce = [0u8; 32];
    let mut route_id = [0u8; 32];
    rng.fill_bytes(&mut sender_secret);
    rng.fill_bytes(&mut htarget);
    rng.fill_bytes(&mut session_nonce);
    rng.fill_bytes(&mut route_id);
    KeyBindingInputs {
        sender_secret,
        htarget,
        session_nonce,
        route_id,
    }
}

fn attach_keybinding_extensions(
    capsule: &mut PolicyCapsule,
    keybinding: &KeyBindingInputs,
) -> Result<()> {
    let hkey = capsule
        .part(ProofKind::KeyBinding)
        .map(|part| part.commitment)
        .unwrap_or([0u8; 32]);
        for part in capsule
            .parts
            .iter_mut()
            .take(capsule.part_count as usize)
        {
            match part.kind {
                ProofKind::Consistency => {
                    let exts = [
                        CapsuleExtensionRef {
                            tag: EXT_TAG_PCD_KEY_HASH,
                            data: &hkey,
                        },
                        CapsuleExtensionRef {
                            tag: EXT_TAG_PCD_TARGET_HASH,
                            data: &keybinding.htarget,
                        },
                    ];
                    let mut aux_buf = [0u8; AUX_MAX];
                    let aux_len = encode_extensions_into(&exts, &mut aux_buf)
                        .expect("encode consistency exts");
                    part.set_aux(&aux_buf[..aux_len]).expect("set aux");
                }
                ProofKind::KeyBinding => {
                    let exts = [
                        CapsuleExtensionRef {
                            tag: EXT_TAG_PCD_KEY_HASH,
                            data: &hkey,
                        },
                        CapsuleExtensionRef {
                            tag: EXT_TAG_SESSION_NONCE,
                            data: &keybinding.session_nonce,
                        },
                        CapsuleExtensionRef {
                            tag: EXT_TAG_ROUTE_ID,
                            data: &keybinding.route_id,
                        },
                    ];
                    let mut aux_buf = [0u8; AUX_MAX];
                    let aux_len =
                        encode_extensions_into(&exts, &mut aux_buf).expect("encode key exts");
                    part.set_aux(&aux_buf[..aux_len]).expect("set aux");
                }
                _ => {}
            }
        }
    Ok(())
}

fn verify_capsule(
    metadata: &PolicyMetadata,
    capsule: &PolicyCapsule,
    target_leaf: &[u8],
    registry: &PolicyRegistry,
    validator: &PlonkCapsuleValidator,
) -> Result<()> {
    let mut capsule_buf = [0u8; MAX_CAPSULE_LEN];
    let capsule_len = capsule.encode_into(&mut capsule_buf).expect("encode");
    let mut capsule_bytes = Vec::with_capacity(capsule_len);
    capsule_bytes.extend_from_slice(&capsule_buf[..capsule_len]);
    let (decoded, consumed) = registry.enforce(&mut capsule_bytes, validator)?;
    if consumed != capsule_bytes.len() {
        return Err(hornet::types::Error::PolicyViolation);
    }
    if decoded.policy_id != metadata.policy_id {
        return Err(hornet::types::Error::PolicyViolation);
    }
    let expected_commit = hornet::policy::plonk::payload_commitment_bytes(target_leaf);
    let policy_part = decoded
        .part(hornet::core::policy::ProofKind::Policy)
        .ok_or(hornet::types::Error::PolicyViolation)?;
    if expected_commit != policy_part.commitment {
        return Err(hornet::types::Error::PolicyViolation);
    }
    Ok(())
}

fn bench_loop<F>(label: &str, iters: usize, mut f: F) -> (Duration, Duration)
where
    F: FnMut(),
{
    let cpu_start = cpu_time();
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let cpu = cpu_time().saturating_sub(cpu_start);
    let cpu_pct = if elapsed.as_secs_f64() > 0.0 {
        (cpu.as_secs_f64() / elapsed.as_secs_f64()) * 100.0
    } else {
        0.0
    };
    println!(
        "{label}: wall={:.3} ms, cpu={:.3} ms, cpu%={:.1}",
        elapsed.as_secs_f64() * 1e3,
        cpu.as_secs_f64() * 1e3,
        cpu_pct
    );
    (elapsed, cpu)
}

fn main() -> Result<()> {
    std::env::set_var("HORNET_KEYBINDING_HASH", "poseidon");
    std::env::set_var("HORNET_KEYBINDING_LOG2", "17");
    let hops = 3usize;
    let payload_cases = [
        ("tiny", 128usize),
        ("dns_like", 256usize),
        ("small", 512usize),
        ("http_small", 1024usize),
        ("http_medium", 4096usize),
        ("http_large", 8192usize),
    ];
    let blocklist_sizes = [64usize, 128usize, 256usize];

    // Ensure we don't load a verifier cache without a prover.
    let _ = std::fs::remove_file("target/keybinding-verifier-poseidon.bin");
    let _ = std::fs::remove_file("target/keybinding-verifier.bin");
    let keybinding = build_keybinding_inputs();
    let leaf = canonical_leaf("safe.example");
    let validator = PlonkCapsuleValidator::new();
    let pipeline = RegistryForwardPipeline::new();
    let fixture = ForwardFixture::new(hops);
    let time = FixedTimeProvider { now: fixture.now };

    for blocklist_size in blocklist_sizes {
        println!("\n== Blocklist size: {} ==", blocklist_size);
        let blocklist = build_blocklist(blocklist_size);
        let policy = match PlonkPolicy::new_with_blocklist(b"bench-policy", &blocklist) {
            Ok(policy) => policy,
            Err(err) => {
                eprintln!("policy init failed (blocklist={}): {err:?}", blocklist_size);
                return Err(err);
            }
        };
        let mut registry = PolicyRegistry::new();

        // Warm-up to populate caches.
        if let Err(err) = policy.prove_payload(leaf.as_slice()) {
            eprintln!("policy-only prove failed: {err:?}");
            return Err(err);
        }
        if let Err(err) = policy.prove_payload_with_keybinding(leaf.as_slice(), Some(keybinding)) {
            eprintln!("keybinding prove failed: {err:?}");
            return Err(err);
        }

        let metadata = policy.metadata(900, 0);
        registry.register(metadata.clone())?;

        println!("== Proving / Verify ==");
        let prove_iters = 5usize;
        let (prove_wall, prove_cpu) = bench_loop("prove_payload_with_keybinding", prove_iters, || {
            let _ = policy
                .prove_payload_with_keybinding(leaf.as_slice(), Some(keybinding))
                .expect("prove");
        });
        let prove_avg_ms = prove_wall.as_secs_f64() * 1e3 / prove_iters as f64;
        let prove_cpu_ms = prove_cpu.as_secs_f64() * 1e3 / prove_iters as f64;
        println!(
            "prove_avg_ms={:.3}, prove_cpu_ms={:.3}",
            prove_avg_ms, prove_cpu_ms
        );

        let capsule = policy.prove_payload_with_keybinding(leaf.as_slice(), Some(keybinding))?;
        let mut capsule = capsule;
        attach_keybinding_extensions(&mut capsule, &keybinding)?;
        let verify_iters = 20usize;
        let (verify_wall, verify_cpu) = bench_loop("verify_capsule", verify_iters, || {
            verify_capsule(&metadata, &capsule, leaf.as_slice(), &registry, &validator)
                .expect("verify");
        });
        let verify_avg_ms = verify_wall.as_secs_f64() * 1e3 / verify_iters as f64;
        let verify_cpu_ms = verify_cpu.as_secs_f64() * 1e3 / verify_iters as f64;
        println!(
            "verify_avg_ms={:.3}, verify_cpu_ms={:.3}",
            verify_avg_ms, verify_cpu_ms
        );

        println!("== End-to-End (3 hops, policy enforced) ==");
        for (label, tail_len) in payload_cases {
            let mut rng = ChaCha20Rng::seed_from_u64(0x00C0_FFEE_u64 ^ tail_len as u64);
            let mut tail = vec![0u8; tail_len];
            rng.fill_bytes(&mut tail);

            let iters = 50usize;
            let (wall, cpu) = bench_loop(label, iters, || {
                let mut chdr = hornet::packet::chdr::data_header(hops as u8, fixture.iv0);
                let mut ahdr = clone_ahdr(&fixture.ahdr);
                let mut encrypted_tail = tail.clone();
                let mut iv = fixture.iv0;
                hornet::source::build(&mut chdr, &ahdr, &fixture.keys, &mut iv, &mut encrypted_tail)
                    .expect("build");
                let mut cap_buf = [0u8; MAX_CAPSULE_LEN];
                let cap_len = capsule.encode_into(&mut cap_buf).expect("encode");
                let mut payload = Vec::with_capacity(cap_len);
                payload.extend_from_slice(&cap_buf[..cap_len]);
                payload.extend_from_slice(&encrypted_tail);
                let mut roles = std::collections::BTreeMap::new();
                roles.insert(metadata.policy_id, PolicyRole::All);
                let policy_rt = PolicyRuntime {
                    registry: &registry,
                    validator: &validator,
                    forward: &pipeline,
                    roles: &roles,
                };
                run_forward_chain(
                    &fixture,
                    &time,
                    Some(policy_rt),
                    &mut chdr,
                    &mut ahdr,
                    &mut payload,
                )
                .expect("forward chain");
            });
            let avg_ms = wall.as_secs_f64() * 1e3 / iters as f64;
            let cpu_ms = cpu.as_secs_f64() * 1e3 / iters as f64;
            let bytes = tail_len as f64;
            let throughput_bps = bytes * iters as f64 / wall.as_secs_f64();
            let throughput_mbps = throughput_bps * 8.0 / 1e6;
            println!(
                "{label}: avg_ms={:.3}, cpu_ms={:.3}, throughput_mbps={:.3}",
                avg_ms, cpu_ms, throughput_mbps
            );
        }
    }

    Ok(())
}
