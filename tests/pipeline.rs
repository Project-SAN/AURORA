mod suppert;

use aurora::application::forward::RegistryForwardPipeline;
use aurora::application::setup::RegistrySetupPipeline;
use aurora::core::policy::PolicyRegistry;
use aurora::core::policy::PolicyRole;
use aurora::node::pipeline::ForwardPipeline;
use aurora::policy::PolicyMetadata;
use aurora::setup::pipeline::SetupPipeline;
use aurora::types::Error;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use suppert::RecordingForward;

fn encode_capsule(capsule: &aurora::policy::PolicyCapsule) -> Vec<u8> {
    capsule.encode().expect("encode capsule")
}

fn demo_zkboo_policy() -> (aurora::policy::zkboo::ZkBooPolicy, PolicyMetadata) {
    // n_inputs=1, output = NOT(input0). Provide input0=0 to satisfy output==1.
    let mut circuit = aurora::crypto::zkp::Circuit::new(1);
    let one = circuit.add_not(0);
    circuit.set_outputs(&[one]);
    let policy = aurora::policy::zkboo::ZkBooPolicy::new(circuit);
    let metadata = policy.metadata(900, 0);
    (policy, metadata)
}

#[test]
fn registry_setup_pipeline_installs_metadata() {
    let (_policy, metadata) = demo_zkboo_policy();
    let mut registry = PolicyRegistry::new();
    {
        let mut pipeline = RegistrySetupPipeline::new(&mut registry);
        pipeline.install(metadata.clone()).expect("install");
    }
    assert!(registry.get(&metadata.policy_id).is_some());
}

#[test]
fn forward_pipeline_enforces_capsules() {
    let (policy, metadata) = demo_zkboo_policy();
    let mut registry = PolicyRegistry::new();
    registry
        .register(metadata.clone())
        .expect("register metadata");
    let validator = aurora::adapters::zkboo::validator::ZkBooCapsuleValidator::new();

    let mut rng = ChaCha20Rng::seed_from_u64(0x5151_5151);
    let capsule = policy.prove_with_rng(&[0u8], 16, &mut rng).expect("prove");

    let mut onwire = encode_capsule(&capsule);
    onwire.extend_from_slice(b"opaque-body");

    let forward_pipeline = RegistryForwardPipeline::new();
    let result = forward_pipeline
        .enforce(&registry, &mut onwire, &validator, PolicyRole::All)
        .expect("enforce pipeline")
        .expect("capsule present");
    assert_eq!(result.1, encode_capsule(&capsule).len());

    // Tampering should fail.
    let mut tampered = encode_capsule(&capsule);
    if let Some(byte) = tampered.last_mut() {
        *byte ^= 0xFF; // guaranteed in-bounds
    }
    let err = forward_pipeline
        .enforce(
            &registry,
            &mut tampered,
            &validator,
            aurora::core::policy::PolicyRole::All,
        )
        .unwrap_err();
    assert!(matches!(err, Error::PolicyViolation));
}

#[test]
fn recording_forward_captures_capsule() {
    let (policy, metadata) = demo_zkboo_policy();
    let mut registry = PolicyRegistry::new();
    registry
        .register(metadata.clone())
        .expect("register metadata");
    let validator = aurora::adapters::zkboo::validator::ZkBooCapsuleValidator::new();

    let mut rng = ChaCha20Rng::seed_from_u64(0xA5A5_A5A5);
    let capsule = policy.prove_with_rng(&[0u8], 16, &mut rng).expect("prove");
    let mut onwire = encode_capsule(&capsule);
    onwire.extend_from_slice(b"opaque-body");

    let recorder = RecordingForward::new();
    let result = recorder
        .enforce(&registry, &mut onwire, &validator, PolicyRole::All)
        .expect("enforce pipeline")
        .expect("capsule present");
    assert_eq!(result.0.policy_id, metadata.policy_id);
    assert!(recorder.last_capsule().is_some());
}
