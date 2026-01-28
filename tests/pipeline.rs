mod suppert;

use hornet::application::forward::RegistryForwardPipeline;
use hornet::application::setup::RegistrySetupPipeline;
use hornet::core::policy::PolicyRegistry;
use hornet::node::pipeline::ForwardPipeline;
use hornet::policy::blocklist::{BlocklistEntry, ValueBytes};
use hornet::policy::plonk::{self, PlonkPolicy};
use hornet::policy::PolicyMetadata;
use hornet::setup::pipeline::SetupPipeline;
use hornet::types::Error;
use std::sync::Arc;
use suppert::RecordingForward;

fn encode_capsule(capsule: &hornet::policy::PolicyCapsule) -> Vec<u8> {
    let mut buf = [0u8; hornet::core::policy::MAX_CAPSULE_LEN];
    let len = capsule.encode_into(&mut buf).expect("encode capsule");
    buf[..len].to_vec()
}

fn demo_policy() -> (PlonkPolicy, PolicyMetadata) {
    let blocklist = vec![
        BlocklistEntry::Exact(ValueBytes::new(b"blocked.example").unwrap()).leaf_bytes(),
        BlocklistEntry::Exact(ValueBytes::new(b"deny.test").unwrap()).leaf_bytes(),
    ];
    let policy = PlonkPolicy::new_with_blocklist(b"pipeline-test", &blocklist).unwrap();
    let metadata = policy.metadata(900, 0);
    (policy, metadata)
}

#[test]
fn registry_setup_pipeline_installs_metadata() {
    let (_policy, metadata) = demo_policy();
    let mut registry = PolicyRegistry::new();
    {
        let mut pipeline = RegistrySetupPipeline::new(&mut registry);
        pipeline.install(metadata.clone()).expect("install");
    }
    assert!(registry.get(&metadata.policy_id).is_some());
}

#[test]
fn forward_pipeline_enforces_capsules() {
    let (policy, metadata) = demo_policy();
    plonk::register_policy(Arc::new(policy.clone()));
    let mut registry = PolicyRegistry::new();
    registry
        .register(metadata.clone())
        .expect("register metadata");
    let validator = hornet::adapters::plonk::validator::PlonkCapsuleValidator::new();

    let payload = BlocklistEntry::Exact(ValueBytes::new(b"safe.example").unwrap()).leaf_bytes();
    let capsule = policy
        .prove_payload(payload.as_slice())
        .expect("prove payload");

    let mut onwire = encode_capsule(&capsule);
    onwire.extend_from_slice(payload.as_slice());

    let forward_pipeline = RegistryForwardPipeline::new();
    let result = forward_pipeline
        .enforce(
            &registry,
            &mut onwire,
            &validator,
            hornet::core::policy::PolicyRole::All,
        )
        .expect("enforce pipeline")
        .expect("capsule present");
    assert_eq!(result.1, encode_capsule(&capsule).len());

    // Tampering should fail.
    let mut tampered = encode_capsule(&capsule);
    if let Some(byte) = tampered.get_mut(50) {
        *byte ^= 0xFF;
    }
    let err = forward_pipeline
        .enforce(
            &registry,
            &mut tampered,
            &validator,
            hornet::core::policy::PolicyRole::All,
        )
        .unwrap_err();
    assert!(matches!(err, Error::PolicyViolation));
}

#[test]
fn recording_forward_captures_capsule() {
    let (policy, metadata) = demo_policy();
    let mut registry = PolicyRegistry::new();
    registry
        .register(metadata.clone())
        .expect("register metadata");
    let validator = hornet::adapters::plonk::validator::PlonkCapsuleValidator::new();

    let payload = BlocklistEntry::Exact(ValueBytes::new(b"safe.record").unwrap()).leaf_bytes();
    let capsule = policy
        .prove_payload(payload.as_slice())
        .expect("prove payload");
    let mut onwire = encode_capsule(&capsule);
    onwire.extend_from_slice(payload.as_slice());

    let recorder = RecordingForward::new();
    let result = recorder
        .enforce(
            &registry,
            &mut onwire,
            &validator,
            hornet::core::policy::PolicyRole::All,
        )
        .expect("enforce pipeline")
        .expect("capsule present");
    assert_eq!(result.0.policy_id, metadata.policy_id);
    assert!(recorder.last_capsule().is_some());
}
