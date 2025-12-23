mod suppert;

use hornet::application::forward::{ForwardPipeline, RegistryForwardPipeline};
use hornet::application::setup::{RegistrySetupPipeline, SetupPipeline};
use hornet::core::policy::PolicyRegistry;
use hornet::policy::blocklist::BlocklistEntry;
use hornet::policy::plonk::{self, PlonkPolicy};
use hornet::policy::PolicyMetadata;
use hornet::types::Error;
use std::sync::Arc;
use suppert::RecordingForward;

fn demo_policy() -> (PlonkPolicy, PolicyMetadata) {
    let blocklist = vec![
        BlocklistEntry::Exact("blocked.example".into()).leaf_bytes(),
        BlocklistEntry::Exact("deny.test".into()).leaf_bytes(),
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

    let payload = BlocklistEntry::Exact("safe.example".into()).leaf_bytes();
    let capsule = policy.prove_payload(&payload).expect("prove payload");

    let mut onwire = capsule.encode();
    onwire.extend_from_slice(payload.as_slice());

    let forward_pipeline = RegistryForwardPipeline::new();
    let result = forward_pipeline
        .enforce(&registry, &mut onwire, &validator)
        .expect("enforce pipeline")
        .expect("capsule present");
    assert_eq!(result.1, capsule.encode().len());

    // Tampering should fail.
    let mut tampered = capsule.encode();
    if let Some(byte) = tampered.get_mut(50) {
        *byte ^= 0xFF;
    }
    let err = forward_pipeline
        .enforce(&registry, &mut tampered, &validator)
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

    let payload = BlocklistEntry::Exact("safe.record".into()).leaf_bytes();
    let capsule = policy.prove_payload(&payload).expect("prove payload");
    let mut onwire = capsule.encode();
    onwire.extend_from_slice(payload.as_slice());

    let recorder = RecordingForward::new();
    let result = recorder
        .enforce(&registry, &mut onwire, &validator)
        .expect("enforce pipeline")
        .expect("capsule present");
    assert_eq!(result.0.policy_id, metadata.policy_id);
    assert!(recorder.last_capsule().is_some());
}
