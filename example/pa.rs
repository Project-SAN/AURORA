use hornet::adapters::plonk::validator::PlonkCapsuleValidator;
use hornet::policy::blocklist::{BlocklistEntry, LeafBytes, ValueBytes};
use hornet::policy::plonk::{self, PlonkPolicy};
use hornet::policy::{PolicyCapsule, PolicyMetadata, PolicyRegistry};
use hornet::core::policy::ProofKind;
use hornet::types::{Error, Result};
use hornet::utils::encode_hex;

fn main() {
    if let Err(err) = run_demo() {
        eprintln!("PA demo failed: {err:?}");
        std::process::exit(1);
    }
}

fn run_demo() -> Result<()> {
    // Policy Authority publishes a blocklist and associated proving/verifying keys.
    let blocklist = demo_blocklist();
    let policy = PlonkPolicy::new_with_blocklist(b"demo-pa", &blocklist)?;
    let metadata = policy.metadata(900, 0);
    println!("Policy ID      : {}", encode_hex(&metadata.policy_id));
    println!("Blocked targets: blocked.example, malicious.test\n");

    // Client extracts the target value from its payload and locally generates a proof.
    let safe_leaf = canonical_leaf("safe.example");
    let capsule = policy.prove_payload(safe_leaf.as_slice())?;
    println!("Client produced capsule for safe.example");
    let policy_part = capsule
        .part(ProofKind::Policy)
        .ok_or(Error::PolicyViolation)?;
    println!("  proof bytes : {}", policy_part.proof.len());
    println!(
        "  commitment  : {}\n",
        encode_hex(&policy_part.commitment)
    );

    // Client submits the capsule to the PA for verification before transmission.
    verify_capsule(&metadata, &capsule, safe_leaf.as_slice())?;
    println!("PA verification succeeded for safe.example\n");

    // Attempts to prove a blocked value fail client-side: the prover cannot invert zero.
    let blocked_leaf = canonical_leaf("blocked.example");
    match policy.prove_payload(blocked_leaf.as_slice()) {
        Ok(_) => println!("unexpected success proving blocked target"),
        Err(Error::PolicyViolation) => {
            println!("Client rejected blocked.example before contacting the PA\n")
        }
        Err(err) => return Err(err),
    }

    // Tampering with the declared payload causes the PA-side verification to fail.
    let tampered_leaf = canonical_leaf("unrelated.example");
    match verify_capsule(&metadata, &capsule, tampered_leaf.as_slice()) {
        Ok(_) => println!("tampering went undetected (unexpected)"),
        Err(Error::PolicyViolation) => {
            println!("PA rejected capsule because the commitment mismatched the payload")
        }
        Err(err) => return Err(err),
    }

    Ok(())
}

fn demo_blocklist() -> Vec<LeafBytes> {
    vec![
        BlocklistEntry::Exact(ValueBytes::new(b"blocked.example").unwrap()).leaf_bytes(),
        BlocklistEntry::Exact(ValueBytes::new(b"malicious.test").unwrap()).leaf_bytes(),
    ]
}

fn canonical_leaf(host: &str) -> LeafBytes {
    let lower = host.to_ascii_lowercase();
    BlocklistEntry::Exact(ValueBytes::new(lower.as_bytes()).unwrap()).leaf_bytes()
}

fn verify_capsule(
    metadata: &PolicyMetadata,
    capsule: &PolicyCapsule,
    target_leaf: &[u8],
) -> Result<()> {
    let mut registry = PolicyRegistry::new();
    registry.register(metadata.clone())?;
    let validator = PlonkCapsuleValidator::new();

    // In the API, the PA receives raw capsule bytes; mimic that flow here.
    let mut capsule_buf = [0u8; hornet::core::policy::MAX_CAPSULE_LEN];
    let capsule_len = capsule
        .encode_into(&mut capsule_buf)
        .expect("encode capsule");
    let mut capsule_bytes = Vec::with_capacity(capsule_len);
    capsule_bytes.extend_from_slice(&capsule_buf[..capsule_len]);
    let (decoded, consumed) = registry.enforce(&mut capsule_bytes, &validator)?;
    if consumed != capsule_bytes.len() {
        return Err(Error::PolicyViolation);
    }
    if decoded.policy_id != metadata.policy_id {
        return Err(Error::PolicyViolation);
    }

    let expected_commit = plonk::payload_commitment_bytes(target_leaf);
    let policy_part = decoded
        .part(ProofKind::Policy)
        .ok_or(Error::PolicyViolation)?;
    if expected_commit != policy_part.commitment {
        return Err(Error::PolicyViolation);
    }

    Ok(())
}
