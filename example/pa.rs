use hornet::adapters::plonk::validator::PlonkCapsuleValidator;
use hornet::policy::blocklist::BlocklistEntry;
use hornet::policy::plonk::{self, PlonkPolicy};
use hornet::policy::{PolicyCapsule, PolicyMetadata, PolicyRegistry};
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
    let capsule = policy.prove_payload(&safe_leaf)?;
    println!("Client produced capsule for safe.example");
    println!("  proof bytes : {}", capsule.proof.len());
    println!("  commitment  : {}\n", encode_hex(&capsule.commitment));

    // Client submits the capsule to the PA for verification before transmission.
    verify_capsule(&metadata, &capsule, &safe_leaf)?;
    println!("PA verification succeeded for safe.example\n");

    // Attempts to prove a blocked value fail client-side: the prover cannot invert zero.
    let blocked_leaf = canonical_leaf("blocked.example");
    match policy.prove_payload(&blocked_leaf) {
        Ok(_) => println!("unexpected success proving blocked target"),
        Err(Error::PolicyViolation) => {
            println!("Client rejected blocked.example before contacting the PA\n")
        }
        Err(err) => return Err(err),
    }

    // Tampering with the declared payload causes the PA-side verification to fail.
    let tampered_leaf = canonical_leaf("unrelated.example");
    match verify_capsule(&metadata, &capsule, &tampered_leaf) {
        Ok(_) => println!("tampering went undetected (unexpected)"),
        Err(Error::PolicyViolation) => {
            println!("PA rejected capsule because the commitment mismatched the payload")
        }
        Err(err) => return Err(err),
    }

    Ok(())
}

fn demo_blocklist() -> Vec<Vec<u8>> {
    vec![
        BlocklistEntry::Exact("blocked.example".into()).leaf_bytes(),
        BlocklistEntry::Exact("malicious.test".into()).leaf_bytes(),
    ]
}

fn canonical_leaf(host: &str) -> Vec<u8> {
    BlocklistEntry::Exact(host.to_ascii_lowercase()).leaf_bytes()
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
    let mut capsule_bytes = capsule.encode();
    let (decoded, consumed) = registry.enforce(&mut capsule_bytes, &validator)?;
    if consumed != capsule_bytes.len() {
        return Err(Error::PolicyViolation);
    }
    if decoded.policy_id != metadata.policy_id {
        return Err(Error::PolicyViolation);
    }

    let expected_commit = plonk::payload_commitment_bytes(target_leaf);
    if expected_commit != decoded.commitment {
        return Err(Error::PolicyViolation);
    }

    Ok(())
}
