use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::core::policy::{
    CapsuleValidator,
    PolicyCapsule,
    PolicyId,
    PolicyMetadata,
    PollingCapsuleValidator,
    ValidateQueue,
};
use crate::types::{Error, Result};
use crate::policy::plonk::{POLICY_FLAG_ROLE_OPEN, POLICY_FLAG_ROLE_PARSE};
use dusk_bytes::Serializable;
use dusk_plonk::{composer::Verifier as PlonkVerifier, prelude::BlsScalar, proof_system::Proof};
use spin::Mutex;

pub struct PlonkCapsuleValidator {
    cache: Mutex<BTreeMap<PolicyId, Arc<PlonkVerifier>>>,
}

impl PlonkCapsuleValidator {
    pub const fn new() -> Self {
        Self {
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn load_verifier(&self, metadata: &PolicyMetadata) -> Result<Option<Arc<PlonkVerifier>>> {
        if metadata.verifier_blob.is_empty() {
            return Ok(None);
        }
        let mut cache = self.cache.lock();
        if let Some(verifier) = cache.get(&metadata.policy_id) {
            return Ok(Some(verifier.clone()));
        }
        let verifier = PlonkVerifier::try_from_bytes(metadata.verifier_blob.as_slice())
            .map_err(|_| Error::PolicyViolation)?;
        let verifier = Arc::new(verifier);
        cache.insert(metadata.policy_id, verifier.clone());
        Ok(Some(verifier))
    }

    fn validate_proof(verifier: &PlonkVerifier, capsule: &PolicyCapsule) -> Result<()> {
        if capsule.proof.len() != Proof::SIZE {
            return Err(Error::PolicyViolation);
        }
        let mut proof_bytes = [0u8; Proof::SIZE];
        proof_bytes.copy_from_slice(&capsule.proof);
        let proof = Proof::from_bytes(&proof_bytes).map_err(|_| Error::PolicyViolation)?;

        if capsule.commitment.len() != BlsScalar::SIZE {
            return Err(Error::PolicyViolation);
        }
        let mut commit_bytes = [0u8; BlsScalar::SIZE];
        commit_bytes.copy_from_slice(&capsule.commitment);
        let target_hash =
            BlsScalar::from_bytes(&commit_bytes).map_err(|_| Error::PolicyViolation)?;

        verifier
            .verify(&proof, core::slice::from_ref(&target_hash))
            .map_err(|_| Error::PolicyViolation)
    }
}

impl CapsuleValidator for PlonkCapsuleValidator {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()> {
        if (metadata.flags & (POLICY_FLAG_ROLE_OPEN | POLICY_FLAG_ROLE_PARSE)) != 0 {
            return Ok(());
        }
        let Some(verifier) = self.load_verifier(metadata)? else {
            return Ok(());
        };
        Self::validate_proof(&verifier, capsule)
    }
}

pub struct QueuedValidationJob {
    pub capsule: PolicyCapsule,
    pub metadata: PolicyMetadata,
}

pub trait ViolationSink {
    fn on_violation(&mut self, job: &QueuedValidationJob, err: Error);
}

pub struct NoopViolationSink;

impl ViolationSink for NoopViolationSink {
    fn on_violation(&mut self, _job: &QueuedValidationJob, _err: Error) {}
}

pub struct QueuedCapsuleValidator<const N: usize> {
    queue: ValidateQueue<QueuedValidationJob, N>,
    inner: PlonkCapsuleValidator,
}

impl<const N: usize> QueuedCapsuleValidator<N> {
    pub const fn new() -> Self {
        Self {
            queue: ValidateQueue::new(),
            inner: PlonkCapsuleValidator::new(),
        }
    }

    pub fn poll(&self, budget: usize, sink: &mut dyn ViolationSink) -> usize {
        let mut processed = 0;
        for _ in 0..budget {
            let Some(job) = self.queue.pop() else {
                break;
            };
            processed += 1;
            if let Err(err) = self.inner.validate(&job.capsule, &job.metadata) {
                sink.on_violation(&job, err);
            }
        }
        processed
    }

    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }
}

impl<const N: usize> CapsuleValidator for QueuedCapsuleValidator<N> {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()> {
        let job = QueuedValidationJob {
            capsule: capsule.clone(),
            metadata: metadata.clone(),
        };
        self.queue.push(job).map_err(|_| Error::PolicyViolation)
    }
}

impl<const N: usize> PollingCapsuleValidator for QueuedCapsuleValidator<N> {
    fn poll_validation(&self, budget: usize) -> usize {
        let mut sink = NoopViolationSink;
        self.poll(budget, &mut sink)
    }
}

#[cfg(feature = "std")]
struct ValidationJob {
    capsule: PolicyCapsule,
    metadata: PolicyMetadata,
}

#[cfg(feature = "std")]
pub struct AsyncCapsuleValidator {
    tx: std::sync::mpsc::Sender<ValidationJob>,
}

#[cfg(feature = "std")]
impl AsyncCapsuleValidator {
    pub fn new() -> Self {
        use std::sync::mpsc;
        use std::thread;
        let (tx, rx) = mpsc::channel::<ValidationJob>();
        thread::spawn(move || {
            let validator = PlonkCapsuleValidator::new();
            while let Ok(job) = rx.recv() {
                if let Err(err) = validator.validate(&job.capsule, &job.metadata) {
                    eprintln!(
                        "async policy validation failed: policy_id={:02x?} err={:?}",
                        job.metadata.policy_id, err
                    );
                }
            }
        });
        Self { tx }
    }
}

#[cfg(feature = "std")]
impl CapsuleValidator for AsyncCapsuleValidator {
    fn validate(&self, capsule: &PolicyCapsule, metadata: &PolicyMetadata) -> Result<()> {
        let _ = self.tx.send(ValidationJob {
            capsule: capsule.clone(),
            metadata: metadata.clone(),
        });
        Ok(())
    }
}
