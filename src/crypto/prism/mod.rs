//! PRISM and salt-PRISM protocol logic built on top of the isogeny substrate.

pub mod actual;
pub mod backend;
pub mod encoding;
pub mod hash;
pub mod keygen;
pub mod params;
pub mod reference;
pub mod sign;
pub mod types;
pub mod verify;

pub use actual::{
    ActualChainRequest, ActualPrismBackend, ActualPrismError, ActualWitnessProvider,
    ActualWitnessRequest, ActualWitnessSide, BaseCurveTwoIsogenyActualWitnessProvider,
    SmallModelActualWitnessProvider,
};
pub use backend::{PrismBackend, PrismError};
pub use encoding::SignatureEncoding;
pub use hash::{
    hash_to_prime_with_salt, sample_salt_and_hash_to_prime, verify_hash_to_prime,
    HashToPrimeConfig, HashToPrimeError,
};
pub use keygen::keygen_with_backend;
pub use params::{SaltPrismParameters, SALT_PRISM_LEVEL1, SALT_PRISM_LEVEL3, SALT_PRISM_LEVEL5};
pub use reference::{
    ReferenceActualChain, ReferenceActualQuotientProfile, ReferenceActualStep,
    ReferenceActualWitness, ReferenceBasisCoefficients, ReferenceIdealTrace, ReferenceIdealWitness,
    ReferencePointDescriptor, ReferencePrismBackend, ReferencePrismError, ReferenceSignatureBody,
    ReferenceSignaturePoints, ReferenceSigningKey, ReferenceVerifyingKey,
};
pub use sign::sign_with_backend;
pub use types::{ChallengePrime, Salt, Signature};
pub use verify::verify_with_backend;
