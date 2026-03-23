//! Deterministic reference backend wiring the PRISM protocol layer to the
//! current isogeny bookkeeping code.
//!
//! This backend is intentionally non-secure. Its role is to exercise the
//! protocol flow end-to-end while the real ideal-to-isogeny and product
//! isogeny machinery is still under construction.

use alloc::{boxed::Box, vec, vec::Vec};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Digest, Sha3_256, Shake256,
};

use crate::crypto::isogeny::algorithms::{
    ActualIsogenyChain, ActualIsogenyStep, ActualProductIsogeny, ActualProductIsogenyWitnessData,
    ActualProductKernel, IdealToIsogenyEngine, IdealToIsogenyError, KaniEngine, KaniError,
    KaniTranscript, ProductPoint, QlapotiEngine, QlapotiPlan, RandomIdealError, RandomIdealSampler,
    ReferenceBasisDescriptor, ReferenceCurveDescriptor,
};
use crate::crypto::isogeny::arith::{IsogenyInteger, QuaternionInteger};
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::curve::weierstrass::ShortWeierstrassCurve;
use crate::crypto::isogeny::field::{Fp2, FpModulus};
use crate::crypto::isogeny::ideal::{
    IdealError, LeftIdeal, MaximalOrder, QuaternionAlgebra, QuaternionElement, QuaternionError,
};

use super::backend::PrismBackend;
use super::encoding::SignatureEncoding;
use super::params::SaltPrismParameters;
use super::types::ChallengePrime;

pub type Result<T> = core::result::Result<T, ReferencePrismError>;

const VERIFYING_KEY_TAG: u8 = 0x91;
const SIGNATURE_BODY_TAG: u8 = 0xA7;
const VERIFYING_KEY_LEN: usize = 1 + 32 + 16 + 32 + 32 + 2 + 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferencePrismError {
    Quaternion(QuaternionError),
    Ideal(IdealError),
    IdealToIsogeny(IdealToIsogenyError),
    RandomIdeal(RandomIdealError),
    Kani(KaniError),
}

impl From<QuaternionError> for ReferencePrismError {
    fn from(error: QuaternionError) -> Self {
        Self::Quaternion(error)
    }
}

impl From<IdealError> for ReferencePrismError {
    fn from(error: IdealError) -> Self {
        Self::Ideal(error)
    }
}

impl From<IdealToIsogenyError> for ReferencePrismError {
    fn from(error: IdealToIsogenyError) -> Self {
        Self::IdealToIsogeny(error)
    }
}

impl From<RandomIdealError> for ReferencePrismError {
    fn from(error: RandomIdealError) -> Self {
        Self::RandomIdeal(error)
    }
}

impl From<KaniError> for ReferencePrismError {
    fn from(error: KaniError) -> Self {
        Self::Kani(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceVerifyingKey {
    pub codomain: ReferenceCurveDescriptor,
    pub torsion_basis: ReferenceBasisDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceSigningKey {
    secret_ideal: LeftIdeal,
    verifying_codomain: ReferenceCurveDescriptor,
    verifying_torsion_basis: ReferenceBasisDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceSignatureBody {
    pub encoding: SignatureEncoding,
    pub degree: IsogenyInteger,
    pub codomain: ReferenceCurveDescriptor,
    pub torsion_basis: ReferenceBasisDescriptor,
    pub basis_coefficients: ReferenceBasisCoefficients,
    pub signature_points: ReferenceSignaturePoints,
    pub ideal_witness: ReferenceIdealWitness,
    pub actual_witness: Option<ReferenceActualWitness>,
    pub kani: KaniTranscript,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceBasisCoefficients {
    pub p_coeff_0: Vec<u8>,
    pub p_coeff_1: Vec<u8>,
    pub q_coeff_0: Vec<u8>,
    pub q_coeff_1: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferencePointDescriptor {
    pub tag: [u8; 32],
    pub hint: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceSignaturePoints {
    pub p_sig: ReferencePointDescriptor,
    pub q_sig: ReferencePointDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceActualWitness {
    pub left: ReferenceActualChain,
    pub right: ReferenceActualChain,
    pub kernel: ReferenceActualKernel,
    pub quotient_profile: ReferenceActualQuotientProfile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceActualQuotientProfile {
    pub target_identity: ReferenceProductPoint,
    pub axis_probes: [ReferenceProductPoint; 2],
    pub axis_probe_images: [ReferenceProductPoint; 2],
    pub axis_probe_sum_image: ReferenceProductPoint,
    pub axis_probe_diff_image: ReferenceProductPoint,
    pub axis_probe_double_images: [ReferenceProductPoint; 2],
    pub axis_probe_triple_images: Box<[ReferenceProductPoint; 2]>,
    pub generators: [ReferenceProductPoint; 2],
    pub generator_images: [ReferenceProductPoint; 2],
    pub generator_sum_image: ReferenceProductPoint,
    pub generator_diff_image: ReferenceProductPoint,
    pub generator_double_images: [ReferenceProductPoint; 2],
    pub generator_triple_images: Box<[ReferenceProductPoint; 2]>,
    pub samples: Vec<ReferenceProductPoint>,
    pub images: Vec<ReferenceProductPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceIdealWitness {
    pub left: ReferenceIdealTrace,
    pub right: ReferenceIdealTrace,
    pub left_step_degrees: Vec<IsogenyInteger>,
    pub right_step_degrees: Vec<IsogenyInteger>,
    pub left_stage_traces: Vec<ReferenceIdealTrace>,
    pub right_stage_traces: Vec<ReferenceIdealTrace>,
    pub left_stage_principal_traces: Vec<ReferenceIdealTrace>,
    pub right_stage_principal_traces: Vec<ReferenceIdealTrace>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceIdealTrace {
    pub norm: IsogenyInteger,
    pub generator_coeffs: [QuaternionInteger; 4],
    pub basis_coeffs: [[QuaternionInteger; 4]; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceActualChain {
    pub source: ShortWeierstrassCurve,
    pub steps: Vec<ReferenceActualStep>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceActualStep {
    pub degree: IsogenyInteger,
    pub codomain: ShortWeierstrassCurve,
    pub kernel_generator: CurvePoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceActualKernel {
    pub p: ReferenceProductPoint,
    pub q: ReferenceProductPoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceProductPoint {
    pub left: CurvePoint,
    pub right: CurvePoint,
}

impl ReferenceSignaturePoints {
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:signature-points:v1");
        sha3::Digest::update(&mut hasher, self.p_sig.tag);
        sha3::Digest::update(&mut hasher, self.p_sig.hint);
        sha3::Digest::update(&mut hasher, self.q_sig.tag);
        sha3::Digest::update(&mut hasher, self.q_sig.hint);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

impl ReferenceActualWitness {
    pub fn from_actual(actual: &ActualProductIsogenyWitnessData) -> Option<Self> {
        let quotient_profile = actual.quotient_profile().ok()?;
        Some(Self {
            left: ReferenceActualChain::from_actual(&actual.isogeny.left)?,
            right: ReferenceActualChain::from_actual(&actual.isogeny.right)?,
            kernel: ReferenceActualKernel::from_actual(&actual.kernel),
            quotient_profile: ReferenceActualQuotientProfile::from_actual(&quotient_profile),
        })
    }

    pub fn to_actual(&self) -> Result<ActualProductIsogenyWitnessData> {
        let isogeny = ActualProductIsogeny {
            left: self.left.to_actual()?,
            right: self.right.to_actual()?,
        };
        let kernel = self.kernel.to_actual();
        let quotient_profile = self.quotient_profile.to_actual(&isogeny, &kernel)?;
        if quotient_profile.target_identity != isogeny.target_identity() {
            return Err(ReferencePrismError::Kani(KaniError::InvalidActualWitness));
        }
        let witness = ActualProductIsogenyWitnessData {
            isogeny,
            kernel,
            samples: quotient_profile.samples.clone(),
            images: quotient_profile.images.clone(),
        };
        witness.validate().map_err(ReferencePrismError::from)?;
        let derived_profile = witness
            .quotient_profile()
            .map_err(ReferencePrismError::from)?;
        if derived_profile.generators != quotient_profile.generators
            || derived_profile.axis_probes != quotient_profile.axis_probes
            || derived_profile.axis_probe_images != quotient_profile.axis_probe_images
            || derived_profile.axis_probe_sum_image != quotient_profile.axis_probe_sum_image
            || derived_profile.axis_probe_diff_image != quotient_profile.axis_probe_diff_image
            || derived_profile.axis_probe_double_images != quotient_profile.axis_probe_double_images
            || derived_profile.axis_probe_triple_images != quotient_profile.axis_probe_triple_images
            || derived_profile.generator_images != quotient_profile.generator_images
            || derived_profile.generator_sum_image != quotient_profile.generator_sum_image
            || derived_profile.generator_diff_image != quotient_profile.generator_diff_image
            || derived_profile.generator_double_images != quotient_profile.generator_double_images
            || derived_profile.generator_triple_images != quotient_profile.generator_triple_images
        {
            return Err(ReferencePrismError::Kani(KaniError::InvalidActualWitness));
        }
        Ok(witness)
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:actual-witness:v1");
        sha3::Digest::update(&mut hasher, self.chain_commitment());
        sha3::Digest::update(&mut hasher, self.kernel_commitment());
        sha3::Digest::update(&mut hasher, self.quotient_commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn chain_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(
            &mut hasher,
            b"AURORA:prism:reference:actual-witness-chain:v1",
        );
        sha3::Digest::update(&mut hasher, self.left.commitment());
        sha3::Digest::update(&mut hasher, self.right.commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn kernel_commitment(&self) -> [u8; 32] {
        self.kernel.commitment()
    }

    pub fn quotient_commitment(&self) -> [u8; 32] {
        self.quotient_profile.commitment()
    }

    pub fn probe_commitment(&self) -> [u8; 32] {
        self.quotient_profile.probe_commitment()
    }

    pub fn actual_probe_commitment(&self) -> Result<[u8; 32]> {
        Ok(self.to_actual()?.quotient_profile()?.probe_commitment())
    }

    pub fn actual_quotient_commitment(&self) -> Result<[u8; 32]> {
        self.to_actual()?
            .quotient_profile_commitment()
            .map_err(ReferencePrismError::from)
    }

    pub fn encoded_len(&self) -> usize {
        framed_section_len(self.left.encoded_len())
            + framed_section_len(self.right.encoded_len())
            + framed_section_len(
                self.kernel
                    .encoded_len(&self.left.source, &self.right.source),
            )
            + framed_section_len(self.quotient_profile.encoded_len(
                &self.left.source,
                &self.right.source,
                &self.left.target_modulus(),
                &self.right.target_modulus(),
            ))
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut left = Vec::with_capacity(self.left.encoded_len());
        self.left.encode_into(&mut left);
        encode_framed_section(out, &left);

        let mut right = Vec::with_capacity(self.right.encoded_len());
        self.right.encode_into(&mut right);
        encode_framed_section(out, &right);

        let mut kernel = Vec::with_capacity(
            self.kernel
                .encoded_len(&self.left.source, &self.right.source),
        );
        self.kernel
            .encode_into(&mut kernel, &self.left.source, &self.right.source);
        encode_framed_section(out, &kernel);

        let mut quotient = Vec::with_capacity(self.quotient_profile.encoded_len(
            &self.left.source,
            &self.right.source,
            &self.left.target_modulus(),
            &self.right.target_modulus(),
        ));
        self.quotient_profile.encode_into(
            &mut quotient,
            &self.left.source,
            &self.right.source,
            &self.left.target_modulus(),
            &self.right.target_modulus(),
        );
        encode_framed_section(out, &quotient);
    }

    pub fn decode_from(bytes: &[u8]) -> Option<Self> {
        let (left_section, cursor) = decode_framed_section(bytes, 0)?;
        let (left, left_end) = ReferenceActualChain::decode_from(left_section, 0)?;
        if left_end != left_section.len() {
            return None;
        }

        let (right_section, cursor) = decode_framed_section(bytes, cursor)?;
        let (right, right_end) = ReferenceActualChain::decode_from(right_section, 0)?;
        if right_end != right_section.len() {
            return None;
        }

        let (kernel_section, cursor) = decode_framed_section(bytes, cursor)?;
        let (kernel, kernel_end) =
            ReferenceActualKernel::decode_from(kernel_section, 0, &left.source, &right.source)?;
        if kernel_end != kernel_section.len() {
            return None;
        }

        let left_target = left.target_modulus();
        let right_target = right.target_modulus();
        let (quotient_section, cursor) = decode_framed_section(bytes, cursor)?;
        let (quotient_profile, quotient_end) = ReferenceActualQuotientProfile::decode_from(
            quotient_section,
            0,
            &left.source,
            &right.source,
            &left_target,
            &right_target,
        )?;
        if cursor != bytes.len() {
            return None;
        }
        if quotient_end != quotient_section.len() {
            return None;
        }
        Some(Self {
            left,
            right,
            kernel,
            quotient_profile,
        })
    }
}

impl ReferenceActualQuotientProfile {
    fn from_actual(actual: &crate::crypto::isogeny::algorithms::ActualQuotientProfile) -> Self {
        Self {
            target_identity: ReferenceProductPoint::from_actual(actual.target_identity),
            axis_probes: actual.axis_probes.map(ReferenceProductPoint::from_actual),
            axis_probe_images: actual
                .axis_probe_images
                .map(ReferenceProductPoint::from_actual),
            axis_probe_sum_image: ReferenceProductPoint::from_actual(actual.axis_probe_sum_image),
            axis_probe_diff_image: ReferenceProductPoint::from_actual(actual.axis_probe_diff_image),
            axis_probe_double_images: actual
                .axis_probe_double_images
                .map(ReferenceProductPoint::from_actual),
            axis_probe_triple_images: Box::new(
                (*actual.axis_probe_triple_images).map(ReferenceProductPoint::from_actual),
            ),
            generators: actual.generators.map(ReferenceProductPoint::from_actual),
            generator_images: actual
                .generator_images
                .map(ReferenceProductPoint::from_actual),
            generator_sum_image: ReferenceProductPoint::from_actual(actual.generator_sum_image),
            generator_diff_image: ReferenceProductPoint::from_actual(actual.generator_diff_image),
            generator_double_images: actual
                .generator_double_images
                .map(ReferenceProductPoint::from_actual),
            generator_triple_images: Box::new(
                (*actual.generator_triple_images).map(ReferenceProductPoint::from_actual),
            ),
            samples: actual
                .samples
                .iter()
                .copied()
                .map(ReferenceProductPoint::from_actual)
                .collect(),
            images: actual
                .images
                .iter()
                .copied()
                .map(ReferenceProductPoint::from_actual)
                .collect(),
        }
    }

    fn to_actual(
        &self,
        isogeny: &ActualProductIsogeny,
        kernel: &ActualProductKernel,
    ) -> Result<crate::crypto::isogeny::algorithms::ActualQuotientProfile> {
        let target_identity = self.target_identity.to_actual();
        let axis_probes = self.axis_probes.map(ReferenceProductPoint::to_actual);
        let axis_probe_images = self.axis_probe_images.map(ReferenceProductPoint::to_actual);
        let axis_probe_sum_image = self.axis_probe_sum_image.to_actual();
        let axis_probe_diff_image = self.axis_probe_diff_image.to_actual();
        let axis_probe_double_images = self
            .axis_probe_double_images
            .map(ReferenceProductPoint::to_actual);
        let axis_probe_triple_images = Box::new(
            self.axis_probe_triple_images
                .as_ref()
                .map(ReferenceProductPoint::to_actual),
        );
        let generators = self.generators.map(ReferenceProductPoint::to_actual);
        let generator_images = self.generator_images.map(ReferenceProductPoint::to_actual);
        let generator_sum_image = self.generator_sum_image.to_actual();
        let generator_diff_image = self.generator_diff_image.to_actual();
        let generator_double_images = self
            .generator_double_images
            .map(ReferenceProductPoint::to_actual);
        let generator_triple_images = Box::new(
            self.generator_triple_images
                .as_ref()
                .map(ReferenceProductPoint::to_actual),
        );
        let samples = self
            .samples
            .iter()
            .copied()
            .map(ReferenceProductPoint::to_actual)
            .collect::<Vec<_>>();
        let images = self
            .images
            .iter()
            .copied()
            .map(ReferenceProductPoint::to_actual)
            .collect::<Vec<_>>();
        let profile = crate::crypto::isogeny::algorithms::ActualQuotientProfile {
            target_identity,
            axis_probes,
            axis_probe_images,
            axis_probe_sum_image,
            axis_probe_diff_image,
            axis_probe_double_images,
            axis_probe_triple_images,
            generators,
            generator_images,
            generator_sum_image,
            generator_diff_image,
            generator_double_images,
            generator_triple_images,
            samples: samples.clone(),
            images: images.clone(),
        };
        profile
            .validate(isogeny, kernel)
            .map_err(ReferencePrismError::from)?;
        Ok(profile)
    }

    fn encoded_len(
        &self,
        left_source: &ShortWeierstrassCurve,
        right_source: &ShortWeierstrassCurve,
        left_target: &FpModulus,
        right_target: &FpModulus,
    ) -> usize {
        self.target_identity.encoded_len(left_target, right_target)
            + self
                .axis_probes
                .iter()
                .map(|point| point.encoded_len(left_source.modulus(), right_source.modulus()))
                .sum::<usize>()
            + self
                .axis_probe_images
                .iter()
                .map(|point| point.encoded_len(left_target, right_target))
                .sum::<usize>()
            + self
                .axis_probe_sum_image
                .encoded_len(left_target, right_target)
            + self
                .axis_probe_diff_image
                .encoded_len(left_target, right_target)
            + self
                .axis_probe_double_images
                .iter()
                .map(|point| point.encoded_len(left_target, right_target))
                .sum::<usize>()
            + self
                .axis_probe_triple_images
                .iter()
                .map(|point| point.encoded_len(left_target, right_target))
                .sum::<usize>()
            + self
                .generators
                .iter()
                .map(|point| point.encoded_len(left_source.modulus(), right_source.modulus()))
                .sum::<usize>()
            + self
                .generator_images
                .iter()
                .map(|point| point.encoded_len(left_target, right_target))
                .sum::<usize>()
            + self
                .generator_sum_image
                .encoded_len(left_target, right_target)
            + self
                .generator_diff_image
                .encoded_len(left_target, right_target)
            + self
                .generator_double_images
                .iter()
                .map(|point| point.encoded_len(left_target, right_target))
                .sum::<usize>()
            + self
                .generator_triple_images
                .iter()
                .map(|point| point.encoded_len(left_target, right_target))
                .sum::<usize>()
            + 2
            + self
                .samples
                .iter()
                .map(|point| point.encoded_len(left_source.modulus(), right_source.modulus()))
                .sum::<usize>()
            + 2
            + self
                .images
                .iter()
                .map(|point| point.encoded_len(left_target, right_target))
                .sum::<usize>()
    }

    fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(
            &mut hasher,
            b"AURORA:prism:reference:actual-quotient-profile:v1",
        );
        sha3::Digest::update(&mut hasher, self.target_identity.commitment());
        for probe in &self.axis_probes {
            sha3::Digest::update(&mut hasher, probe.commitment());
        }
        for image in &self.axis_probe_images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        sha3::Digest::update(&mut hasher, self.axis_probe_sum_image.commitment());
        sha3::Digest::update(&mut hasher, self.axis_probe_diff_image.commitment());
        for image in &self.axis_probe_double_images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        for image in self.axis_probe_triple_images.iter() {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        for generator in &self.generators {
            sha3::Digest::update(&mut hasher, generator.commitment());
        }
        for image in &self.generator_images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        sha3::Digest::update(&mut hasher, self.generator_sum_image.commitment());
        sha3::Digest::update(&mut hasher, self.generator_diff_image.commitment());
        for image in &self.generator_double_images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        for image in self.generator_triple_images.iter() {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        sha3::Digest::update(&mut hasher, (self.samples.len() as u32).to_be_bytes());
        for sample in &self.samples {
            sha3::Digest::update(&mut hasher, sample.commitment());
        }
        sha3::Digest::update(&mut hasher, (self.images.len() as u32).to_be_bytes());
        for image in &self.images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn probe_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(
            &mut hasher,
            b"AURORA:prism:reference:actual-quotient-probes:v1",
        );
        sha3::Digest::update(&mut hasher, self.target_identity.commitment());
        for probe in &self.axis_probes {
            sha3::Digest::update(&mut hasher, probe.commitment());
        }
        for image in &self.axis_probe_images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        sha3::Digest::update(&mut hasher, self.axis_probe_sum_image.commitment());
        sha3::Digest::update(&mut hasher, self.axis_probe_diff_image.commitment());
        for image in &self.axis_probe_double_images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        for image in self.axis_probe_triple_images.iter() {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        for generator in &self.generators {
            sha3::Digest::update(&mut hasher, generator.commitment());
        }
        for image in &self.generator_images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        sha3::Digest::update(&mut hasher, self.generator_sum_image.commitment());
        sha3::Digest::update(&mut hasher, self.generator_diff_image.commitment());
        for image in &self.generator_double_images {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        for image in self.generator_triple_images.iter() {
            sha3::Digest::update(&mut hasher, image.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn encode_into(
        &self,
        out: &mut Vec<u8>,
        left_source: &ShortWeierstrassCurve,
        right_source: &ShortWeierstrassCurve,
        left_target: &FpModulus,
        right_target: &FpModulus,
    ) {
        let _ = (left_source, right_source);
        self.target_identity.encode_into(out);
        for probe in &self.axis_probes {
            probe.encode_into(out);
        }
        for image in &self.axis_probe_images {
            image.encode_into(out);
        }
        self.axis_probe_sum_image.encode_into(out);
        self.axis_probe_diff_image.encode_into(out);
        for image in &self.axis_probe_double_images {
            image.encode_into(out);
        }
        for image in self.axis_probe_triple_images.iter() {
            image.encode_into(out);
        }
        for generator in &self.generators {
            generator.encode_into(out);
        }
        for image in &self.generator_images {
            image.encode_into(out);
        }
        self.generator_sum_image.encode_into(out);
        self.generator_diff_image.encode_into(out);
        for image in &self.generator_double_images {
            image.encode_into(out);
        }
        for image in self.generator_triple_images.iter() {
            image.encode_into(out);
        }
        out.extend_from_slice(&(self.samples.len() as u16).to_be_bytes());
        for sample in &self.samples {
            sample.encode_into(out);
        }
        out.extend_from_slice(&(self.images.len() as u16).to_be_bytes());
        for image in &self.images {
            image.encode_into(out);
        }
        let _ = (left_target, right_target);
    }

    fn decode_from(
        bytes: &[u8],
        offset: usize,
        left_source: &ShortWeierstrassCurve,
        right_source: &ShortWeierstrassCurve,
        left_target: &FpModulus,
        right_target: &FpModulus,
    ) -> Option<(Self, usize)> {
        let (target_identity, mut cursor) =
            ReferenceProductPoint::decode_from(bytes, offset, left_target, right_target)?;
        let (axis_probe_0, next_cursor) = ReferenceProductPoint::decode_from(
            bytes,
            cursor,
            left_source.modulus(),
            right_source.modulus(),
        )?;
        cursor = next_cursor;
        let (axis_probe_1, next_cursor) = ReferenceProductPoint::decode_from(
            bytes,
            cursor,
            left_source.modulus(),
            right_source.modulus(),
        )?;
        cursor = next_cursor;
        let (axis_probe_image_0, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (axis_probe_image_1, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (axis_probe_sum_image, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (axis_probe_diff_image, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (axis_probe_double_image_0, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (axis_probe_double_image_1, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (axis_probe_triple_image_0, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (axis_probe_triple_image_1, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (generator_0, next_cursor) = ReferenceProductPoint::decode_from(
            bytes,
            cursor,
            left_source.modulus(),
            right_source.modulus(),
        )?;
        cursor = next_cursor;
        let (generator_1, next_cursor) = ReferenceProductPoint::decode_from(
            bytes,
            cursor,
            left_source.modulus(),
            right_source.modulus(),
        )?;
        cursor = next_cursor;
        let (generator_image_0, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (generator_image_1, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (generator_sum_image, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (generator_diff_image, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (generator_double_image_0, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (generator_double_image_1, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (generator_triple_image_0, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let (generator_triple_image_1, next_cursor) =
            ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
        cursor = next_cursor;
        let sample_count = u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?);
        cursor += 2;
        let mut samples = Vec::with_capacity(sample_count as usize);
        for _ in 0..sample_count {
            let (sample, next_cursor) = ReferenceProductPoint::decode_from(
                bytes,
                cursor,
                left_source.modulus(),
                right_source.modulus(),
            )?;
            samples.push(sample);
            cursor = next_cursor;
        }
        let image_count = u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?);
        cursor += 2;
        let mut images = Vec::with_capacity(image_count as usize);
        for _ in 0..image_count {
            let (image, next_cursor) =
                ReferenceProductPoint::decode_from(bytes, cursor, left_target, right_target)?;
            images.push(image);
            cursor = next_cursor;
        }
        Some((
            Self {
                target_identity,
                axis_probes: [axis_probe_0, axis_probe_1],
                axis_probe_images: [axis_probe_image_0, axis_probe_image_1],
                axis_probe_sum_image,
                axis_probe_diff_image,
                axis_probe_double_images: [axis_probe_double_image_0, axis_probe_double_image_1],
                axis_probe_triple_images: Box::new([
                    axis_probe_triple_image_0,
                    axis_probe_triple_image_1,
                ]),
                generators: [generator_0, generator_1],
                generator_images: [generator_image_0, generator_image_1],
                generator_sum_image,
                generator_diff_image,
                generator_double_images: [generator_double_image_0, generator_double_image_1],
                generator_triple_images: Box::new([
                    generator_triple_image_0,
                    generator_triple_image_1,
                ]),
                samples,
                images,
            },
            cursor,
        ))
    }
}

impl ReferenceIdealWitness {
    const MAX_STEP_HINTS: usize = 64;

    pub fn new(left: ReferenceIdealTrace, right: ReferenceIdealTrace) -> Self {
        Self {
            left,
            right,
            left_step_degrees: Vec::new(),
            right_step_degrees: Vec::new(),
            left_stage_traces: Vec::new(),
            right_stage_traces: Vec::new(),
            left_stage_principal_traces: Vec::new(),
            right_stage_principal_traces: Vec::new(),
        }
    }

    pub fn encoded_len(&self) -> usize {
        ReferenceIdealTrace::encoded_len() * 2
            + 2
            + self.left_step_degrees.len() * IsogenyInteger::BYTES
            + 2
            + self.right_step_degrees.len() * IsogenyInteger::BYTES
            + 2
            + self.left_stage_traces.len() * ReferenceIdealTrace::encoded_len()
            + 2
            + self.right_stage_traces.len() * ReferenceIdealTrace::encoded_len()
            + 2
            + self.left_stage_principal_traces.len() * ReferenceIdealTrace::encoded_len()
            + 2
            + self.right_stage_principal_traces.len() * ReferenceIdealTrace::encoded_len()
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        self.left.encode_into(out);
        self.right.encode_into(out);
        encode_step_degrees(&self.left_step_degrees, out);
        encode_step_degrees(&self.right_step_degrees, out);
        encode_stage_traces(&self.left_stage_traces, out);
        encode_stage_traces(&self.right_stage_traces, out);
        encode_stage_traces(&self.left_stage_principal_traces, out);
        encode_stage_traces(&self.right_stage_principal_traces, out);
    }

    pub fn decode_from(bytes: &[u8]) -> Option<(Self, usize)> {
        let left_end = ReferenceIdealTrace::encoded_len();
        let right_end = left_end + ReferenceIdealTrace::encoded_len();
        if bytes.len() < right_end + 4 {
            return None;
        }
        let left = ReferenceIdealTrace::decode_from(&bytes[..left_end])?;
        let right = ReferenceIdealTrace::decode_from(&bytes[left_end..right_end])?;
        let (left_step_degrees, cursor) = decode_step_degrees(bytes, right_end)?;
        let (right_step_degrees, cursor) = decode_step_degrees(bytes, cursor)?;
        let (left_stage_traces, cursor) = decode_stage_traces(bytes, cursor)?;
        let (right_stage_traces, cursor) = decode_stage_traces(bytes, cursor)?;
        let (left_stage_principal_traces, cursor) = decode_stage_traces(bytes, cursor)?;
        let (right_stage_principal_traces, cursor) = decode_stage_traces(bytes, cursor)?;
        Some((
            Self {
                left,
                right,
                left_step_degrees,
                right_step_degrees,
                left_stage_traces,
                right_stage_traces,
                left_stage_principal_traces,
                right_stage_principal_traces,
            },
            cursor,
        ))
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:ideal-witness:v1");
        sha3::Digest::update(&mut hasher, self.root_commitment());
        sha3::Digest::update(&mut hasher, self.step_hint_commitment());
        sha3::Digest::update(&mut hasher, self.stage_commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn root_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:ideal-witness-root:v1");
        sha3::Digest::update(&mut hasher, self.left.commitment());
        sha3::Digest::update(&mut hasher, self.right.commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn step_hint_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(
            &mut hasher,
            b"AURORA:prism:reference:ideal-witness-step-hints:v1",
        );
        sha3::Digest::update(
            &mut hasher,
            trace_degrees_commitment(&self.left_step_degrees),
        );
        sha3::Digest::update(
            &mut hasher,
            trace_degrees_commitment(&self.right_step_degrees),
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn stage_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(
            &mut hasher,
            b"AURORA:prism:reference:ideal-witness-stage-decomposition:v1",
        );
        sha3::Digest::update(
            &mut hasher,
            trace_list_commitment(
                b"AURORA:prism:reference:left-stage-traces:v1",
                &self.left_stage_traces,
            ),
        );
        sha3::Digest::update(
            &mut hasher,
            trace_list_commitment(
                b"AURORA:prism:reference:right-stage-traces:v1",
                &self.right_stage_traces,
            ),
        );
        sha3::Digest::update(
            &mut hasher,
            trace_list_commitment(
                b"AURORA:prism:reference:left-stage-principals:v1",
                &self.left_stage_principal_traces,
            ),
        );
        sha3::Digest::update(
            &mut hasher,
            trace_list_commitment(
                b"AURORA:prism:reference:right-stage-principals:v1",
                &self.right_stage_principal_traces,
            ),
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn set_step_degrees(
        &mut self,
        left: &[IsogenyInteger],
        right: &[IsogenyInteger],
    ) -> Option<()> {
        self.left_step_degrees = canonical_step_degrees(left)?;
        self.right_step_degrees = canonical_step_degrees(right)?;
        Some(())
    }

    pub fn set_stage_traces_from_ideals(
        &mut self,
        left_ideal: &LeftIdeal,
        left_degrees: &[IsogenyInteger],
        right_ideal: &LeftIdeal,
        right_degrees: &[IsogenyInteger],
    ) -> Result<()> {
        let left_decomposition =
            IdealToIsogenyEngine::derive_stage_decomposition(left_ideal, left_degrees)?;
        self.left_stage_traces = left_decomposition
            .iter()
            .map(|stage| ReferenceIdealTrace::from_ideal(&stage.stage))
            .collect();
        self.left_stage_principal_traces = left_decomposition
            .iter()
            .map(|stage| ReferenceIdealTrace::from_ideal(&stage.principal))
            .collect();

        let right_decomposition =
            IdealToIsogenyEngine::derive_stage_decomposition(right_ideal, right_degrees)?;
        self.right_stage_traces = right_decomposition
            .iter()
            .map(|stage| ReferenceIdealTrace::from_ideal(&stage.stage))
            .collect();
        self.right_stage_principal_traces = right_decomposition
            .iter()
            .map(|stage| ReferenceIdealTrace::from_ideal(&stage.principal))
            .collect();
        Ok(())
    }

    pub fn left_step_degrees_u128(&self) -> Option<Vec<u128>> {
        self.left_step_degrees
            .iter()
            .map(|degree| degree.try_to_u128())
            .collect()
    }

    pub fn left_step_degrees_integers(&self) -> Vec<IsogenyInteger> {
        self.left_step_degrees.clone()
    }

    pub fn right_step_degrees_u128(&self) -> Option<Vec<u128>> {
        self.right_step_degrees
            .iter()
            .map(|degree| degree.try_to_u128())
            .collect()
    }

    pub fn right_step_degrees_integers(&self) -> Vec<IsogenyInteger> {
        self.right_step_degrees.clone()
    }
}

impl ReferenceIdealTrace {
    pub fn from_ideal(ideal: &LeftIdeal) -> Self {
        Self {
            norm: ideal.norm(),
            generator_coeffs: ideal.generator().coeffs(),
            basis_coeffs: ideal.basis().map(|element| element.coeffs()),
        }
    }

    pub const fn encoded_len() -> usize {
        IsogenyInteger::BYTES + (QuaternionInteger::BYTES * 4) + (QuaternionInteger::BYTES * 4 * 4)
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.norm.to_be_bytes_fixed());
        for coeff in self.generator_coeffs {
            let bytes = coeff.to_be_bytes_fixed();
            out.extend_from_slice(&bytes);
        }
        for basis_coeffs in self.basis_coeffs {
            for coeff in basis_coeffs {
                let bytes = coeff.to_be_bytes_fixed();
                out.extend_from_slice(&bytes);
            }
        }
    }

    pub fn decode_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::encoded_len() {
            return None;
        }
        let norm = IsogenyInteger::from_be_slice(&bytes[..IsogenyInteger::BYTES])?;
        let mut generator_coeffs = [QuaternionInteger::zero(); 4];
        for (idx, coeff) in generator_coeffs.iter_mut().enumerate() {
            let start = IsogenyInteger::BYTES + (idx * QuaternionInteger::BYTES);
            *coeff =
                QuaternionInteger::from_be_slice(&bytes[start..start + QuaternionInteger::BYTES])?;
        }
        let basis_start = IsogenyInteger::BYTES + (QuaternionInteger::BYTES * 4);
        let mut basis_coeffs = [[QuaternionInteger::zero(); 4]; 4];
        for (basis_index, coeffs) in basis_coeffs.iter_mut().enumerate() {
            for (coeff_index, coeff) in coeffs.iter_mut().enumerate() {
                let start =
                    basis_start + ((basis_index * 4 + coeff_index) * QuaternionInteger::BYTES);
                *coeff = QuaternionInteger::from_be_slice(
                    &bytes[start..start + QuaternionInteger::BYTES],
                )?;
            }
        }
        Some(Self {
            norm,
            generator_coeffs,
            basis_coeffs,
        })
    }

    pub fn to_ideal(&self, params: &'static SaltPrismParameters) -> Result<LeftIdeal> {
        let algebra = QuaternionAlgebra::new(params.base.cofactor)?;
        let order = MaximalOrder::reference(algebra);
        self.to_ideal_with_orders(order, order)
    }

    pub fn to_ideal_with_orders(
        &self,
        left_order: MaximalOrder,
        right_order: MaximalOrder,
    ) -> Result<LeftIdeal> {
        let algebra = left_order.algebra();
        LeftIdeal::with_basis(
            left_order,
            right_order,
            QuaternionElement::from_coeffs(algebra, self.generator_coeffs),
            self.norm,
            self.basis_coeffs
                .map(|coeffs| QuaternionElement::from_coeffs(algebra, coeffs)),
        )
        .map_err(ReferencePrismError::from)
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:ideal-trace:v1");
        sha3::Digest::update(&mut hasher, self.norm.to_be_bytes_fixed());
        for coeff in self.generator_coeffs {
            let bytes = coeff.to_be_bytes_fixed();
            sha3::Digest::update(&mut hasher, &bytes);
        }
        for basis_coeffs in self.basis_coeffs {
            for coeff in basis_coeffs {
                let bytes = coeff.to_be_bytes_fixed();
                sha3::Digest::update(&mut hasher, &bytes);
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

fn step_hints_compatible_with_plan(plan: &QlapotiPlan, hints: &[IsogenyInteger]) -> bool {
    for hint in hints {
        if *hint < IsogenyInteger::from(2u64) {
            return false;
        }
    }
    plan.annotate_selected_degrees(hints).is_some()
}

fn stage_traces_match_ideal(
    ideal: &LeftIdeal,
    degrees: &[IsogenyInteger],
    traces: &[ReferenceIdealTrace],
    principal_traces: &[ReferenceIdealTrace],
) -> bool {
    if degrees.is_empty() {
        return traces.is_empty() && principal_traces.is_empty();
    }
    if traces.len() != degrees.len() || principal_traces.len() != degrees.len() {
        return false;
    }
    let principal_ideals = match principal_traces
        .iter()
        .map(|trace| trace.to_ideal_with_orders(ideal.left_order(), ideal.right_order()))
        .collect::<Result<Vec<_>>>()
    {
        Ok(principal_ideals) => principal_ideals,
        Err(_) => return false,
    };
    match IdealToIsogenyEngine::replay_stage_decomposition_from_principals(
        ideal,
        degrees,
        &principal_ideals,
    ) {
        Ok(decomposition) => decomposition
            .iter()
            .map(|stage| ReferenceIdealTrace::from_ideal(&stage.stage))
            .eq(traces.iter().copied()),
        Err(_) => false,
    }
}

fn canonical_step_degrees(degrees: &[IsogenyInteger]) -> Option<Vec<IsogenyInteger>> {
    if degrees.len() > ReferenceIdealWitness::MAX_STEP_HINTS {
        return None;
    }
    let mut out = Vec::with_capacity(degrees.len());
    for degree in degrees {
        if *degree < IsogenyInteger::from(2u64) {
            return None;
        }
        out.push(*degree);
    }
    Some(out)
}

fn encode_step_degrees(step_degrees: &[IsogenyInteger], out: &mut Vec<u8>) {
    out.extend_from_slice(&(step_degrees.len() as u16).to_be_bytes());
    for degree in step_degrees {
        out.extend_from_slice(&degree.to_be_bytes_fixed());
    }
}

fn decode_step_degrees(bytes: &[u8], offset: usize) -> Option<(Vec<IsogenyInteger>, usize)> {
    let count = u16::from_be_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
    let count = usize::from(count);
    if count > ReferenceIdealWitness::MAX_STEP_HINTS {
        return None;
    }
    let mut cursor = offset + 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let degree =
            IsogenyInteger::from_be_slice(bytes.get(cursor..cursor + IsogenyInteger::BYTES)?)?;
        if degree < IsogenyInteger::from(2u64) {
            return None;
        }
        out.push(degree);
        cursor += IsogenyInteger::BYTES;
    }
    Some((out, cursor))
}

fn encode_stage_traces(traces: &[ReferenceIdealTrace], out: &mut Vec<u8>) {
    out.extend_from_slice(&(traces.len() as u16).to_be_bytes());
    for trace in traces {
        trace.encode_into(out);
    }
}

fn trace_degrees_commitment(degrees: &[IsogenyInteger]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(
        &mut hasher,
        b"AURORA:prism:reference:ideal-witness-degree-list:v1",
    );
    sha3::Digest::update(&mut hasher, (degrees.len() as u32).to_be_bytes());
    for degree in degrees {
        sha3::Digest::update(&mut hasher, degree.to_be_bytes_fixed());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub(crate) fn qlapoti_step_hint_commitment(
    params: &'static SaltPrismParameters,
    ideal_witness: &ReferenceIdealWitness,
) -> [u8; 32] {
    fn side_commitment(
        params: &'static SaltPrismParameters,
        trace: ReferenceIdealTrace,
        degrees: &[IsogenyInteger],
    ) -> [u8; 32] {
        trace
            .to_ideal(params)
            .ok()
            .and_then(|ideal| {
                QlapotiEngine::plan_for_ideal(&ideal).selected_degree_commitment(degrees)
            })
            .unwrap_or([0xff; 32])
    }

    let mut hasher = Sha3_256::new();
    sha3::Digest::update(
        &mut hasher,
        b"AURORA:prism:reference:ideal-witness-qlapoti-step-hints:v1",
    );
    sha3::Digest::update(
        &mut hasher,
        side_commitment(params, ideal_witness.left, &ideal_witness.left_step_degrees),
    );
    sha3::Digest::update(
        &mut hasher,
        side_commitment(
            params,
            ideal_witness.right,
            &ideal_witness.right_step_degrees,
        ),
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn trace_list_commitment(domain: &[u8], traces: &[ReferenceIdealTrace]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, domain);
    sha3::Digest::update(&mut hasher, (traces.len() as u32).to_be_bytes());
    for trace in traces {
        sha3::Digest::update(&mut hasher, trace.commitment());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn decode_stage_traces(bytes: &[u8], offset: usize) -> Option<(Vec<ReferenceIdealTrace>, usize)> {
    let count = u16::from_be_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
    let count = usize::from(count);
    if count > ReferenceIdealWitness::MAX_STEP_HINTS {
        return None;
    }
    let mut cursor = offset + 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let end = cursor.checked_add(ReferenceIdealTrace::encoded_len())?;
        out.push(ReferenceIdealTrace::decode_from(bytes.get(cursor..end)?)?);
        cursor = end;
    }
    Some((out, cursor))
}

impl ReferenceActualChain {
    fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:actual-chain:v1");
        let mut encoded = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut encoded);
        sha3::Digest::update(&mut hasher, (encoded.len() as u32).to_be_bytes());
        sha3::Digest::update(&mut hasher, &encoded);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn from_actual(actual: &ActualIsogenyChain) -> Option<Self> {
        let mut steps = Vec::with_capacity(actual.steps.len());
        for step in &actual.steps {
            steps.push(ReferenceActualStep::from_actual(step)?);
        }
        Some(Self {
            source: actual.source,
            steps,
        })
    }

    fn to_actual(&self) -> Result<ActualIsogenyChain> {
        let mut current = self.source;
        let mut steps = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            let actual = step.to_actual(current)?;
            current = actual.codomain;
            steps.push(actual);
        }
        Ok(ActualIsogenyChain {
            source: self.source,
            target: current,
            steps,
        })
    }

    fn encoded_len(&self) -> usize {
        encoded_curve_len(&self.source)
            + 2
            + self
                .steps
                .iter()
                .map(ReferenceActualStep::encoded_len)
                .sum::<usize>()
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_curve(&self.source, out);
        out.extend_from_slice(&(self.steps.len() as u16).to_be_bytes());
        for step in &self.steps {
            step.encode_into(out);
        }
    }

    fn decode_from(bytes: &[u8], offset: usize) -> Option<(Self, usize)> {
        let (source, mut cursor) = decode_curve(bytes, offset)?;
        let step_count = u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?);
        cursor += 2;

        let mut current = source;
        let mut steps = Vec::with_capacity(step_count as usize);
        for _ in 0..step_count {
            let (step, next_curve, next_cursor) =
                ReferenceActualStep::decode_from(bytes, cursor, current)?;
            steps.push(step);
            current = next_curve;
            cursor = next_cursor;
        }
        Some((Self { source, steps }, cursor))
    }

    fn target_curve(&self) -> ShortWeierstrassCurve {
        let mut current = self.source;
        for step in &self.steps {
            current = step.codomain;
        }
        current
    }

    fn target_modulus(&self) -> FpModulus {
        *self.target_curve().modulus()
    }
}

impl ReferenceActualStep {
    fn from_actual(actual: &ActualIsogenyStep) -> Option<Self> {
        Some(Self {
            degree: IsogenyInteger::from(u64::try_from(actual.degree).ok()?),
            codomain: actual.codomain,
            kernel_generator: actual.kernel_generator,
        })
    }

    fn to_actual(&self, domain: ShortWeierstrassCurve) -> Result<ActualIsogenyStep> {
        Ok(ActualIsogenyStep {
            degree: self
                .degree
                .try_to_usize()
                .ok_or(ReferencePrismError::IdealToIsogeny(
                    IdealToIsogenyError::UnsupportedActualDegree,
                ))?,
            domain,
            codomain: self.codomain,
            kernel_generator: self.kernel_generator,
        })
    }

    fn encoded_len(&self) -> usize {
        IsogenyInteger::BYTES
            + encoded_curve_len(&self.codomain)
            + encoded_point_len(self.codomain.modulus())
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.degree.to_be_bytes_fixed());
        encode_curve(&self.codomain, out);
        encode_point(&self.kernel_generator, out);
    }

    fn decode_from(
        bytes: &[u8],
        offset: usize,
        domain: ShortWeierstrassCurve,
    ) -> Option<(Self, ShortWeierstrassCurve, usize)> {
        let degree =
            IsogenyInteger::from_be_slice(bytes.get(offset..offset + IsogenyInteger::BYTES)?)?;
        let (codomain, mut cursor) = decode_curve(bytes, offset + IsogenyInteger::BYTES)?;
        let (kernel_generator, next_cursor) = decode_point(bytes, cursor, domain.modulus())?;
        cursor = next_cursor;
        Some((
            Self {
                degree,
                codomain,
                kernel_generator,
            },
            codomain,
            cursor,
        ))
    }
}

impl ReferenceActualKernel {
    fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:actual-kernel:v1");
        sha3::Digest::update(&mut hasher, self.p.commitment());
        sha3::Digest::update(&mut hasher, self.q.commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn from_actual(kernel: &ActualProductKernel) -> Self {
        Self {
            p: ReferenceProductPoint::from_actual(kernel.p),
            q: ReferenceProductPoint::from_actual(kernel.q),
        }
    }

    fn to_actual(&self) -> ActualProductKernel {
        ActualProductKernel {
            p: self.p.to_actual(),
            q: self.q.to_actual(),
        }
    }

    fn encoded_len(
        &self,
        left_source: &ShortWeierstrassCurve,
        right_source: &ShortWeierstrassCurve,
    ) -> usize {
        self.p
            .encoded_len(left_source.modulus(), right_source.modulus())
            + self
                .q
                .encoded_len(left_source.modulus(), right_source.modulus())
    }

    fn encode_into(
        &self,
        out: &mut Vec<u8>,
        _left_source: &ShortWeierstrassCurve,
        _right_source: &ShortWeierstrassCurve,
    ) {
        self.p.encode_into(out);
        self.q.encode_into(out);
    }

    fn decode_from(
        bytes: &[u8],
        offset: usize,
        left_source: &ShortWeierstrassCurve,
        right_source: &ShortWeierstrassCurve,
    ) -> Option<(Self, usize)> {
        let (p, cursor) = ReferenceProductPoint::decode_from(
            bytes,
            offset,
            left_source.modulus(),
            right_source.modulus(),
        )?;
        let (q, cursor) = ReferenceProductPoint::decode_from(
            bytes,
            cursor,
            left_source.modulus(),
            right_source.modulus(),
        )?;
        Some((Self { p, q }, cursor))
    }
}

impl ReferenceProductPoint {
    fn commitment(&self) -> [u8; 32] {
        self.to_actual().commitment()
    }

    fn from_actual(point: ProductPoint) -> Self {
        Self {
            left: point.left,
            right: point.right,
        }
    }

    fn to_actual(self) -> ProductPoint {
        ProductPoint::new(self.left, self.right)
    }

    fn encoded_len(&self, left_modulus: &FpModulus, right_modulus: &FpModulus) -> usize {
        encoded_point_len(left_modulus) + encoded_point_len(right_modulus)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_point(&self.left, out);
        encode_point(&self.right, out);
    }

    fn decode_from(
        bytes: &[u8],
        offset: usize,
        left_modulus: &FpModulus,
        right_modulus: &FpModulus,
    ) -> Option<(Self, usize)> {
        let (left, cursor) = decode_point(bytes, offset, left_modulus)?;
        let (right, cursor) = decode_point(bytes, cursor, right_modulus)?;
        Some((Self { left, right }, cursor))
    }
}

impl ReferenceBasisCoefficients {
    pub fn scalar_bytes(power_bits: usize) -> usize {
        power_bits.div_ceil(8)
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:basis-coefficients:v1");
        for scalar in [
            &self.p_coeff_0,
            &self.p_coeff_1,
            &self.q_coeff_0,
            &self.q_coeff_1,
        ] {
            sha3::Digest::update(&mut hasher, (scalar.len() as u32).to_be_bytes());
            sha3::Digest::update(&mut hasher, scalar);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn empty() -> Self {
        Self {
            p_coeff_0: Vec::new(),
            p_coeff_1: Vec::new(),
            q_coeff_0: Vec::new(),
            q_coeff_1: Vec::new(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.p_coeff_0);
        out.extend_from_slice(&self.p_coeff_1);
        out.extend_from_slice(&self.q_coeff_0);
        out.extend_from_slice(&self.q_coeff_1);
    }

    fn decode_from(bytes: &[u8], power_bits: usize) -> Option<Self> {
        let scalar_len = Self::scalar_bytes(power_bits);
        let total_len = scalar_len.checked_mul(4)?;
        if bytes.len() != total_len {
            return None;
        }

        let p_coeff_0 = bytes[0..scalar_len].to_vec();
        let p_coeff_1 = bytes[scalar_len..2 * scalar_len].to_vec();
        let q_coeff_0 = bytes[2 * scalar_len..3 * scalar_len].to_vec();
        let q_coeff_1 = bytes[3 * scalar_len..4 * scalar_len].to_vec();

        if !unused_top_bits_zero(&p_coeff_0, power_bits)
            || !unused_top_bits_zero(&p_coeff_1, power_bits)
            || !unused_top_bits_zero(&q_coeff_0, power_bits)
            || !unused_top_bits_zero(&q_coeff_1, power_bits)
        {
            return None;
        }

        Some(Self {
            p_coeff_0,
            p_coeff_1,
            q_coeff_0,
            q_coeff_1,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ReferencePrismBackend {
    params: &'static SaltPrismParameters,
    key_counter: u64,
    signature_encoding: SignatureEncoding,
    actual_small_model: bool,
}

impl ReferencePrismBackend {
    pub const fn new(params: &'static SaltPrismParameters) -> Self {
        Self {
            params,
            key_counter: 0,
            signature_encoding: SignatureEncoding::CurveAndBasisCoefficients,
            actual_small_model: false,
        }
    }

    pub const fn with_signature_encoding(mut self, signature_encoding: SignatureEncoding) -> Self {
        self.signature_encoding = signature_encoding;
        self
    }

    pub const fn with_actual_small_model(mut self, actual_small_model: bool) -> Self {
        self.actual_small_model = actual_small_model;
        self
    }

    pub const fn signature_encoding(&self) -> SignatureEncoding {
        self.signature_encoding
    }

    pub const fn actual_small_model(&self) -> bool {
        self.actual_small_model
    }

    fn reference_algebra(&self) -> Result<QuaternionAlgebra> {
        QuaternionAlgebra::new(self.params.base.cofactor).map_err(ReferencePrismError::from)
    }

    fn reference_order(&self) -> Result<MaximalOrder> {
        Ok(MaximalOrder::reference(self.reference_algebra()?))
    }

    fn derive_secret_generator(
        &self,
        counter: u64,
        algebra: QuaternionAlgebra,
    ) -> QuaternionElement {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:keygen:v1");
        sha3::Digest::update(
            &mut hasher,
            (self.params.security_bits as u64).to_be_bytes(),
        );
        sha3::Digest::update(
            &mut hasher,
            (self.params.challenge_bits as u64).to_be_bytes(),
        );
        sha3::Digest::update(&mut hasher, counter.to_be_bytes());
        let digest = hasher.finalize();

        let mut coeffs = [QuaternionInteger::zero(); 4];
        for (idx, chunk) in digest.chunks_exact(8).take(4).enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            let raw = u64::from_be_bytes(bytes);
            coeffs[idx] = QuaternionInteger::from(i128::from(raw & 0x3fff) - 0x1fff);
        }
        if coeffs.iter().all(QuaternionInteger::is_zero) {
            coeffs[0] = QuaternionInteger::from(1i32);
        }
        QuaternionElement::from_coeffs(algebra, coeffs)
    }

    fn challenge_to_reference_degree(&self, challenge: &ChallengePrime) -> IsogenyInteger {
        if let Some(degree) = challenge.paper_degree(self.params.challenge_bits) {
            return degree;
        }

        let digest = Sha3_256::digest(challenge.as_bytes());
        let mut degree_bytes = [0u8; 16];
        degree_bytes.copy_from_slice(&digest[..16]);
        let degree = u128::from_be_bytes(degree_bytes) | 1;
        IsogenyInteger::from(degree.max(3))
    }

    fn challenge_seed(
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:challenge-ideal:v1");
        sha3::Digest::update(&mut hasher, verifying_key.codomain.tag);
        sha3::Digest::update(&mut hasher, verifying_key.torsion_basis.commitment());
        sha3::Digest::update(&mut hasher, challenge.as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hasher.finalize());
        seed
    }

    fn derive_challenge_ideal(
        &self,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        degree: IsogenyInteger,
        order: MaximalOrder,
    ) -> Result<LeftIdeal> {
        let seed = Self::challenge_seed(verifying_key, challenge);
        let mut rng = ChaCha20Rng::from_seed(seed);
        RandomIdealSampler::sample_given_norm(&order, degree, &mut rng)
            .map_err(ReferencePrismError::from)
    }

    fn derive_signature_coefficients(
        &self,
        signing_key: &ReferenceSigningKey,
        signature_codomain: &ReferenceCurveDescriptor,
        signature_basis: &ReferenceBasisDescriptor,
        challenge: &ChallengePrime,
    ) -> ReferenceBasisCoefficients {
        let scalar_len = ReferenceBasisCoefficients::scalar_bytes(self.params.challenge_bits);
        let mut hasher = Shake256::default();
        sha3::digest::Update::update(
            &mut hasher,
            b"AURORA:prism:reference:signature-coefficients:v1",
        );
        sha3::digest::Update::update(&mut hasher, &signing_key.verifying_codomain.tag);
        sha3::digest::Update::update(
            &mut hasher,
            &signing_key.verifying_torsion_basis.commitment(),
        );
        sha3::digest::Update::update(&mut hasher, &signature_codomain.tag);
        sha3::digest::Update::update(&mut hasher, &signature_basis.commitment());
        for coeff in signing_key.secret_ideal.generator().coeffs() {
            sha3::digest::Update::update(&mut hasher, &coeff.to_be_bytes());
        }
        sha3::digest::Update::update(
            &mut hasher,
            &(challenge.as_bytes().len() as u32).to_be_bytes(),
        );
        sha3::digest::Update::update(&mut hasher, challenge.as_bytes());

        let mut reader = hasher.finalize_xof();
        let mut buf = vec![0u8; scalar_len * 4];
        reader.read(&mut buf);

        let mut p_coeff_0 = buf[0..scalar_len].to_vec();
        let mut p_coeff_1 = buf[scalar_len..2 * scalar_len].to_vec();
        let mut q_coeff_0 = buf[2 * scalar_len..3 * scalar_len].to_vec();
        let mut q_coeff_1 = buf[3 * scalar_len..4 * scalar_len].to_vec();

        mask_top_bits(&mut p_coeff_0, self.params.challenge_bits);
        mask_top_bits(&mut p_coeff_1, self.params.challenge_bits);
        mask_top_bits(&mut q_coeff_0, self.params.challenge_bits);
        mask_top_bits(&mut q_coeff_1, self.params.challenge_bits);
        ensure_non_zero_scalar(&mut p_coeff_0);
        ensure_non_zero_scalar(&mut q_coeff_1);

        ReferenceBasisCoefficients {
            p_coeff_0,
            p_coeff_1,
            q_coeff_0,
            q_coeff_1,
        }
    }

    fn derive_signature_points(
        &self,
        signature_codomain: &ReferenceCurveDescriptor,
        signature_basis: &ReferenceBasisDescriptor,
        basis_coefficients: &ReferenceBasisCoefficients,
    ) -> ReferenceSignaturePoints {
        ReferenceSignaturePoints {
            p_sig: derive_point_descriptor(
                b"AURORA:prism:reference:p-sig:v1",
                signature_codomain,
                signature_basis,
                basis_coefficients,
            ),
            q_sig: derive_point_descriptor(
                b"AURORA:prism:reference:q-sig:v1",
                signature_codomain,
                signature_basis,
                basis_coefficients,
            ),
        }
    }

    fn witness_commitment(&self, signature: &ReferenceSignatureBody) -> [u8; 32] {
        let payload = match signature.encoding {
            SignatureEncoding::CurveAndBasisCoefficients => {
                signature.basis_coefficients.commitment()
            }
            SignatureEncoding::CurveAndPoints => signature.signature_points.commitment(),
        };
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, b"AURORA:prism:reference:bound-witness:v1");
        sha3::Digest::update(&mut hasher, payload);
        sha3::Digest::update(&mut hasher, signature.ideal_witness.root_commitment());
        sha3::Digest::update(&mut hasher, signature.ideal_witness.step_hint_commitment());
        sha3::Digest::update(
            &mut hasher,
            qlapoti_step_hint_commitment(self.params, &signature.ideal_witness),
        );
        sha3::Digest::update(&mut hasher, signature.ideal_witness.stage_commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn actual_small_model_seed(
        &self,
        domain: &[u8],
        primary: &[u8; 32],
        secondary: &[u8; 32],
        challenge: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        sha3::Digest::update(&mut hasher, domain);
        sha3::Digest::update(&mut hasher, primary);
        sha3::Digest::update(&mut hasher, secondary);
        sha3::Digest::update(&mut hasher, (challenge.len() as u32).to_be_bytes());
        sha3::Digest::update(&mut hasher, challenge);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn actual_small_model_norm(seed: &[u8; 32]) -> IsogenyInteger {
        const SUPPORTED: [IsogenyInteger; 7] = [
            IsogenyInteger::from_u64(2),
            IsogenyInteger::from_u64(3),
            IsogenyInteger::from_u64(4),
            IsogenyInteger::from_u64(5),
            IsogenyInteger::from_u64(7),
            IsogenyInteger::from_u64(8),
            IsogenyInteger::from_u64(9),
        ];
        let index = usize::from(seed[0]) % SUPPORTED.len();
        SUPPORTED[index]
    }

    fn derive_actual_small_chain(
        &self,
        seed: [u8; 32],
    ) -> Result<crate::crypto::isogeny::algorithms::ActualIsogenyChain> {
        let order = self.reference_order()?;
        let norm = Self::actual_small_model_norm(&seed);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let ideal = RandomIdealSampler::sample_given_norm(&order, norm, &mut rng)?;
        IdealToIsogenyEngine::realize_small_qlapoti_chain_with_curve_search(&ideal)
            .map_err(ReferencePrismError::from)
    }

    fn derive_actual_small_witness(
        &self,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> Result<ActualProductIsogenyWitnessData> {
        let left_seed = self.actual_small_model_seed(
            b"AURORA:prism:reference:actual-left:v1",
            &verifying_key.codomain.tag,
            &verifying_key.torsion_basis.commitment(),
            challenge.as_bytes(),
        );
        let right_seed = self.actual_small_model_seed(
            b"AURORA:prism:reference:actual-right:v1",
            &signature.codomain.tag,
            &self.witness_commitment(signature),
            challenge.as_bytes(),
        );
        ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny {
            left: self.derive_actual_small_chain(left_seed)?,
            right: self.derive_actual_small_chain(right_seed)?,
        })
        .map_err(ReferencePrismError::from)
    }

    fn kani_binding_commitment(
        &self,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> Result<[u8; 32]> {
        if let Some(actual_witness) = &signature.actual_witness {
            let expected = ReferenceActualWitness::from_actual(&self.derive_actual_small_witness(
                verifying_key,
                challenge,
                signature,
            )?)
            .ok_or(ReferencePrismError::IdealToIsogeny(
                IdealToIsogenyError::UnsupportedActualDegree,
            ))?;
            if &expected != actual_witness {
                return Err(ReferencePrismError::Kani(KaniError::InvalidActualWitness));
            }
            actual_witness.to_actual()?;
            Ok(actual_kani_binding_commitment(
                self.params,
                actual_witness,
                &signature.ideal_witness,
            ))
        } else {
            Ok(self.witness_commitment(signature))
        }
    }

    fn public_kani_statement(
        &self,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> Result<crate::crypto::isogeny::algorithms::ProductIsogenyStatement> {
        Ok(KaniEngine::statement(
            verifying_key.codomain.tag,
            verifying_key.torsion_basis.commitment(),
            signature.codomain.tag,
            signature.torsion_basis.commitment(),
            signature.ideal_witness.stage_commitment(),
            match signature.actual_witness.as_ref() {
                Some(actual_witness) => actual_witness.actual_probe_commitment()?,
                None => [0u8; 32],
            },
            match signature.actual_witness.as_ref() {
                Some(actual_witness) => actual_witness.actual_quotient_commitment()?,
                None => [0u8; 32],
            },
            self.kani_binding_commitment(verifying_key, challenge, signature)?,
        ))
    }

    pub(crate) fn verify_public_consistency(
        &self,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> Result<bool> {
        let expected_vk_curve =
            IdealToIsogenyEngine::curve_descriptor_from_tag(verifying_key.codomain.tag);
        let expected_vk_basis = IdealToIsogenyEngine::basis_descriptor_from_tag(
            verifying_key.codomain.tag,
            self.params.challenge_bits,
        )?;
        if verifying_key.codomain != expected_vk_curve
            || verifying_key.torsion_basis != expected_vk_basis
        {
            return Ok(false);
        }

        if signature.degree != self.challenge_to_reference_degree(challenge) {
            return Ok(false);
        }
        if signature.torsion_basis.power as usize != self.params.challenge_bits {
            return Ok(false);
        }
        let expected_sig_curve =
            IdealToIsogenyEngine::curve_descriptor_from_tag(signature.codomain.tag);
        let expected_sig_basis = IdealToIsogenyEngine::basis_descriptor_from_tag(
            signature.codomain.tag,
            self.params.challenge_bits,
        )?;
        if signature.codomain != expected_sig_curve || signature.torsion_basis != expected_sig_basis
        {
            return Ok(false);
        }
        let order = self.reference_order()?;
        let expected_challenge_ideal =
            self.derive_challenge_ideal(verifying_key, challenge, signature.degree, order)?;
        let expected_left_plan = QlapotiEngine::plan_for_ideal(&expected_challenge_ideal);
        if signature.ideal_witness.left
            != ReferenceIdealTrace::from_ideal(&expected_challenge_ideal)
        {
            return Ok(false);
        }
        let right_ideal = match signature.ideal_witness.right.to_ideal(self.params) {
            Ok(ideal) => ideal,
            Err(_) => return Ok(false),
        };
        let expected_right_plan = QlapotiEngine::plan_for_ideal(&right_ideal);
        if signature.ideal_witness.left.norm != signature.degree
            || signature.ideal_witness.right.norm != signature.degree
            || !step_hints_compatible_with_plan(
                &expected_left_plan,
                &signature.ideal_witness.left_step_degrees,
            )
            || !step_hints_compatible_with_plan(
                &expected_right_plan,
                &signature.ideal_witness.right_step_degrees,
            )
            || !stage_traces_match_ideal(
                &expected_challenge_ideal,
                &signature.ideal_witness.left_step_degrees,
                &signature.ideal_witness.left_stage_traces,
                &signature.ideal_witness.left_stage_principal_traces,
            )
            || !stage_traces_match_ideal(
                &right_ideal,
                &signature.ideal_witness.right_step_degrees,
                &signature.ideal_witness.right_stage_traces,
                &signature.ideal_witness.right_stage_principal_traces,
            )
        {
            return Ok(false);
        }
        match signature.encoding {
            SignatureEncoding::CurveAndBasisCoefficients => {
                let expected_points = self.derive_signature_points(
                    &signature.codomain,
                    &signature.torsion_basis,
                    &signature.basis_coefficients,
                );
                if signature.signature_points != expected_points {
                    return Ok(false);
                }
            }
            SignatureEncoding::CurveAndPoints => {}
        }
        Ok(true)
    }
}

fn actual_kani_binding_commitment(
    params: &'static SaltPrismParameters,
    actual_witness: &ReferenceActualWitness,
    ideal_witness: &ReferenceIdealWitness,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(
        &mut hasher,
        b"AURORA:prism:reference:actual-kani-binding:v1",
    );
    sha3::Digest::update(&mut hasher, actual_witness.chain_commitment());
    sha3::Digest::update(&mut hasher, actual_witness.kernel_commitment());
    sha3::Digest::update(&mut hasher, actual_witness.probe_commitment());
    sha3::Digest::update(&mut hasher, actual_witness.quotient_commitment());
    sha3::Digest::update(&mut hasher, ideal_witness.root_commitment());
    sha3::Digest::update(&mut hasher, ideal_witness.step_hint_commitment());
    sha3::Digest::update(
        &mut hasher,
        qlapoti_step_hint_commitment(params, ideal_witness),
    );
    sha3::Digest::update(&mut hasher, ideal_witness.stage_commitment());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

impl PrismBackend for ReferencePrismBackend {
    type Error = ReferencePrismError;
    type VerifyingKey = ReferenceVerifyingKey;
    type SigningKey = ReferenceSigningKey;
    type SignatureBody = ReferenceSignatureBody;

    fn params(&self) -> &'static SaltPrismParameters {
        self.params
    }

    fn keygen(
        &mut self,
    ) -> core::result::Result<(Self::VerifyingKey, Self::SigningKey), Self::Error> {
        let order = self.reference_order()?;
        let generator = self.derive_secret_generator(self.key_counter, order.algebra());
        self.key_counter = self.key_counter.wrapping_add(1);

        // The reference model fixes the secret ideal norm to 1 so that the
        // challenge-derived ideal drives the public signature degree.
        let secret_ideal = LeftIdeal::new(order, order, generator, 1)?;
        let verifying_isogeny =
            IdealToIsogenyEngine::translate(&secret_ideal, self.params.challenge_bits)?;
        let verifying_key = ReferenceVerifyingKey {
            codomain: verifying_isogeny.codomain,
            torsion_basis: verifying_isogeny.torsion_basis,
        };
        let signing_key = ReferenceSigningKey {
            secret_ideal,
            verifying_codomain: verifying_isogeny.codomain,
            verifying_torsion_basis: verifying_isogeny.torsion_basis,
        };
        Ok((verifying_key, signing_key))
    }

    fn encode_verifying_key(&self, verifying_key: &Self::VerifyingKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(VERIFYING_KEY_LEN);
        out.push(VERIFYING_KEY_TAG);
        out.extend_from_slice(&verifying_key.codomain.tag);
        out.extend_from_slice(&verifying_key.codomain.hint);
        out.extend_from_slice(&verifying_key.torsion_basis.p_tag);
        out.extend_from_slice(&verifying_key.torsion_basis.q_tag);
        out.extend_from_slice(&verifying_key.torsion_basis.power.to_be_bytes());
        out.extend_from_slice(&verifying_key.torsion_basis.hint.to_be_bytes());
        out
    }

    fn sign_challenge(
        &mut self,
        verifying_key: &Self::VerifyingKey,
        signing_key: &Self::SigningKey,
        challenge: &ChallengePrime,
    ) -> core::result::Result<Self::SignatureBody, Self::Error> {
        let degree = self.challenge_to_reference_degree(challenge);
        let order = signing_key.secret_ideal.left_order();
        let challenge_ideal =
            self.derive_challenge_ideal(verifying_key, challenge, degree, order)?;
        let signature_ideal = signing_key.secret_ideal.intersect(&challenge_ideal)?;
        let ideal_witness = ReferenceIdealWitness::new(
            ReferenceIdealTrace::from_ideal(&challenge_ideal),
            ReferenceIdealTrace::from_ideal(&signature_ideal),
        );
        let signature_isogeny =
            IdealToIsogenyEngine::translate(&signature_ideal, self.params.challenge_bits)?;
        let basis_coefficients = self.derive_signature_coefficients(
            signing_key,
            &signature_isogeny.codomain,
            &signature_isogeny.torsion_basis,
            challenge,
        );
        let signature_points = self.derive_signature_points(
            &signature_isogeny.codomain,
            &signature_isogeny.torsion_basis,
            &basis_coefficients,
        );
        let actual_witness = if self.actual_small_model {
            Some(
                ReferenceActualWitness::from_actual(&self.derive_actual_small_witness(
                    verifying_key,
                    challenge,
                    &ReferenceSignatureBody {
                        encoding: self.signature_encoding,
                        degree: signature_isogeny.degree,
                        codomain: signature_isogeny.codomain,
                        torsion_basis: signature_isogeny.torsion_basis,
                        basis_coefficients: basis_coefficients.clone(),
                        signature_points: signature_points.clone(),
                        ideal_witness: ideal_witness.clone(),
                        actual_witness: None,
                        kani: KaniTranscript {
                            kernel: crate::crypto::isogeny::algorithms::KaniKernel {
                                pairing_commitment: [0u8; 32],
                                torsion_commitment: [0u8; 32],
                            },
                            image: crate::crypto::isogeny::algorithms::KaniImage {
                                left_codomain_tag: [0u8; 32],
                                right_codomain_tag: [0u8; 32],
                            },
                        },
                    },
                )?)
                .ok_or(ReferencePrismError::IdealToIsogeny(
                    IdealToIsogenyError::UnsupportedActualDegree,
                ))?,
            )
        } else {
            None
        };
        let mut signature = ReferenceSignatureBody {
            encoding: self.signature_encoding,
            degree: signature_isogeny.degree,
            codomain: signature_isogeny.codomain,
            torsion_basis: signature_isogeny.torsion_basis,
            basis_coefficients,
            signature_points,
            ideal_witness,
            actual_witness,
            kani: KaniTranscript {
                kernel: crate::crypto::isogeny::algorithms::KaniKernel {
                    pairing_commitment: [0u8; 32],
                    torsion_commitment: [0u8; 32],
                },
                image: crate::crypto::isogeny::algorithms::KaniImage {
                    left_codomain_tag: [0u8; 32],
                    right_codomain_tag: [0u8; 32],
                },
            },
        };
        let kani = if let Some(actual_witness) = &signature.actual_witness {
            let statement = self.public_kani_statement(verifying_key, challenge, &signature)?;
            KaniEngine::construct_actual(
                statement,
                &actual_witness.to_actual()?,
                challenge.as_bytes(),
            )?
        } else {
            let kani_binding =
                self.kani_binding_commitment(verifying_key, challenge, &signature)?;
            KaniEngine::construct(
                signing_key.verifying_codomain.tag,
                signing_key.verifying_torsion_basis.commitment(),
                signature.codomain.tag,
                signature.torsion_basis.commitment(),
                signature.ideal_witness.stage_commitment(),
                [0u8; 32],
                [0u8; 32],
                kani_binding,
                challenge.as_bytes(),
            )
        };
        signature.kani = kani;
        Ok(signature)
    }

    fn encode_signature_body(&self, signature: &Self::SignatureBody) -> Vec<u8> {
        let mut out = Vec::with_capacity(signature_body_len(
            signature.encoding,
            self.params.challenge_bits,
            &signature.ideal_witness,
            signature.actual_witness.as_ref(),
        ));
        out.push(SIGNATURE_BODY_TAG);
        out.push(signature_encoding_to_wire(
            signature.encoding,
            signature.actual_witness.is_some(),
        ));
        out.extend_from_slice(&signature.degree.to_be_bytes_fixed());
        out.extend_from_slice(&signature.codomain.tag);
        out.extend_from_slice(&signature.codomain.hint);
        out.extend_from_slice(&signature.torsion_basis.p_tag);
        out.extend_from_slice(&signature.torsion_basis.q_tag);
        out.extend_from_slice(&signature.torsion_basis.power.to_be_bytes());
        out.extend_from_slice(&signature.torsion_basis.hint.to_be_bytes());
        match signature.encoding {
            SignatureEncoding::CurveAndBasisCoefficients => {
                signature.basis_coefficients.encode_into(&mut out);
            }
            SignatureEncoding::CurveAndPoints => {
                out.extend_from_slice(&signature.signature_points.p_sig.tag);
                out.extend_from_slice(&signature.signature_points.p_sig.hint);
                out.extend_from_slice(&signature.signature_points.q_sig.tag);
                out.extend_from_slice(&signature.signature_points.q_sig.hint);
            }
        }
        out.extend_from_slice(&(signature.ideal_witness.encoded_len() as u16).to_be_bytes());
        signature.ideal_witness.encode_into(&mut out);
        if let Some(actual_witness) = &signature.actual_witness {
            actual_witness.encode_into(&mut out);
        }
        out.extend_from_slice(&signature.kani.kernel.pairing_commitment);
        out.extend_from_slice(&signature.kani.kernel.torsion_commitment);
        out.extend_from_slice(&signature.kani.image.left_codomain_tag);
        out.extend_from_slice(&signature.kani.image.right_codomain_tag);
        out
    }

    fn decode_signature_body(&self, bytes: &[u8]) -> Option<Self::SignatureBody> {
        if bytes.first().copied()? != SIGNATURE_BODY_TAG {
            return None;
        }
        let (encoding, has_actual_witness) = signature_encoding_from_wire(*bytes.get(1)?)?;
        let min_len = signature_body_len(
            encoding,
            self.params.challenge_bits,
            &ReferenceIdealWitness::new(
                ReferenceIdealTrace {
                    norm: 1u128.into(),
                    generator_coeffs: [
                        QuaternionInteger::from(1i32),
                        QuaternionInteger::zero(),
                        QuaternionInteger::zero(),
                        QuaternionInteger::zero(),
                    ],
                    basis_coeffs: [[QuaternionInteger::zero(); 4]; 4],
                },
                ReferenceIdealTrace {
                    norm: 1u128.into(),
                    generator_coeffs: [
                        QuaternionInteger::from(1i32),
                        QuaternionInteger::zero(),
                        QuaternionInteger::zero(),
                        QuaternionInteger::zero(),
                    ],
                    basis_coeffs: [[QuaternionInteger::zero(); 4]; 4],
                },
            ),
            None,
        );
        if bytes.len() < min_len {
            return None;
        }

        let degree_start = 2;
        let degree_end = degree_start + IsogenyInteger::BYTES;
        let codomain_tag_start = degree_end;
        let codomain_tag_end = codomain_tag_start + 32;
        let codomain_hint_start = codomain_tag_end;
        let codomain_hint_end = codomain_hint_start + 16;
        let p_tag_start = codomain_hint_end;
        let p_tag_end = p_tag_start + 32;
        let q_tag_start = p_tag_end;
        let q_tag_end = q_tag_start + 32;
        let power_start = q_tag_end;
        let power_end = power_start + 2;
        let hint_start = power_end;
        let hint_end = hint_start + 2;
        let witness_start = hint_end;

        let degree = IsogenyInteger::from_be_slice(bytes.get(degree_start..degree_end)?)?;
        let codomain_tag = bytes[codomain_tag_start..codomain_tag_end]
            .try_into()
            .ok()?;
        let codomain_hint = bytes[codomain_hint_start..codomain_hint_end]
            .try_into()
            .ok()?;
        let p_tag = bytes[p_tag_start..p_tag_end].try_into().ok()?;
        let q_tag = bytes[q_tag_start..q_tag_end].try_into().ok()?;
        let power = u16::from_be_bytes(bytes[power_start..power_end].try_into().ok()?);
        let hint = u16::from_be_bytes(bytes[hint_start..hint_end].try_into().ok()?);
        let (basis_coefficients, signature_points, transcript_start) = match encoding {
            SignatureEncoding::CurveAndBasisCoefficients => {
                let scalar_len =
                    ReferenceBasisCoefficients::scalar_bytes(self.params.challenge_bits);
                let coefficient_bytes = scalar_len.checked_mul(4)?;
                let witness_end = witness_start + coefficient_bytes;
                let basis_coefficients = ReferenceBasisCoefficients::decode_from(
                    &bytes[witness_start..witness_end],
                    self.params.challenge_bits,
                )?;
                let signature_points = self.derive_signature_points(
                    &ReferenceCurveDescriptor {
                        tag: codomain_tag,
                        hint: codomain_hint,
                    },
                    &ReferenceBasisDescriptor {
                        p_tag,
                        q_tag,
                        power,
                        hint,
                    },
                    &basis_coefficients,
                );
                (basis_coefficients, signature_points, witness_end)
            }
            SignatureEncoding::CurveAndPoints => {
                let p_sig_tag = bytes[witness_start..witness_start + 32].try_into().ok()?;
                let p_sig_hint = bytes[witness_start + 32..witness_start + 48]
                    .try_into()
                    .ok()?;
                let q_sig_tag = bytes[witness_start + 48..witness_start + 80]
                    .try_into()
                    .ok()?;
                let q_sig_hint = bytes[witness_start + 80..witness_start + 96]
                    .try_into()
                    .ok()?;
                (
                    ReferenceBasisCoefficients::empty(),
                    ReferenceSignaturePoints {
                        p_sig: ReferencePointDescriptor {
                            tag: p_sig_tag,
                            hint: p_sig_hint,
                        },
                        q_sig: ReferencePointDescriptor {
                            tag: q_sig_tag,
                            hint: q_sig_hint,
                        },
                    },
                    witness_start + 96,
                )
            }
        };
        let ideal_len = u16::from_be_bytes(
            bytes
                .get(transcript_start..transcript_start + 2)?
                .try_into()
                .ok()?,
        );
        let ideal_len = usize::from(ideal_len);
        let ideal_start = transcript_start + 2;
        let ideal_end = ideal_start.checked_add(ideal_len)?;
        let final_transcript_start = bytes.len().checked_sub(128)?;
        if ideal_end > final_transcript_start {
            return None;
        }
        let (ideal_witness, decoded_ideal_len) =
            ReferenceIdealWitness::decode_from(&bytes[ideal_start..ideal_end])?;
        if decoded_ideal_len != ideal_len {
            return None;
        }
        let final_transcript_start = if has_actual_witness {
            final_transcript_start
        } else {
            ideal_end
        };
        if final_transcript_start < ideal_end {
            return None;
        }
        if !has_actual_witness && bytes.len() != ideal_end + 128 {
            return None;
        }
        let actual_witness = if has_actual_witness {
            Some(ReferenceActualWitness::decode_from(
                &bytes[ideal_end..final_transcript_start],
            )?)
        } else {
            None
        };
        let pairing_commitment = bytes[final_transcript_start..final_transcript_start + 32]
            .try_into()
            .ok()?;
        let torsion_commitment = bytes[final_transcript_start + 32..final_transcript_start + 64]
            .try_into()
            .ok()?;
        let left_codomain_tag = bytes[final_transcript_start + 64..final_transcript_start + 96]
            .try_into()
            .ok()?;
        let right_codomain_tag = bytes[final_transcript_start + 96..final_transcript_start + 128]
            .try_into()
            .ok()?;

        Some(ReferenceSignatureBody {
            encoding,
            degree,
            codomain: ReferenceCurveDescriptor {
                tag: codomain_tag,
                hint: codomain_hint,
            },
            torsion_basis: ReferenceBasisDescriptor {
                p_tag,
                q_tag,
                power,
                hint,
            },
            basis_coefficients,
            signature_points,
            ideal_witness,
            actual_witness,
            kani: KaniTranscript {
                kernel: crate::crypto::isogeny::algorithms::KaniKernel {
                    pairing_commitment,
                    torsion_commitment,
                },
                image: crate::crypto::isogeny::algorithms::KaniImage {
                    left_codomain_tag,
                    right_codomain_tag,
                },
            },
        })
    }

    fn verify_challenge(
        &self,
        verifying_key: &Self::VerifyingKey,
        challenge: &ChallengePrime,
        signature: &Self::SignatureBody,
    ) -> core::result::Result<bool, Self::Error> {
        if !self.verify_public_consistency(verifying_key, challenge, signature)? {
            return Ok(false);
        }
        let kani_binding = match self.kani_binding_commitment(verifying_key, challenge, signature) {
            Ok(binding) => binding,
            Err(ReferencePrismError::Kani(KaniError::InvalidActualWitness))
            | Err(ReferencePrismError::IdealToIsogeny(IdealToIsogenyError::KernelSearchFailed))
            | Err(ReferencePrismError::IdealToIsogeny(
                IdealToIsogenyError::UnsupportedActualDegree,
            )) => return Ok(false),
            Err(error) => return Err(error),
        };
        let kani_result = if let Some(actual_witness) = &signature.actual_witness {
            let statement = self.public_kani_statement(verifying_key, challenge, signature)?;
            KaniEngine::verify_actual(
                &signature.kani,
                statement,
                &actual_witness.to_actual()?,
                challenge.as_bytes(),
            )
        } else {
            KaniEngine::verify(
                &signature.kani,
                verifying_key.codomain.tag,
                verifying_key.torsion_basis.commitment(),
                signature.codomain.tag,
                signature.torsion_basis.commitment(),
                signature.ideal_witness.stage_commitment(),
                [0u8; 32],
                [0u8; 32],
                kani_binding,
                challenge.as_bytes(),
            )
        };
        match kani_result {
            Ok(()) => Ok(true),
            Err(KaniError::InvalidTranscript)
            | Err(KaniError::InvalidActualWitness)
            | Err(KaniError::IdealToIsogeny(_)) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::crypto::isogeny::algorithms::KaniError;
    use crate::crypto::isogeny::algorithms::QlapotiEngine;
    use crate::crypto::isogeny::arith::{IsogenyInteger, QuaternionInteger};
    use crate::crypto::isogeny::params::NIST_LEVEL1_BASE;
    use crate::crypto::prism::{
        keygen_with_backend, sign_with_backend, verify_with_backend, PrismBackend,
        ReferenceIdealTrace, ReferenceIdealWitness, SaltPrismParameters, SignatureEncoding,
    };

    use super::{
        signature_body_len, ReferenceActualWitness, ReferenceBasisCoefficients,
        ReferencePrismBackend, ReferenceSignatureBody, VERIFYING_KEY_LEN, VERIFYING_KEY_TAG,
    };

    const TEST_PARAMS: SaltPrismParameters = SaltPrismParameters {
        security_bits: 16,
        base: NIST_LEVEL1_BASE,
        challenge_bits: 16,
        hash_bits: 16,
        salt_bits: 16,
        max_signatures_log2: 8,
    };

    fn run_on_large_stack<F>(f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn reference_backend_roundtrip_verifies() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        assert!(verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap());
        assert!(!verify_with_backend(&backend, &verifying_key, b"tampered", &signature).unwrap());
    }

    #[test]
    fn successive_keygen_outputs_change() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (vk1, _) = keygen_with_backend(&mut backend).unwrap();
        let (vk2, _) = keygen_with_backend(&mut backend).unwrap();
        assert_ne!(vk1.codomain.tag, vk2.codomain.tag);
        assert_ne!(vk1.torsion_basis.p_tag, vk2.torsion_basis.p_tag);
    }

    #[test]
    fn decode_rejects_wrong_tag_or_length() {
        let backend = ReferencePrismBackend::new(&TEST_PARAMS);
        assert!(backend.decode_signature_body(&[]).is_none());
        let malformed = vec![
            0u8;
            signature_body_len(
                backend.signature_encoding(),
                TEST_PARAMS.challenge_bits,
                &ReferenceIdealWitness::new(
                    ReferenceIdealTrace {
                        norm: 1u128.into(),
                        generator_coeffs: [
                            QuaternionInteger::from(1i32),
                            QuaternionInteger::zero(),
                            QuaternionInteger::zero(),
                            QuaternionInteger::zero(),
                        ],
                        basis_coeffs: [[QuaternionInteger::zero(); 4]; 4],
                    },
                    ReferenceIdealTrace {
                        norm: 1u128.into(),
                        generator_coeffs: [
                            QuaternionInteger::from(1i32),
                            QuaternionInteger::zero(),
                            QuaternionInteger::zero(),
                            QuaternionInteger::zero(),
                        ],
                        basis_coeffs: [[QuaternionInteger::zero(); 4]; 4],
                    },
                ),
                None
            )
        ];
        assert!(backend.decode_signature_body(&malformed).is_none());
    }

    #[test]
    fn signature_body_roundtrip_is_lossless() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        let decoded: ReferenceSignatureBody =
            backend.decode_signature_body(&signature.body).unwrap();
        let reencoded = backend.encode_signature_body(&decoded);
        assert_eq!(signature.body, reencoded);
    }

    #[test]
    fn verifying_key_encoding_is_stable() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, _) = keygen_with_backend(&mut backend).unwrap();
        let encoded = backend.encode_verifying_key(&verifying_key);
        assert_eq!(encoded.len(), VERIFYING_KEY_LEN);
        assert_eq!(encoded[0], VERIFYING_KEY_TAG);
    }

    #[test]
    fn verify_rejects_tampered_basis_coefficients() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
        let mut signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        let coeff_offset = super::signature_body_fixed_prefix_len();
        signature.body[coeff_offset] ^= 1;
        assert!(!verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_ideal_witness() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
        let mut signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        let coeff_bytes = ReferenceBasisCoefficients::scalar_bytes(TEST_PARAMS.challenge_bits) * 4;
        let ideal_offset = super::signature_body_fixed_prefix_len() + coeff_bytes + 2;
        signature.body[ideal_offset] ^= 1;
        assert!(!verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_right_ideal_witness() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([24u8; 32]);
        let mut signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        let coeff_bytes = ReferenceBasisCoefficients::scalar_bytes(TEST_PARAMS.challenge_bits) * 4;
        let right_ideal_offset = super::signature_body_fixed_prefix_len()
            + coeff_bytes
            + 2
            + ReferenceIdealTrace::encoded_len();
        signature.body[right_ideal_offset] ^= 1;
        assert!(!verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap());
    }

    #[test]
    fn points_encoding_roundtrip_verifies() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS)
            .with_signature_encoding(SignatureEncoding::CurveAndPoints);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([25u8; 32]);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        assert!(verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap());
        let decoded = backend.decode_signature_body(&signature.body).unwrap();
        assert_eq!(decoded.encoding, SignatureEncoding::CurveAndPoints);
    }

    #[test]
    fn ideal_trace_rejects_zero_basis_element() {
        use crate::crypto::isogeny::ideal::{
            LeftIdeal, MaximalOrder, QuaternionAlgebra, QuaternionElement,
        };

        let algebra = QuaternionAlgebra::new(TEST_PARAMS.base.cofactor).unwrap();
        let order = MaximalOrder::reference(algebra);
        let ideal =
            LeftIdeal::principal(order, QuaternionElement::from_coeffs(algebra, [1, 2, 0, 1]))
                .unwrap();
        let mut trace = ReferenceIdealTrace::from_ideal(&ideal);
        trace.basis_coeffs[0] = [QuaternionInteger::zero(); 4];
        assert!(matches!(
            trace.to_ideal_with_orders(order, order),
            Err(super::ReferencePrismError::Ideal(
                crate::crypto::isogeny::ideal::IdealError::ZeroBasisElement
            ))
        ));
    }

    #[test]
    fn actual_small_model_roundtrip_verifies() {
        run_on_large_stack(|| {
            let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([27u8; 32]);
            let signature = sign_with_backend(
                &mut backend,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                256,
            )
            .unwrap();

            assert!(verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap());
            assert!(
                !verify_with_backend(&backend, &verifying_key, b"tampered", &signature).unwrap()
            );
        });
    }

    #[test]
    fn actual_small_model_rejects_witness_tampering() {
        run_on_large_stack(|| {
            let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([29u8; 32]);
            let mut signature = sign_with_backend(
                &mut backend,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                256,
            )
            .unwrap();

            let coeff_offset = super::signature_body_fixed_prefix_len();
            signature.body[coeff_offset] ^= 1;
            assert!(
                !verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap()
            );
        });
    }

    #[test]
    fn actual_small_model_signature_encodes_actual_witness() {
        run_on_large_stack(|| {
            let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
            let signature = sign_with_backend(
                &mut backend,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                256,
            )
            .unwrap();

            let decoded = backend.decode_signature_body(&signature.body).unwrap();
            assert_eq!(decoded.ideal_witness.left.norm, decoded.degree);
            assert_eq!(decoded.ideal_witness.right.norm, decoded.degree);
            assert!(decoded.actual_witness.is_some());
            assert_eq!(signature.body, backend.encode_signature_body(&decoded));
        });
    }

    #[test]
    fn actual_small_model_witness_roundtrips_explicit_samples() {
        run_on_large_stack(|| {
            let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([32u8; 32]);
            let signature = sign_with_backend(
                &mut backend,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                256,
            )
            .unwrap();

            let decoded = backend.decode_signature_body(&signature.body).unwrap();
            let actual = decoded.actual_witness.clone().unwrap().to_actual().unwrap();
            let reencoded = ReferenceActualWitness::from_actual(&actual).unwrap();
            assert_eq!(reencoded, decoded.actual_witness.unwrap());
        });
    }

    #[test]
    fn actual_small_model_rejects_tampered_target_identity() {
        run_on_large_stack(|| {
            let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([33u8; 32]);
            let signature = sign_with_backend(
                &mut backend,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                256,
            )
            .unwrap();

            let decoded = backend.decode_signature_body(&signature.body).unwrap();
            let actual_witness = decoded.actual_witness.clone().unwrap();
            let actual = actual_witness.to_actual().unwrap();
            let left_target = actual.isogeny.left.target;
            let original = actual_witness.quotient_profile.target_identity.left;

            let replacement = (1..=8u64)
                .find_map(|delta| {
                    let x = original
                        .x
                        .add(&crate::crypto::isogeny::field::Fp2::from_u64(
                            left_target.modulus(),
                            delta,
                        ))
                        .ok()?;
                    let candidate =
                        crate::crypto::isogeny::curve::point::CurvePoint::affine(x, original.y);
                    (!left_target.is_on_curve(&candidate).ok()?).then_some(candidate)
                })
                .expect("expected invalid target identity");

            let mut tampered = actual_witness;
            tampered.quotient_profile.target_identity.left = replacement;
            assert!(matches!(
                tampered.to_actual(),
                Err(super::ReferencePrismError::Kani(
                    KaniError::InvalidActualWitness
                ))
            ));
        });
    }

    #[test]
    fn actual_small_model_rejects_tampered_generator_triple_image() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([34u8; 32]);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        let decoded = backend.decode_signature_body(&signature.body).unwrap();
        let mut actual_witness = decoded.actual_witness.unwrap();
        let identity = actual_witness
            .to_actual()
            .unwrap()
            .isogeny
            .target_identity();
        actual_witness.quotient_profile.generator_triple_images[0] =
            super::ReferenceProductPoint::from_actual(identity);

        assert!(matches!(
            actual_witness.to_actual(),
            Err(super::ReferencePrismError::Kani(
                KaniError::InvalidActualWitness
            ))
        ));
    }

    #[test]
    fn actual_witness_component_commitments_split_kernel_and_quotient() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([34u8; 32]);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        let actual_witness = backend
            .decode_signature_body(&signature.body)
            .unwrap()
            .actual_witness
            .unwrap();

        let mut kernel_tampered = actual_witness.clone();
        kernel_tampered.kernel.p.left.infinity = !kernel_tampered.kernel.p.left.infinity;
        assert_eq!(
            actual_witness.quotient_commitment(),
            kernel_tampered.quotient_commitment()
        );
        assert_ne!(
            actual_witness.kernel_commitment(),
            kernel_tampered.kernel_commitment()
        );

        let mut quotient_tampered = actual_witness.clone();
        quotient_tampered.quotient_profile.target_identity =
            quotient_tampered.quotient_profile.images[0];
        assert_eq!(
            actual_witness.kernel_commitment(),
            quotient_tampered.kernel_commitment()
        );
        assert_ne!(
            actual_witness.quotient_commitment(),
            quotient_tampered.quotient_commitment()
        );
    }

    #[test]
    fn actual_witness_rejects_tampered_section_length() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([36u8; 32]);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        let actual_witness = backend
            .decode_signature_body(&signature.body)
            .unwrap()
            .actual_witness
            .unwrap();
        let mut encoded = Vec::new();
        actual_witness.encode_into(&mut encoded);

        let left_len = u32::from_be_bytes(encoded[0..4].try_into().unwrap()) as usize;
        let right_offset = 4 + left_len;
        let right_len =
            u32::from_be_bytes(encoded[right_offset..right_offset + 4].try_into().unwrap())
                as usize;
        let kernel_offset = right_offset + 4 + right_len;
        let kernel_len = u32::from_be_bytes(
            encoded[kernel_offset..kernel_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let quotient_offset = kernel_offset + 4 + kernel_len;
        let mut quotient_len = u32::from_be_bytes(
            encoded[quotient_offset..quotient_offset + 4]
                .try_into()
                .unwrap(),
        );
        quotient_len += 1;
        encoded[quotient_offset..quotient_offset + 4].copy_from_slice(&quotient_len.to_be_bytes());

        assert!(ReferenceActualWitness::decode_from(&encoded).is_none());
    }

    #[test]
    fn actual_small_model_supports_extended_norm_set() {
        run_on_large_stack(|| {
            let backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
            let mut norms = Vec::new();
            for selector in 0u8..7 {
                let mut seed = [0u8; 32];
                seed[0] = selector;
                let chain = backend.derive_actual_small_chain(seed).unwrap();
                norms.push(
                    chain
                        .steps
                        .iter()
                        .fold(1u128, |acc, step| acc * u128::from(step.degree as u64)),
                );
            }
            norms.sort_unstable();
            norms.dedup();
            assert_eq!(norms, vec![2, 3, 4, 5, 7, 8, 9]);
        });
    }

    #[test]
    fn actual_small_model_rejects_actual_witness_tampering() {
        run_on_large_stack(|| {
            let mut backend = ReferencePrismBackend::new(&TEST_PARAMS).with_actual_small_model(true);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([33u8; 32]);
            let mut signature = sign_with_backend(
                &mut backend,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                256,
            )
            .unwrap();

            let decoded = backend.decode_signature_body(&signature.body).unwrap();
            let payload_len = match decoded.encoding {
                SignatureEncoding::CurveAndBasisCoefficients => {
                    ReferenceBasisCoefficients::scalar_bytes(TEST_PARAMS.challenge_bits) * 4
                }
                SignatureEncoding::CurveAndPoints => 96,
            };
            let actual_offset = super::signature_body_fixed_prefix_len()
                + payload_len
                + 2
                + decoded.ideal_witness.encoded_len();
            signature.body[actual_offset] ^= 1;
            assert!(
                !verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap()
            );
        });
    }

    #[test]
    fn step_hints_accept_supported_subdecompositions() {
        let plan = QlapotiEngine::plan_for_degree(360);
        assert!(super::step_hints_compatible_with_plan(
            &plan,
            &[
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(5u64),
            ]
        ));
        assert!(super::step_hints_compatible_with_plan(
            &plan,
            &[IsogenyInteger::from(8u64), IsogenyInteger::from(5u64)]
        ));
        assert!(super::step_hints_compatible_with_plan(
            &plan,
            &[
                IsogenyInteger::from(4u64),
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(9u64),
            ]
        ));
        assert!(super::step_hints_compatible_with_plan(
            &plan,
            &[IsogenyInteger::from(9u64)]
        ));
        assert!(super::step_hints_compatible_with_plan(&plan, &[]));
    }

    #[test]
    fn step_hints_reject_incompatible_decompositions() {
        let plan = QlapotiEngine::plan_for_degree(360);
        assert!(!super::step_hints_compatible_with_plan(
            &plan,
            &[IsogenyInteger::from(27u64)]
        ));
        assert!(!super::step_hints_compatible_with_plan(
            &plan,
            &[IsogenyInteger::from(25u64)]
        ));
        assert!(!super::step_hints_compatible_with_plan(
            &plan,
            &[
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(5u64),
            ]
        ));
        assert!(!super::step_hints_compatible_with_plan(
            &plan,
            &[IsogenyInteger::from(15u64), IsogenyInteger::from(3u64)]
        ));
        assert!(!super::step_hints_compatible_with_plan(
            &plan,
            &[
                IsogenyInteger::from(9u64),
                IsogenyInteger::from(4u64),
                IsogenyInteger::from(2u64),
            ]
        ));
    }
}

fn signature_body_len(
    encoding: SignatureEncoding,
    power_bits: usize,
    ideal_witness: &ReferenceIdealWitness,
    actual_witness: Option<&ReferenceActualWitness>,
) -> usize {
    let witness_len = match encoding {
        SignatureEncoding::CurveAndBasisCoefficients => {
            ReferenceBasisCoefficients::scalar_bytes(power_bits) * 4
        }
        SignatureEncoding::CurveAndPoints => 32 + 16 + 32 + 16,
    };
    1 + 1
        + IsogenyInteger::BYTES
        + 32
        + 16
        + 32
        + 32
        + 2
        + 2
        + witness_len
        + 2
        + ideal_witness.encoded_len()
        + actual_witness.map_or(0, ReferenceActualWitness::encoded_len)
        + 32
        + 32
        + 32
        + 32
}

fn signature_body_fixed_prefix_len() -> usize {
    1 + 1 + IsogenyInteger::BYTES + 32 + 16 + 32 + 32 + 2 + 2
}

fn framed_section_len(payload_len: usize) -> usize {
    4 + payload_len
}

fn encode_framed_section(out: &mut Vec<u8>, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

fn decode_framed_section(bytes: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let len = u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
    let len = usize::try_from(len).ok()?;
    let start = offset.checked_add(4)?;
    let end = start.checked_add(len)?;
    Some((bytes.get(start..end)?, end))
}

fn mask_top_bits(bytes: &mut [u8], bits: usize) {
    if bytes.is_empty() {
        return;
    }
    let rem = bits % 8;
    if rem != 0 {
        bytes[0] &= (1u8 << rem) - 1;
    }
}

fn unused_top_bits_zero(bytes: &[u8], bits: usize) -> bool {
    if bytes.is_empty() {
        return bits == 0;
    }
    let rem = bits % 8;
    if rem == 0 {
        true
    } else {
        (bytes[0] >> rem) == 0
    }
}

fn ensure_non_zero_scalar(bytes: &mut [u8]) {
    if bytes.iter().all(|byte| *byte == 0) && !bytes.is_empty() {
        let last = bytes.len() - 1;
        bytes[last] = 1;
    }
}

fn signature_encoding_to_wire(encoding: SignatureEncoding, has_actual_witness: bool) -> u8 {
    let base = match encoding {
        SignatureEncoding::CurveAndPoints => 0x01,
        SignatureEncoding::CurveAndBasisCoefficients => 0x02,
    };
    if has_actual_witness {
        base | 0x80
    } else {
        base
    }
}

fn signature_encoding_from_wire(byte: u8) -> Option<(SignatureEncoding, bool)> {
    let has_actual_witness = (byte & 0x80) != 0;
    let encoding = match byte & 0x7f {
        0x01 => SignatureEncoding::CurveAndPoints,
        0x02 => SignatureEncoding::CurveAndBasisCoefficients,
        _ => return None,
    };
    Some((encoding, has_actual_witness))
}

fn encoded_curve_len(curve: &ShortWeierstrassCurve) -> usize {
    let width = curve.modulus().byte_len();
    1 + width + width * 4
}

fn encoded_point_len(modulus: &FpModulus) -> usize {
    1 + modulus.byte_len() * 4
}

fn encode_curve(curve: &ShortWeierstrassCurve, out: &mut Vec<u8>) {
    let mut modulus_be = Vec::with_capacity(curve.modulus().byte_len());
    for limb in curve.modulus().as_limbs().iter().rev() {
        modulus_be.extend_from_slice(&limb.to_be_bytes());
    }
    let first_non_zero = modulus_be
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(modulus_be.len().saturating_sub(1));
    modulus_be = modulus_be[first_non_zero..].to_vec();
    out.push(modulus_be.len() as u8);
    out.extend_from_slice(&modulus_be);
    encode_fp2(&curve.a, out);
    encode_fp2(&curve.b, out);
}

fn decode_curve(bytes: &[u8], offset: usize) -> Option<(ShortWeierstrassCurve, usize)> {
    let modulus_len = *bytes.get(offset)? as usize;
    let modulus_bytes = bytes.get(offset + 1..offset + 1 + modulus_len)?;
    let modulus = FpModulus::from_be_bytes(modulus_bytes).ok()?;
    let (a, after_a) = decode_fp2(bytes, offset + 1 + modulus_len, &modulus)?;
    let (b, cursor) = decode_fp2(bytes, after_a, &modulus)?;
    Some((ShortWeierstrassCurve::new(a, b).ok()?, cursor))
}

fn encode_fp2(value: &Fp2, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.c0.to_be_bytes());
    out.extend_from_slice(&value.c1.to_be_bytes());
}

fn decode_fp2(bytes: &[u8], offset: usize, modulus: &FpModulus) -> Option<(Fp2, usize)> {
    let width = modulus.byte_len();
    let c0 = crate::crypto::isogeny::field::Fp::from_be_bytes(
        modulus,
        bytes.get(offset..offset + width)?,
    );
    let c1 = crate::crypto::isogeny::field::Fp::from_be_bytes(
        modulus,
        bytes.get(offset + width..offset + 2 * width)?,
    );
    Some((Fp2::new(c0, c1).ok()?, offset + 2 * width))
}

fn encode_point(point: &CurvePoint, out: &mut Vec<u8>) {
    out.push(u8::from(point.infinity));
    encode_fp2(&point.x, out);
    encode_fp2(&point.y, out);
}

fn decode_point(bytes: &[u8], offset: usize, modulus: &FpModulus) -> Option<(CurvePoint, usize)> {
    let infinity = *bytes.get(offset)? != 0;
    let (x, after_x) = decode_fp2(bytes, offset + 1, modulus)?;
    let (y, cursor) = decode_fp2(bytes, after_x, modulus)?;
    Some((
        if infinity {
            CurvePoint::infinity(modulus)
        } else {
            CurvePoint::affine(x, y)
        },
        cursor,
    ))
}

fn derive_point_descriptor(
    domain: &[u8],
    codomain: &ReferenceCurveDescriptor,
    basis: &ReferenceBasisDescriptor,
    coefficients: &ReferenceBasisCoefficients,
) -> ReferencePointDescriptor {
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, domain);
    sha3::Digest::update(&mut hasher, codomain.tag);
    sha3::Digest::update(&mut hasher, codomain.hint);
    sha3::Digest::update(&mut hasher, basis.commitment());
    sha3::Digest::update(&mut hasher, coefficients.commitment());
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&hasher.finalize());

    let mut hint_hasher = Sha3_256::new();
    sha3::Digest::update(&mut hint_hasher, b"AURORA:prism:reference:point-hint:v1");
    sha3::Digest::update(&mut hint_hasher, tag);
    let hint_hash = hint_hasher.finalize();
    let mut hint = [0u8; 16];
    hint.copy_from_slice(&hint_hash[..16]);

    ReferencePointDescriptor { tag, hint }
}
