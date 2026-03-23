//! Kani's lemma based 2-dimensional isogeny constructions.

use alloc::{boxed::Box, vec::Vec};

use crate::crypto::isogeny::algorithms::ideal_to_isogeny::{
    ActualIsogenyChain, IdealToIsogenyError,
};
use crate::crypto::isogeny::algorithms::theta::{
    theta_product_isogeny_sqrt_no_strategy, ThetaCouplePoint,
};
use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::curve::weierstrass::MontgomeryIsomorphism;
use crate::crypto::isogeny::curve::weierstrass::ShortWeierstrassCurve;
use crate::crypto::isogeny::curve::xonly::{x_of_difference, Proj1};
use crate::crypto::isogeny::field::{Fp, Fp2};
use sha3::{Digest, Sha3_256};

pub type Result<T> = core::result::Result<T, KaniError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KaniError {
    InvalidTranscript,
    InvalidActualWitness,
    IdealToIsogeny(IdealToIsogenyError),
}

impl From<IdealToIsogenyError> for KaniError {
    fn from(value: IdealToIsogenyError) -> Self {
        Self::IdealToIsogeny(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaniKernel {
    pub pairing_commitment: [u8; 32],
    pub torsion_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaniImage {
    pub left_codomain_tag: [u8; 32],
    pub right_codomain_tag: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaniTranscript {
    pub kernel: KaniKernel,
    pub image: KaniImage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductIsogenyStatement {
    pub verifying_codomain_tag: [u8; 32],
    pub verifying_basis_commitment: [u8; 32],
    pub signature_codomain_tag: [u8; 32],
    pub signature_basis_commitment: [u8; 32],
    pub decomposition_commitment: [u8; 32],
    pub probe_commitment: [u8; 32],
    pub quotient_commitment: [u8; 32],
    pub witness_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductIsogenyWitness {
    pub statement: ProductIsogenyStatement,
    pub transcript: KaniTranscript,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductPoint {
    pub left: CurvePoint,
    pub right: CurvePoint,
}

impl ProductPoint {
    pub const fn new(left: CurvePoint, right: CurvePoint) -> Self {
        Self { left, right }
    }

    pub fn identity(
        left_curve: &ShortWeierstrassCurve,
        right_curve: &ShortWeierstrassCurve,
    ) -> Self {
        Self {
            left: left_curve.identity(),
            right: right_curve.identity(),
        }
    }

    pub fn is_identity(
        &self,
        left_curve: &ShortWeierstrassCurve,
        right_curve: &ShortWeierstrassCurve,
    ) -> bool {
        *self == Self::identity(left_curve, right_curve)
    }

    pub fn add(
        &self,
        rhs: &Self,
        left_curve: &ShortWeierstrassCurve,
        right_curve: &ShortWeierstrassCurve,
    ) -> Result<Self> {
        Ok(Self {
            left: left_curve
                .add(&self.left, &rhs.left)
                .map_err(|_| KaniError::InvalidActualWitness)?,
            right: right_curve
                .add(&self.right, &rhs.right)
                .map_err(|_| KaniError::InvalidActualWitness)?,
        })
    }

    pub fn negate(
        &self,
        left_curve: &ShortWeierstrassCurve,
        right_curve: &ShortWeierstrassCurve,
    ) -> Result<Self> {
        Ok(Self {
            left: left_curve
                .negate(&self.left)
                .map_err(|_| KaniError::InvalidActualWitness)?,
            right: right_curve
                .negate(&self.right)
                .map_err(|_| KaniError::InvalidActualWitness)?,
        })
    }

    pub fn scalar_mul_u64(
        &self,
        scalar: u64,
        left_curve: &ShortWeierstrassCurve,
        right_curve: &ShortWeierstrassCurve,
    ) -> Result<Self> {
        Ok(Self {
            left: left_curve
                .scalar_mul_u64(&self.left, scalar)
                .map_err(|_| KaniError::InvalidActualWitness)?,
            right: right_curve
                .scalar_mul_u64(&self.right, scalar)
                .map_err(|_| KaniError::InvalidActualWitness)?,
        })
    }

    pub fn validate_on(
        &self,
        left_curve: &ShortWeierstrassCurve,
        right_curve: &ShortWeierstrassCurve,
    ) -> Result<()> {
        left_curve
            .validate_point(&self.left)
            .map_err(|_| KaniError::InvalidActualWitness)?;
        right_curve
            .validate_point(&self.right)
            .map_err(|_| KaniError::InvalidActualWitness)?;
        Ok(())
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:product-point:v1");
        update_point_hash(&mut hasher, &self.left);
        update_point_hash(&mut hasher, &self.right);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActualProductKernel {
    pub p: ProductPoint,
    pub q: ProductPoint,
}

impl ActualProductKernel {
    pub fn validate(&self, isogeny: &ActualProductIsogeny) -> Result<()> {
        isogeny
            .left
            .source
            .validate_point(&self.p.left)
            .map_err(|_| KaniError::InvalidActualWitness)?;
        isogeny
            .right
            .source
            .validate_point(&self.p.right)
            .map_err(|_| KaniError::InvalidActualWitness)?;
        isogeny
            .left
            .source
            .validate_point(&self.q.left)
            .map_err(|_| KaniError::InvalidActualWitness)?;
        isogeny
            .right
            .source
            .validate_point(&self.q.right)
            .map_err(|_| KaniError::InvalidActualWitness)?;

        let source_identity = isogeny.source_identity();
        if self.p == self.q
            || self
                .p
                .is_identity(&isogeny.left.source, &isogeny.right.source)
            || self
                .q
                .is_identity(&isogeny.left.source, &isogeny.right.source)
        {
            return Err(KaniError::InvalidActualWitness);
        }

        let p_plus_q = self
            .p
            .add(&self.q, &isogeny.left.source, &isogeny.right.source)?;
        if p_plus_q == self.p || p_plus_q == self.q || p_plus_q == source_identity {
            return Err(KaniError::InvalidActualWitness);
        }

        let p_minus_q = self.p.add(
            &self.q.negate(&isogeny.left.source, &isogeny.right.source)?,
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        if p_minus_q == source_identity {
            return Err(KaniError::InvalidActualWitness);
        }

        Ok(())
    }

    pub fn subgroup_commitment(&self, isogeny: &ActualProductIsogeny) -> Result<[u8; 32]> {
        self.validate(isogeny)?;
        let p_plus_q = self
            .p
            .add(&self.q, &isogeny.left.source, &isogeny.right.source)?;
        let p_minus_q = self.p.add(
            &self.q.negate(&isogeny.left.source, &isogeny.right.source)?,
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:kernel-subgroup:v1");
        hasher.update(self.p.commitment());
        hasher.update(self.q.commitment());
        hasher.update(p_plus_q.commitment());
        hasher.update(p_minus_q.commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }

    pub fn left_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:left-kernel:v1");
        update_point_hash(&mut hasher, &self.p.left);
        update_point_hash(&mut hasher, &self.q.left);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn right_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:right-kernel:v1");
        update_point_hash(&mut hasher, &self.p.right);
        update_point_hash(&mut hasher, &self.q.right);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualProductIsogeny {
    pub left: ActualIsogenyChain,
    pub right: ActualIsogenyChain,
}

impl ActualProductIsogeny {
    pub fn validate(&self) -> Result<()> {
        self.left.validate()?;
        self.right.validate()?;
        Ok(())
    }

    pub fn source_identity(&self) -> ProductPoint {
        ProductPoint::identity(&self.left.source, &self.right.source)
    }

    pub fn target_identity(&self) -> ProductPoint {
        ProductPoint::identity(&self.left.target, &self.right.target)
    }

    pub fn source_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:product-source:v1");
        update_curve_hash(&mut hasher, &self.left.source);
        update_curve_hash(&mut hasher, &self.right.source);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn target_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:product-target:v1");
        update_curve_hash(&mut hasher, &self.left.target);
        update_curve_hash(&mut hasher, &self.right.target);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:product-isogeny:v1");
        hasher.update(self.source_commitment());
        hasher.update(self.target_commitment());
        hasher.update(self.left.commitment());
        hasher.update(self.right.commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn map_point(&self, point: &ProductPoint) -> Result<ProductPoint> {
        Ok(ProductPoint {
            left: self.left.map_point(&point.left)?,
            right: self.right.map_point(&point.right)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualProductIsogenyWitnessData {
    pub isogeny: ActualProductIsogeny,
    pub kernel: ActualProductKernel,
    pub samples: Vec<ProductPoint>,
    pub images: Vec<ProductPoint>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StructuredQuotientBackend;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualQuotientProfile {
    pub target_identity: ProductPoint,
    pub axis_probes: [ProductPoint; 2],
    pub axis_probe_images: [ProductPoint; 2],
    pub axis_probe_sum_image: ProductPoint,
    pub axis_probe_diff_image: ProductPoint,
    pub axis_probe_double_images: [ProductPoint; 2],
    pub axis_probe_triple_images: Box<[ProductPoint; 2]>,
    pub generators: [ProductPoint; 2],
    pub generator_images: [ProductPoint; 2],
    pub generator_sum_image: ProductPoint,
    pub generator_diff_image: ProductPoint,
    pub generator_double_images: [ProductPoint; 2],
    pub generator_triple_images: Box<[ProductPoint; 2]>,
    pub samples: Vec<ProductPoint>,
    pub images: Vec<ProductPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalByKaniActualInput {
    pub generators: [ProductPoint; 2],
    pub axis_probes: [ProductPoint; 2],
    pub samples: Vec<ProductPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalByKaniActualOutput {
    pub generator_images: [ProductPoint; 2],
    pub generator_sum_image: ProductPoint,
    pub generator_diff_image: ProductPoint,
    pub generator_double_images: [ProductPoint; 2],
    pub generator_triple_images: Box<[ProductPoint; 2]>,
    pub axis_probe_images: [ProductPoint; 2],
    pub axis_probe_sum_image: ProductPoint,
    pub axis_probe_diff_image: ProductPoint,
    pub axis_probe_double_images: [ProductPoint; 2],
    pub axis_probe_triple_images: Box<[ProductPoint; 2]>,
    pub images: Vec<ProductPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThetaProductIsogenyInput {
    pub generators: [ProductPoint; 2],
    pub axis_probes: [ProductPoint; 2],
    pub samples: Vec<ProductPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThetaProductIsogenyOutput {
    pub generator_images: [ProductPoint; 2],
    pub generator_sum_image: ProductPoint,
    pub generator_diff_image: ProductPoint,
    pub generator_double_images: [ProductPoint; 2],
    pub generator_triple_images: Box<[ProductPoint; 2]>,
    pub axis_probe_images: [ProductPoint; 2],
    pub axis_probe_sum_image: ProductPoint,
    pub axis_probe_diff_image: ProductPoint,
    pub axis_probe_double_images: [ProductPoint; 2],
    pub axis_probe_triple_images: Box<[ProductPoint; 2]>,
    pub images: Vec<ProductPoint>,
    pub theta_data: Option<ThetaQuotientData>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThetaQuotientData {
    pub codomain: [Proj1; 2],
    pub generator_images_xonly: [ThetaCouplePoint; 2],
    pub axis_probe_images_xonly: [ThetaCouplePoint; 2],
    pub sample_images_xonly: Vec<ThetaCouplePoint>,
}

impl ThetaQuotientData {
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:theta-quotient:v1");
        for codomain in &self.codomain {
            update_proj1_hash(&mut hasher, codomain);
        }
        for point in &self.generator_images_xonly {
            update_theta_couple_hash(&mut hasher, point);
        }
        for point in &self.axis_probe_images_xonly {
            update_theta_couple_hash(&mut hasher, point);
        }
        hasher.update((self.sample_images_xonly.len() as u32).to_be_bytes());
        for point in &self.sample_images_xonly {
            update_theta_couple_hash(&mut hasher, point);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

impl ActualQuotientProfile {
    pub fn from_witness(witness: &ActualProductIsogenyWitnessData) -> Result<Self> {
        if witness.samples.len() < 2 || witness.images.len() < 2 {
            return Err(KaniError::InvalidActualWitness);
        }
        let generators = [witness.samples[0], witness.samples[1]];
        let (axis_probes, _) = derive_axis_probes(&witness.isogeny, &witness.kernel)?;
        let evaluation = StructuredQuotientBackend::eval_theta_quotient(
            &witness.isogeny,
            &witness.kernel,
            &ThetaProductIsogenyInput {
                generators,
                axis_probes,
                samples: witness.samples.clone(),
            },
        )?;
        if evaluation.images != witness.images {
            return Err(KaniError::InvalidActualWitness);
        }
        let profile = Self {
            target_identity: witness.isogeny.target_identity(),
            axis_probes,
            axis_probe_images: evaluation.axis_probe_images,
            axis_probe_sum_image: evaluation.axis_probe_sum_image,
            axis_probe_diff_image: evaluation.axis_probe_diff_image,
            axis_probe_double_images: evaluation.axis_probe_double_images,
            axis_probe_triple_images: evaluation.axis_probe_triple_images,
            generators,
            generator_images: evaluation.generator_images,
            generator_sum_image: evaluation.generator_sum_image,
            generator_diff_image: evaluation.generator_diff_image,
            generator_double_images: evaluation.generator_double_images,
            generator_triple_images: evaluation.generator_triple_images,
            samples: witness.samples.clone(),
            images: witness.images.clone(),
        };
        profile.validate(&witness.isogeny, &witness.kernel)?;
        Ok(profile)
    }

    pub fn validate(
        &self,
        isogeny: &ActualProductIsogeny,
        kernel: &ActualProductKernel,
    ) -> Result<()> {
        self.target_identity
            .validate_on(&isogeny.left.target, &isogeny.right.target)?;
        if self.target_identity != isogeny.target_identity() {
            return Err(KaniError::InvalidActualWitness);
        }
        if self.samples.is_empty() || self.samples.len() != self.images.len() {
            return Err(KaniError::InvalidActualWitness);
        }
        for (probe, image) in self.axis_probes.iter().zip(self.axis_probe_images.iter()) {
            probe.validate_on(&isogeny.left.source, &isogeny.right.source)?;
            image.validate_on(&isogeny.left.target, &isogeny.right.target)?;
            let left_identity = probe.left == isogeny.left.source.identity();
            let right_identity = probe.right == isogeny.right.source.identity();
            if (left_identity && right_identity) || (!left_identity && !right_identity) {
                return Err(KaniError::InvalidActualWitness);
            }
            let mapped = isogeny.map_point(probe)?;
            if mapped == self.target_identity || mapped != *image {
                return Err(KaniError::InvalidActualWitness);
            }
        }
        if self.axis_probes[0] == self.axis_probes[1] {
            return Err(KaniError::InvalidActualWitness);
        }
        self.axis_probe_sum_image
            .validate_on(&isogeny.left.target, &isogeny.right.target)?;
        self.axis_probe_diff_image
            .validate_on(&isogeny.left.target, &isogeny.right.target)?;
        let axis_probe_sum = self.axis_probes[0].add(
            &self.axis_probes[1],
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let axis_probe_diff = self.axis_probes[0].add(
            &self.axis_probes[1].negate(&isogeny.left.source, &isogeny.right.source)?,
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let mapped_axis_sum = isogeny.map_point(&axis_probe_sum)?;
        let mapped_axis_diff = isogeny.map_point(&axis_probe_diff)?;
        if mapped_axis_sum != self.axis_probe_sum_image {
            return Err(KaniError::InvalidActualWitness);
        }
        if mapped_axis_diff != self.axis_probe_diff_image {
            return Err(KaniError::InvalidActualWitness);
        }
        let target_axis_sum = self.axis_probe_images[0].add(
            &self.axis_probe_images[1],
            &isogeny.left.target,
            &isogeny.right.target,
        )?;
        if target_axis_sum != self.axis_probe_sum_image {
            return Err(KaniError::InvalidActualWitness);
        }
        let target_axis_diff = self.axis_probe_images[0].add(
            &self.axis_probe_images[1].negate(&isogeny.left.target, &isogeny.right.target)?,
            &isogeny.left.target,
            &isogeny.right.target,
        )?;
        if target_axis_diff != self.axis_probe_diff_image {
            return Err(KaniError::InvalidActualWitness);
        }
        for index in 0..self.axis_probes.len() {
            self.axis_probe_double_images[index]
                .validate_on(&isogeny.left.target, &isogeny.right.target)?;
            self.axis_probe_triple_images[index]
                .validate_on(&isogeny.left.target, &isogeny.right.target)?;
            let source_double = self.axis_probes[index].add(
                &self.axis_probes[index],
                &isogeny.left.source,
                &isogeny.right.source,
            )?;
            let mapped_double = isogeny.map_point(&source_double)?;
            if mapped_double != self.axis_probe_double_images[index] {
                return Err(KaniError::InvalidActualWitness);
            }
            let target_double = self.axis_probe_images[index].add(
                &self.axis_probe_images[index],
                &isogeny.left.target,
                &isogeny.right.target,
            )?;
            if target_double != self.axis_probe_double_images[index] {
                return Err(KaniError::InvalidActualWitness);
            }
            let source_triple = source_double.add(
                &self.axis_probes[index],
                &isogeny.left.source,
                &isogeny.right.source,
            )?;
            let mapped_triple = isogeny.map_point(&source_triple)?;
            if mapped_triple != self.axis_probe_triple_images[index] {
                return Err(KaniError::InvalidActualWitness);
            }
            let target_triple = target_double.add(
                &self.axis_probe_images[index],
                &isogeny.left.target,
                &isogeny.right.target,
            )?;
            if target_triple != self.axis_probe_triple_images[index] {
                return Err(KaniError::InvalidActualWitness);
            }
        }
        for (generator, image) in self.generators.iter().zip(self.generator_images.iter()) {
            generator.validate_on(&isogeny.left.source, &isogeny.right.source)?;
            image.validate_on(&isogeny.left.target, &isogeny.right.target)?;
            let mapped = isogeny.map_point(generator)?;
            if mapped == self.target_identity || mapped != *image {
                return Err(KaniError::InvalidActualWitness);
            }
        }
        if self.generators[0] == self.generators[1]
            || self.generator_images[0] == self.generator_images[1]
        {
            return Err(KaniError::InvalidActualWitness);
        }
        if sample_orbit(isogeny, kernel, &self.generators[0])?.contains(&self.generators[1]) {
            return Err(KaniError::InvalidActualWitness);
        }
        self.generator_sum_image
            .validate_on(&isogeny.left.target, &isogeny.right.target)?;
        let generator_sum = self.generators[0].add(
            &self.generators[1],
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let generator_diff = self.generators[0].add(
            &self.generators[1].negate(&isogeny.left.source, &isogeny.right.source)?,
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let mapped_sum = isogeny.map_point(&generator_sum)?;
        let mapped_diff = isogeny.map_point(&generator_diff)?;
        if mapped_sum != self.generator_sum_image
            || mapped_sum == self.target_identity
            || mapped_sum == self.generator_images[0]
            || mapped_sum == self.generator_images[1]
        {
            return Err(KaniError::InvalidActualWitness);
        }
        self.generator_diff_image
            .validate_on(&isogeny.left.target, &isogeny.right.target)?;
        if mapped_diff != self.generator_diff_image {
            return Err(KaniError::InvalidActualWitness);
        }
        let target_sum = self.generator_images[0].add(
            &self.generator_images[1],
            &isogeny.left.target,
            &isogeny.right.target,
        )?;
        if target_sum != self.generator_sum_image {
            return Err(KaniError::InvalidActualWitness);
        }
        let target_diff = self.generator_images[0].add(
            &self.generator_images[1].negate(&isogeny.left.target, &isogeny.right.target)?,
            &isogeny.left.target,
            &isogeny.right.target,
        )?;
        if target_diff != self.generator_diff_image {
            return Err(KaniError::InvalidActualWitness);
        }
        for index in 0..self.generators.len() {
            self.generator_double_images[index]
                .validate_on(&isogeny.left.target, &isogeny.right.target)?;
            self.generator_triple_images[index]
                .validate_on(&isogeny.left.target, &isogeny.right.target)?;
            let source_double = self.generators[index].add(
                &self.generators[index],
                &isogeny.left.source,
                &isogeny.right.source,
            )?;
            let mapped_double = isogeny.map_point(&source_double)?;
            if mapped_double != self.generator_double_images[index] {
                return Err(KaniError::InvalidActualWitness);
            }
            let target_double = self.generator_images[index].add(
                &self.generator_images[index],
                &isogeny.left.target,
                &isogeny.right.target,
            )?;
            if target_double != self.generator_double_images[index] {
                return Err(KaniError::InvalidActualWitness);
            }
            let source_triple = source_double.add(
                &self.generators[index],
                &isogeny.left.source,
                &isogeny.right.source,
            )?;
            let mapped_triple = isogeny.map_point(&source_triple)?;
            if mapped_triple != self.generator_triple_images[index] {
                return Err(KaniError::InvalidActualWitness);
            }
            let target_triple = target_double.add(
                &self.generator_images[index],
                &isogeny.left.target,
                &isogeny.right.target,
            )?;
            if target_triple != self.generator_triple_images[index] {
                return Err(KaniError::InvalidActualWitness);
            }
        }
        for (sample, image) in self.samples.iter().zip(self.images.iter()) {
            sample.validate_on(&isogeny.left.source, &isogeny.right.source)?;
            image.validate_on(&isogeny.left.target, &isogeny.right.target)?;
            let mapped = isogeny.map_point(sample)?;
            if mapped == self.target_identity || mapped != *image {
                return Err(KaniError::InvalidActualWitness);
            }
            let orbit = sample_orbit(isogeny, kernel, sample)?;
            let mut distinct_points = 0usize;
            for translated in orbit {
                if translated != *sample {
                    distinct_points += 1;
                }
                if isogeny.map_point(&translated)? != *image {
                    return Err(KaniError::InvalidActualWitness);
                }
            }
            if distinct_points == 0 {
                return Err(KaniError::InvalidActualWitness);
            }
        }
        Ok(())
    }

    pub fn sample_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:samples:v1");
        for sample in &self.samples {
            hasher.update(sample.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn image_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:sample-images:v1");
        for image in &self.images {
            hasher.update(image.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn generator_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:quotient-generators:v1");
        for generator in &self.generators {
            hasher.update(generator.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn axis_probe_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:quotient-axis-probes:v1");
        for probe in &self.axis_probes {
            hasher.update(probe.commitment());
        }
        for image in &self.axis_probe_images {
            hasher.update(image.commitment());
        }
        hasher.update(self.axis_probe_sum_image.commitment());
        hasher.update(self.axis_probe_diff_image.commitment());
        for image in &self.axis_probe_double_images {
            hasher.update(image.commitment());
        }
        for image in self.axis_probe_triple_images.iter() {
            hasher.update(image.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn generator_image_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:quotient-generator-images:v1");
        for image in &self.generator_images {
            hasher.update(image.commitment());
        }
        hasher.update(self.generator_sum_image.commitment());
        hasher.update(self.generator_diff_image.commitment());
        for image in &self.generator_double_images {
            hasher.update(image.commitment());
        }
        for image in self.generator_triple_images.iter() {
            hasher.update(image.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn probe_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:quotient-probes:v1");
        hasher.update(self.target_identity.commitment());
        hasher.update(self.axis_probe_commitment());
        hasher.update(self.generator_commitment());
        hasher.update(self.generator_image_commitment());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    pub fn coset_commitment(
        &self,
        isogeny: &ActualProductIsogeny,
        kernel: &ActualProductKernel,
    ) -> Result<[u8; 32]> {
        self.validate(isogeny, kernel)?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:sample-cosets:v1");
        for sample in &self.samples {
            for point in sample_orbit(isogeny, kernel, sample)? {
                hasher.update(point.commitment());
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }

    pub fn commitment(
        &self,
        isogeny: &ActualProductIsogeny,
        kernel: &ActualProductKernel,
    ) -> Result<[u8; 32]> {
        self.validate(isogeny, kernel)?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:kani:quotient-profile:v1");
        hasher.update(isogeny.target_commitment());
        hasher.update(self.target_identity.commitment());
        hasher.update(self.axis_probe_commitment());
        hasher.update(self.generator_commitment());
        hasher.update(self.generator_image_commitment());
        hasher.update(self.sample_commitment());
        hasher.update(self.image_commitment());
        hasher.update(self.coset_commitment(isogeny, kernel)?);
        hasher.update((self.images.len() as u32).to_be_bytes());
        for image in &self.images {
            hasher.update(image.commitment());
        }
        if let Some(theta_commitment) = self.theta_commitment(isogeny, kernel)? {
            hasher.update([1]);
            hasher.update(theta_commitment);
        } else {
            hasher.update([0]);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }

    pub fn theta_commitment(
        &self,
        isogeny: &ActualProductIsogeny,
        kernel: &ActualProductKernel,
    ) -> Result<Option<[u8; 32]>> {
        let theta = StructuredQuotientBackend::eval_theta_quotient(
            isogeny,
            kernel,
            &ThetaProductIsogenyInput {
                generators: self.generators,
                axis_probes: self.axis_probes,
                samples: self.samples.clone(),
            },
        )?;
        if let Some(theta_data) = theta.theta_data.as_ref() {
            if !theta_data_matches_profile(theta_data, self) {
                return Err(KaniError::InvalidActualWitness);
            }
            Ok(Some(theta_data.commitment()))
        } else {
            Ok(None)
        }
    }
}

impl ActualProductIsogenyWitnessData {
    pub fn from_isogeny(isogeny: ActualProductIsogeny) -> Result<Self> {
        StructuredQuotientBackend::witness_from_isogeny(isogeny)
    }

    pub fn validate(&self) -> Result<()> {
        StructuredQuotientBackend::validate_witness(self)
    }

    pub fn statement(&self) -> Result<ProductIsogenyStatement> {
        StructuredQuotientBackend::statement(self)
    }

    pub fn construct_witness(&self, challenge: &[u8]) -> Result<ProductIsogenyWitness> {
        Ok(KaniEngine::construct_witness(self.statement()?, challenge))
    }

    pub fn construct_witness_for_statement(
        &self,
        statement: ProductIsogenyStatement,
        challenge: &[u8],
    ) -> Result<ProductIsogenyWitness> {
        Ok(ProductIsogenyWitness {
            statement,
            transcript: KaniEngine::construct_actual(statement, self, challenge)?,
        })
    }

    pub fn sample_points(&self) -> &[ProductPoint] {
        &self.samples
    }

    pub fn sample_images(&self) -> &[ProductPoint] {
        &self.images
    }

    pub fn quotient_profile(&self) -> Result<ActualQuotientProfile> {
        StructuredQuotientBackend::profile_from_witness(self)
    }

    pub fn sample_commitment(&self) -> [u8; 32] {
        self.quotient_profile()
            .expect("validated witness yields a quotient profile")
            .sample_commitment()
    }

    pub fn image_commitment(&self) -> [u8; 32] {
        self.quotient_profile()
            .expect("validated witness yields a quotient profile")
            .image_commitment()
    }

    pub fn coset_commitment(&self) -> Result<[u8; 32]> {
        self.quotient_profile()?
            .coset_commitment(&self.isogeny, &self.kernel)
    }

    pub fn quotient_profile_commitment(&self) -> Result<[u8; 32]> {
        self.quotient_profile()?
            .commitment(&self.isogeny, &self.kernel)
    }

    fn sample_orbit(&self, sample: &ProductPoint) -> Result<[ProductPoint; 4]> {
        sample_orbit(&self.isogeny, &self.kernel, sample)
    }
}

impl StructuredQuotientBackend {
    pub fn witness_from_isogeny(
        isogeny: ActualProductIsogeny,
    ) -> Result<ActualProductIsogenyWitnessData> {
        isogeny.validate()?;
        let left_generator = isogeny
            .left
            .steps
            .first()
            .map(|step| step.kernel_generator)
            .ok_or(KaniError::InvalidActualWitness)?;
        let right_generator = isogeny
            .right
            .steps
            .first()
            .map(|step| step.kernel_generator)
            .ok_or(KaniError::InvalidActualWitness)?;

        let kernel = derive_kernel_basis(&isogeny, left_generator, right_generator)?;
        let (samples, images) = Self::derive_samples_and_images(&isogeny, &kernel)?;
        let data = ActualProductIsogenyWitnessData {
            isogeny,
            kernel,
            samples,
            images,
        };
        Self::validate_witness(&data)?;
        Ok(data)
    }

    pub fn validate_witness(witness: &ActualProductIsogenyWitnessData) -> Result<()> {
        witness.isogeny.validate()?;
        witness.kernel.validate(&witness.isogeny)?;
        let identity = witness.isogeny.target_identity();
        if witness.isogeny.map_point(&witness.kernel.p)? != identity
            || witness.isogeny.map_point(&witness.kernel.q)? != identity
        {
            return Err(KaniError::InvalidActualWitness);
        }
        let kernel_sum = witness.kernel.p.add(
            &witness.kernel.q,
            &witness.isogeny.left.source,
            &witness.isogeny.right.source,
        )?;
        if witness.isogeny.map_point(&kernel_sum)? != identity {
            return Err(KaniError::InvalidActualWitness);
        }
        Self::profile_from_witness(witness)?.validate(&witness.isogeny, &witness.kernel)?;
        Ok(())
    }

    pub fn statement(witness: &ActualProductIsogenyWitnessData) -> Result<ProductIsogenyStatement> {
        Self::validate_witness(witness)?;
        Ok(KaniEngine::statement(
            witness.isogeny.source_commitment(),
            witness.kernel.left_commitment(),
            witness.isogeny.target_commitment(),
            witness.kernel.right_commitment(),
            [0u8; 32],
            Self::profile_from_witness(witness)?.probe_commitment(),
            witness.quotient_profile_commitment()?,
            witness.isogeny.commitment(),
        ))
    }

    fn derive_samples_and_images(
        isogeny: &ActualProductIsogeny,
        kernel: &ActualProductKernel,
    ) -> Result<(Vec<ProductPoint>, Vec<ProductPoint>)> {
        let mut samples = Vec::new();
        let left_identity = isogeny.left.source.identity();
        let right_identity = isogeny.right.source.identity();
        let target_identity = isogeny.target_identity();

        for point in enumerate_small_curve_points(&isogeny.left.source)? {
            if point.is_infinity() || point == kernel.p.left {
                continue;
            }
            let candidate = ProductPoint::new(point, right_identity);
            if isogeny.map_point(&candidate)? != target_identity {
                samples.push(candidate);
                break;
            }
        }

        for point in enumerate_small_curve_points(&isogeny.right.source)? {
            if point.is_infinity() || point == kernel.q.right {
                continue;
            }
            let candidate = ProductPoint::new(left_identity, point);
            if isogeny.map_point(&candidate)? != target_identity
                && !samples.iter().any(|existing| {
                    sample_orbit(isogeny, kernel, existing)
                        .map(|orbit| orbit.contains(&candidate))
                        .unwrap_or(false)
                })
            {
                samples.push(candidate);
                break;
            }
        }

        if samples.len() < 2 {
            let left_points = enumerate_small_curve_points(&isogeny.left.source)?;
            let right_points = enumerate_small_curve_points(&isogeny.right.source)?;
            'outer: for left in left_points {
                if left.is_infinity() {
                    continue;
                }
                for right in &right_points {
                    if right.is_infinity() {
                        continue;
                    }
                    let candidate = ProductPoint::new(left, *right);
                    let image = isogeny.map_point(&candidate)?;
                    if image == target_identity {
                        continue;
                    }
                    if samples.iter().any(|existing| {
                        sample_orbit(isogeny, kernel, existing)
                            .map(|orbit| orbit.contains(&candidate))
                            .unwrap_or(false)
                    }) {
                        continue;
                    }
                    samples.push(candidate);
                    if samples.len() >= 2 {
                        break 'outer;
                    }
                }
            }
        }

        if samples.len() < 2 {
            return Err(KaniError::InvalidActualWitness);
        }
        let mut images = Vec::with_capacity(samples.len());
        for sample in &samples {
            images.push(isogeny.map_point(sample)?);
        }
        Ok((samples, images))
    }

    pub fn profile_from_witness(
        witness: &ActualProductIsogenyWitnessData,
    ) -> Result<ActualQuotientProfile> {
        ActualQuotientProfile::from_witness(witness)
    }

    pub fn eval_theta_quotient(
        isogeny: &ActualProductIsogeny,
        kernel: &ActualProductKernel,
        input: &ThetaProductIsogenyInput,
    ) -> Result<ThetaProductIsogenyOutput> {
        let evaluation = KaniEngine::eval_by_kani_actual(
            isogeny,
            &EvalByKaniActualInput {
                generators: input.generators,
                axis_probes: input.axis_probes,
                samples: input.samples.clone(),
            },
        )?;
        let mut output = ThetaProductIsogenyOutput {
            generator_images: evaluation.generator_images,
            generator_sum_image: evaluation.generator_sum_image,
            generator_diff_image: evaluation.generator_diff_image,
            generator_double_images: evaluation.generator_double_images,
            generator_triple_images: evaluation.generator_triple_images,
            axis_probe_images: evaluation.axis_probe_images,
            axis_probe_sum_image: evaluation.axis_probe_sum_image,
            axis_probe_diff_image: evaluation.axis_probe_diff_image,
            axis_probe_double_images: evaluation.axis_probe_double_images,
            axis_probe_triple_images: evaluation.axis_probe_triple_images,
            images: evaluation.images,
            theta_data: None,
        };
        if let Some(theta_data) = Self::try_eval_theta_quotient_data(isogeny, kernel, input)? {
            if !theta_data_matches_affine_output(&theta_data, &output) {
                return Err(KaniError::InvalidActualWitness);
            }
            output.theta_data = Some(theta_data);
        }
        Ok(output)
    }

    fn try_eval_theta_quotient_data(
        isogeny: &ActualProductIsogeny,
        kernel: &ActualProductKernel,
        input: &ThetaProductIsogenyInput,
    ) -> Result<Option<ThetaQuotientData>> {
        if isogeny.left.steps.is_empty()
            || isogeny.left.steps.len() != isogeny.right.steps.len()
            || !isogeny.left.steps.iter().all(|step| step.degree == 2)
            || !isogeny.right.steps.iter().all(|step| step.degree == 2)
        {
            return Ok(None);
        }

        let left = match recover_montgomery_isomorphism(&isogeny.left.source) {
            Some(value) => value,
            None => return Ok(None),
        };
        let right = match recover_montgomery_isomorphism(&isogeny.right.source) {
            Some(value) => value,
            None => return Ok(None),
        };

        let p = match product_point_to_theta_couple(&kernel.p, &left, &right) {
            Some(value) => value,
            None => return Ok(None),
        };
        let q = match product_point_to_theta_couple(&kernel.q, &left, &right) {
            Some(value) => value,
            None => return Ok(None),
        };

        let p_left = left.to_montgomery_point(&kernel.p.left).ok();
        let q_left = left.to_montgomery_point(&kernel.q.left).ok();
        let p_right = right.to_montgomery_point(&kernel.p.right).ok();
        let q_right = right.to_montgomery_point(&kernel.q.right).ok();
        let diff = match (p_left, q_left, p_right, q_right) {
            (Some(pl), Some(ql), Some(pr), Some(qr))
                if !pl.is_infinity()
                    && !ql.is_infinity()
                    && !pr.is_infinity()
                    && !qr.is_infinity() =>
            {
                ThetaCouplePoint {
                    p1: x_of_difference(left.montgomery_curve(), &pl, &ql)
                        .ok()
                        .unwrap_or(Proj1::identity(left.montgomery_curve().modulus())),
                    p2: x_of_difference(right.montgomery_curve(), &pr, &qr)
                        .ok()
                        .unwrap_or(Proj1::identity(right.montgomery_curve().modulus())),
                }
            }
            _ => return Ok(None),
        };

        let mut image_points = Vec::with_capacity(4 + input.samples.len());
        image_points.push(
            match product_point_to_theta_couple(&input.generators[0], &left, &right) {
                Some(value) => value,
                None => return Ok(None),
            },
        );
        image_points.push(
            match product_point_to_theta_couple(&input.generators[1], &left, &right) {
                Some(value) => value,
                None => return Ok(None),
            },
        );
        image_points.push(
            match product_point_to_theta_couple(&input.axis_probes[0], &left, &right) {
                Some(value) => value,
                None => return Ok(None),
            },
        );
        image_points.push(
            match product_point_to_theta_couple(&input.axis_probes[1], &left, &right) {
                Some(value) => value,
                None => return Ok(None),
            },
        );
        for sample in &input.samples {
            image_points.push(match product_point_to_theta_couple(sample, &left, &right) {
                Some(value) => value,
                None => return Ok(None),
            });
        }

        let (codomain, mapped) = match theta_product_isogeny_sqrt_no_strategy(
            left.montgomery_curve(),
            right.montgomery_curve(),
            p,
            q,
            diff,
            image_points,
            isogeny.left.steps.len(),
        ) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };

        if mapped.len() < 6 {
            return Ok(None);
        }
        let kernel_base = mapped.len().saturating_sub(2);

        Ok(Some(ThetaQuotientData {
            codomain,
            generator_images_xonly: [mapped[0], mapped[1]],
            axis_probe_images_xonly: [mapped[2], mapped[3]],
            sample_images_xonly: mapped[4..kernel_base].to_vec(),
        }))
    }
}

fn theta_data_matches_affine_output(
    theta_data: &ThetaQuotientData,
    output: &ThetaProductIsogenyOutput,
) -> bool {
    theta_couple_matches_product_point(
        &theta_data.generator_images_xonly[0],
        &output.generator_images[0],
    ) && theta_couple_matches_product_point(
        &theta_data.generator_images_xonly[1],
        &output.generator_images[1],
    ) && theta_couple_matches_product_point(
        &theta_data.axis_probe_images_xonly[0],
        &output.axis_probe_images[0],
    ) && theta_couple_matches_product_point(
        &theta_data.axis_probe_images_xonly[1],
        &output.axis_probe_images[1],
    ) && theta_data.sample_images_xonly.len() == output.images.len()
        && theta_data
            .sample_images_xonly
            .iter()
            .zip(output.images.iter())
            .all(|(lhs, rhs)| theta_couple_matches_product_point(lhs, rhs))
}

fn theta_data_matches_profile(
    theta_data: &ThetaQuotientData,
    profile: &ActualQuotientProfile,
) -> bool {
    theta_couple_matches_product_point(
        &theta_data.generator_images_xonly[0],
        &profile.generator_images[0],
    ) && theta_couple_matches_product_point(
        &theta_data.generator_images_xonly[1],
        &profile.generator_images[1],
    ) && theta_couple_matches_product_point(
        &theta_data.axis_probe_images_xonly[0],
        &profile.axis_probe_images[0],
    ) && theta_couple_matches_product_point(
        &theta_data.axis_probe_images_xonly[1],
        &profile.axis_probe_images[1],
    ) && theta_data.sample_images_xonly.len() == profile.images.len()
        && theta_data
            .sample_images_xonly
            .iter()
            .zip(profile.images.iter())
            .all(|(lhs, rhs)| theta_couple_matches_product_point(lhs, rhs))
}

fn theta_couple_matches_product_point(lhs: &ThetaCouplePoint, rhs: &ProductPoint) -> bool {
    proj_matches_curve_point_x(&lhs.p1, &rhs.left)
        && proj_matches_curve_point_x(&lhs.p2, &rhs.right)
}

fn proj_matches_curve_point_x(lhs: &Proj1, rhs: &CurvePoint) -> bool {
    if lhs.is_identity() || rhs.is_infinity() {
        return lhs.is_identity() == rhs.is_infinity();
    }
    match lhs.to_affine_x() {
        Ok(x) => x == rhs.x,
        Err(_) => false,
    }
}

fn recover_montgomery_isomorphism(curve: &ShortWeierstrassCurve) -> Option<MontgomeryIsomorphism> {
    let modulus = curve.modulus();
    let denominator = Fp2::one(modulus).add(&curve.a.double()).ok()?;
    if denominator.is_zero() {
        return None;
    }
    let a_param = Fp2::from_u64(modulus, 9)
        .neg()
        .mul(&curve.b)
        .ok()?
        .mul(&denominator.invert().ok()?)
        .ok()?;
    let montgomery = MontgomeryCurve::new(a_param).ok()?;
    let iso = MontgomeryIsomorphism::new(montgomery).ok()?;
    if iso.weierstrass_curve() == curve {
        Some(iso)
    } else {
        None
    }
}

fn product_point_to_theta_couple(
    point: &ProductPoint,
    left: &MontgomeryIsomorphism,
    right: &MontgomeryIsomorphism,
) -> Option<ThetaCouplePoint> {
    let left_point = left.to_montgomery_point(&point.left).ok()?;
    let right_point = right.to_montgomery_point(&point.right).ok()?;
    Some(ThetaCouplePoint {
        p1: if left_point.is_infinity() {
            Proj1::identity(left.montgomery_curve().modulus())
        } else {
            Proj1::from_point(&left_point).ok()?
        },
        p2: if right_point.is_infinity() {
            Proj1::identity(right.montgomery_curve().modulus())
        } else {
            Proj1::from_point(&right_point).ok()?
        },
    })
}

fn derive_kernel_basis(
    isogeny: &ActualProductIsogeny,
    left_generator: CurvePoint,
    right_generator: CurvePoint,
) -> Result<ActualProductKernel> {
    let axis_p = ProductPoint::new(left_generator, isogeny.right.source.identity());
    let axis_q = ProductPoint::new(isogeny.left.source.identity(), right_generator);
    let fallback = ActualProductKernel {
        p: axis_p,
        q: axis_q,
    };

    let mut best = fallback;
    let mut best_score = kernel_mixed_score(&best, isogeny);
    for matrix in UNIMODULAR_KERNEL_MATRICES {
        let candidate = ActualProductKernel {
            p: combine_kernel_generators(isogeny, &axis_p, &axis_q, matrix[0][0], matrix[0][1])?,
            q: combine_kernel_generators(isogeny, &axis_p, &axis_q, matrix[1][0], matrix[1][1])?,
        };
        if candidate.validate(isogeny).is_err() {
            continue;
        }
        let score = kernel_mixed_score(&candidate, isogeny);
        if score > best_score {
            best = candidate;
            best_score = score;
        }
    }
    Ok(best)
}

const UNIMODULAR_KERNEL_MATRICES: [[[u64; 2]; 2]; 6] = [
    [[1, 1], [1, 0]],
    [[1, 1], [0, 1]],
    [[1, 1], [2, 1]],
    [[1, 2], [1, 1]],
    [[2, 1], [1, 0]],
    [[1, 0], [1, 1]],
];

fn combine_kernel_generators(
    isogeny: &ActualProductIsogeny,
    axis_p: &ProductPoint,
    axis_q: &ProductPoint,
    p_coeff: u64,
    q_coeff: u64,
) -> Result<ProductPoint> {
    let p_term = axis_p.scalar_mul_u64(p_coeff, &isogeny.left.source, &isogeny.right.source)?;
    let q_term = axis_q.scalar_mul_u64(q_coeff, &isogeny.left.source, &isogeny.right.source)?;
    p_term.add(&q_term, &isogeny.left.source, &isogeny.right.source)
}

fn kernel_mixed_score(kernel: &ActualProductKernel, isogeny: &ActualProductIsogeny) -> u8 {
    [
        !kernel.p.left.is_infinity(),
        !kernel.p.right.is_infinity(),
        !kernel.q.left.is_infinity(),
        !kernel.q.right.is_infinity(),
    ]
    .into_iter()
    .map(u8::from)
    .sum::<u8>()
        + u8::from(
            !kernel
                .p
                .is_identity(&isogeny.left.source, &isogeny.right.source),
        )
        + u8::from(
            !kernel
                .q
                .is_identity(&isogeny.left.source, &isogeny.right.source),
        )
}

fn sample_orbit(
    isogeny: &ActualProductIsogeny,
    kernel: &ActualProductKernel,
    sample: &ProductPoint,
) -> Result<[ProductPoint; 4]> {
    let sample_plus_p = sample.add(&kernel.p, &isogeny.left.source, &isogeny.right.source)?;
    let sample_plus_q = sample.add(&kernel.q, &isogeny.left.source, &isogeny.right.source)?;
    let kernel_sum = kernel
        .p
        .add(&kernel.q, &isogeny.left.source, &isogeny.right.source)?;
    let sample_plus_p_plus_q =
        sample.add(&kernel_sum, &isogeny.left.source, &isogeny.right.source)?;
    Ok([*sample, sample_plus_p, sample_plus_q, sample_plus_p_plus_q])
}

fn derive_axis_probes(
    isogeny: &ActualProductIsogeny,
    kernel: &ActualProductKernel,
) -> Result<([ProductPoint; 2], [ProductPoint; 2])> {
    let left_identity = isogeny.left.source.identity();
    let right_identity = isogeny.right.source.identity();
    let target_identity = isogeny.target_identity();
    let mut probes = Vec::with_capacity(2);
    let mut images = Vec::with_capacity(2);
    for point in enumerate_small_curve_points(&isogeny.left.source)? {
        if point.is_infinity() {
            continue;
        }
        let probe = ProductPoint::new(point, right_identity);
        let image = isogeny.map_point(&probe)?;
        if image == target_identity {
            continue;
        }
        if probes.iter().any(|existing| {
            sample_orbit(isogeny, kernel, existing)
                .map(|orbit| orbit.contains(&probe))
                .unwrap_or(false)
        }) {
            continue;
        }
        probes.push(probe);
        images.push(image);
        if probes.len() == 2 {
            break;
        }
    }
    if probes.len() < 2 {
        for point in enumerate_small_curve_points(&isogeny.right.source)? {
            if point.is_infinity() {
                continue;
            }
            let probe = ProductPoint::new(left_identity, point);
            let image = isogeny.map_point(&probe)?;
            if image == target_identity {
                continue;
            }
            if probes.iter().any(|existing| {
                sample_orbit(isogeny, kernel, existing)
                    .map(|orbit| orbit.contains(&probe))
                    .unwrap_or(false)
            }) {
                continue;
            }
            probes.push(probe);
            images.push(image);
            if probes.len() == 2 {
                break;
            }
        }
    }
    if probes.len() != 2 || images.len() != 2 {
        return Err(KaniError::InvalidActualWitness);
    }
    Ok(([probes[0], probes[1]], [images[0], images[1]]))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KaniEngine;

impl KaniEngine {
    pub fn eval_by_kani_actual(
        isogeny: &ActualProductIsogeny,
        input: &EvalByKaniActualInput,
    ) -> Result<EvalByKaniActualOutput> {
        for generator in &input.generators {
            generator.validate_on(&isogeny.left.source, &isogeny.right.source)?;
        }
        for probe in &input.axis_probes {
            probe.validate_on(&isogeny.left.source, &isogeny.right.source)?;
        }
        for sample in &input.samples {
            sample.validate_on(&isogeny.left.source, &isogeny.right.source)?;
        }

        let generator_images = [
            isogeny.map_point(&input.generators[0])?,
            isogeny.map_point(&input.generators[1])?,
        ];
        let generator_sum = input.generators[0].add(
            &input.generators[1],
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let generator_diff = input.generators[0].add(
            &input.generators[1].negate(&isogeny.left.source, &isogeny.right.source)?,
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let generator_sum_image = isogeny.map_point(&generator_sum)?;
        let generator_diff_image = isogeny.map_point(&generator_diff)?;
        let generator_double_images = [
            isogeny.map_point(&input.generators[0].add(
                &input.generators[0],
                &isogeny.left.source,
                &isogeny.right.source,
            )?)?,
            isogeny.map_point(&input.generators[1].add(
                &input.generators[1],
                &isogeny.left.source,
                &isogeny.right.source,
            )?)?,
        ];
        let generator_triple_images = Box::new([
            isogeny.map_point(
                &input.generators[0]
                    .add(
                        &input.generators[0],
                        &isogeny.left.source,
                        &isogeny.right.source,
                    )?
                    .add(
                        &input.generators[0],
                        &isogeny.left.source,
                        &isogeny.right.source,
                    )?,
            )?,
            isogeny.map_point(
                &input.generators[1]
                    .add(
                        &input.generators[1],
                        &isogeny.left.source,
                        &isogeny.right.source,
                    )?
                    .add(
                        &input.generators[1],
                        &isogeny.left.source,
                        &isogeny.right.source,
                    )?,
            )?,
        ]);

        let axis_probe_images = [
            isogeny.map_point(&input.axis_probes[0])?,
            isogeny.map_point(&input.axis_probes[1])?,
        ];
        let axis_probe_sum = input.axis_probes[0].add(
            &input.axis_probes[1],
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let axis_probe_diff = input.axis_probes[0].add(
            &input.axis_probes[1].negate(&isogeny.left.source, &isogeny.right.source)?,
            &isogeny.left.source,
            &isogeny.right.source,
        )?;
        let axis_probe_sum_image = isogeny.map_point(&axis_probe_sum)?;
        let axis_probe_diff_image = isogeny.map_point(&axis_probe_diff)?;
        let axis_probe_double_images = [
            isogeny.map_point(&input.axis_probes[0].add(
                &input.axis_probes[0],
                &isogeny.left.source,
                &isogeny.right.source,
            )?)?,
            isogeny.map_point(&input.axis_probes[1].add(
                &input.axis_probes[1],
                &isogeny.left.source,
                &isogeny.right.source,
            )?)?,
        ];
        let axis_probe_triple_images = Box::new([
            isogeny.map_point(
                &input.axis_probes[0]
                    .add(
                        &input.axis_probes[0],
                        &isogeny.left.source,
                        &isogeny.right.source,
                    )?
                    .add(
                        &input.axis_probes[0],
                        &isogeny.left.source,
                        &isogeny.right.source,
                    )?,
            )?,
            isogeny.map_point(
                &input.axis_probes[1]
                    .add(
                        &input.axis_probes[1],
                        &isogeny.left.source,
                        &isogeny.right.source,
                    )?
                    .add(
                        &input.axis_probes[1],
                        &isogeny.left.source,
                        &isogeny.right.source,
                    )?,
            )?,
        ]);

        let mut images = Vec::with_capacity(input.samples.len());
        for sample in &input.samples {
            images.push(isogeny.map_point(sample)?);
        }

        Ok(EvalByKaniActualOutput {
            generator_images,
            generator_sum_image,
            generator_diff_image,
            generator_double_images,
            generator_triple_images,
            axis_probe_images,
            axis_probe_sum_image,
            axis_probe_diff_image,
            axis_probe_double_images,
            axis_probe_triple_images,
            images,
        })
    }

    pub fn statement(
        verifying_codomain_tag: [u8; 32],
        verifying_basis_commitment: [u8; 32],
        signature_codomain_tag: [u8; 32],
        signature_basis_commitment: [u8; 32],
        decomposition_commitment: [u8; 32],
        probe_commitment: [u8; 32],
        quotient_commitment: [u8; 32],
        witness_commitment: [u8; 32],
    ) -> ProductIsogenyStatement {
        ProductIsogenyStatement {
            verifying_codomain_tag,
            verifying_basis_commitment,
            signature_codomain_tag,
            signature_basis_commitment,
            decomposition_commitment,
            probe_commitment,
            quotient_commitment,
            witness_commitment,
        }
    }

    pub fn construct(
        verifying_codomain_tag: [u8; 32],
        verifying_basis_commitment: [u8; 32],
        signature_codomain_tag: [u8; 32],
        signature_basis_commitment: [u8; 32],
        decomposition_commitment: [u8; 32],
        probe_commitment: [u8; 32],
        quotient_commitment: [u8; 32],
        signature_coefficients_commitment: [u8; 32],
        challenge: &[u8],
    ) -> KaniTranscript {
        KaniTranscript {
            kernel: KaniKernel {
                pairing_commitment: domain_hash(
                    b"AURORA:isogeny:kani:pairing:v1",
                    &verifying_codomain_tag,
                    &verifying_basis_commitment,
                    &signature_codomain_tag,
                    &signature_basis_commitment,
                    &decomposition_commitment,
                    &probe_commitment,
                    &quotient_commitment,
                    &signature_coefficients_commitment,
                    challenge,
                ),
                torsion_commitment: domain_hash(
                    b"AURORA:isogeny:kani:torsion:v1",
                    &verifying_codomain_tag,
                    &verifying_basis_commitment,
                    &signature_codomain_tag,
                    &signature_basis_commitment,
                    &decomposition_commitment,
                    &probe_commitment,
                    &quotient_commitment,
                    &signature_coefficients_commitment,
                    challenge,
                ),
            },
            image: KaniImage {
                left_codomain_tag: domain_hash(
                    b"AURORA:isogeny:kani:image-left:v1",
                    &verifying_codomain_tag,
                    &verifying_basis_commitment,
                    &signature_codomain_tag,
                    &signature_basis_commitment,
                    &decomposition_commitment,
                    &probe_commitment,
                    &quotient_commitment,
                    &signature_coefficients_commitment,
                    challenge,
                ),
                right_codomain_tag: domain_hash(
                    b"AURORA:isogeny:kani:image-right:v1",
                    &signature_codomain_tag,
                    &signature_basis_commitment,
                    &verifying_codomain_tag,
                    &verifying_basis_commitment,
                    &decomposition_commitment,
                    &probe_commitment,
                    &quotient_commitment,
                    &signature_coefficients_commitment,
                    challenge,
                ),
            },
        }
    }

    pub fn construct_witness(
        statement: ProductIsogenyStatement,
        challenge: &[u8],
    ) -> ProductIsogenyWitness {
        ProductIsogenyWitness {
            statement,
            transcript: Self::construct(
                statement.verifying_codomain_tag,
                statement.verifying_basis_commitment,
                statement.signature_codomain_tag,
                statement.signature_basis_commitment,
                statement.decomposition_commitment,
                statement.probe_commitment,
                statement.quotient_commitment,
                statement.witness_commitment,
                challenge,
            ),
        }
    }

    pub fn construct_actual(
        statement: ProductIsogenyStatement,
        witness: &ActualProductIsogenyWitnessData,
        challenge: &[u8],
    ) -> Result<KaniTranscript> {
        witness.validate()?;
        let quotient_profile = witness.quotient_profile()?;
        let quotient_probe_commitment = quotient_profile.probe_commitment();
        let sample_commitment = witness.sample_commitment();
        let image_commitment = witness.image_commitment();
        let coset_commitment = witness.coset_commitment()?;
        let quotient_profile_commitment =
            quotient_profile.commitment(&witness.isogeny, &witness.kernel)?;
        let quotient_generator_commitment = quotient_profile.generator_commitment();
        let quotient_generator_image_commitment = quotient_profile.generator_image_commitment();
        let kernel_subgroup_commitment = witness.kernel.subgroup_commitment(&witness.isogeny)?;
        Ok(KaniTranscript {
            kernel: KaniKernel {
                pairing_commitment: actual_domain_hash(
                    b"AURORA:isogeny:kani:pairing:actual:v1",
                    &statement,
                    &[
                        witness.kernel.left_commitment(),
                        witness.kernel.right_commitment(),
                        witness.isogeny.source_commitment(),
                        kernel_subgroup_commitment,
                        quotient_probe_commitment,
                        coset_commitment,
                        quotient_generator_commitment,
                        sample_commitment,
                        quotient_profile_commitment,
                    ],
                    challenge,
                ),
                torsion_commitment: actual_domain_hash(
                    b"AURORA:isogeny:kani:torsion:actual:v1",
                    &statement,
                    &[
                        witness.kernel.p.commitment(),
                        witness.kernel.q.commitment(),
                        kernel_subgroup_commitment,
                        quotient_probe_commitment,
                        coset_commitment,
                        quotient_generator_image_commitment,
                        witness.isogeny.commitment(),
                        image_commitment,
                        quotient_profile_commitment,
                    ],
                    challenge,
                ),
            },
            image: KaniImage {
                left_codomain_tag: actual_domain_hash(
                    b"AURORA:isogeny:kani:image-left:actual:v1",
                    &statement,
                    &[
                        curve_commitment(&witness.isogeny.left.target),
                        witness.isogeny.left.commitment(),
                        witness.isogeny.target_commitment(),
                        quotient_probe_commitment,
                        quotient_generator_commitment,
                        image_commitment,
                        quotient_profile_commitment,
                    ],
                    challenge,
                ),
                right_codomain_tag: actual_domain_hash(
                    b"AURORA:isogeny:kani:image-right:actual:v1",
                    &statement,
                    &[
                        curve_commitment(&witness.isogeny.right.target),
                        witness.isogeny.right.commitment(),
                        witness.isogeny.target_commitment(),
                        quotient_probe_commitment,
                        quotient_generator_image_commitment,
                        sample_commitment,
                        quotient_profile_commitment,
                    ],
                    challenge,
                ),
            },
        })
    }

    pub fn verify(
        transcript: &KaniTranscript,
        verifying_codomain_tag: [u8; 32],
        verifying_basis_commitment: [u8; 32],
        signature_codomain_tag: [u8; 32],
        signature_basis_commitment: [u8; 32],
        decomposition_commitment: [u8; 32],
        probe_commitment: [u8; 32],
        quotient_commitment: [u8; 32],
        signature_coefficients_commitment: [u8; 32],
        challenge: &[u8],
    ) -> Result<()> {
        let expected = Self::construct(
            verifying_codomain_tag,
            verifying_basis_commitment,
            signature_codomain_tag,
            signature_basis_commitment,
            decomposition_commitment,
            probe_commitment,
            quotient_commitment,
            signature_coefficients_commitment,
            challenge,
        );
        if *transcript == expected {
            Ok(())
        } else {
            Err(KaniError::InvalidTranscript)
        }
    }

    pub fn verify_witness(witness: &ProductIsogenyWitness, challenge: &[u8]) -> Result<()> {
        Self::verify(
            &witness.transcript,
            witness.statement.verifying_codomain_tag,
            witness.statement.verifying_basis_commitment,
            witness.statement.signature_codomain_tag,
            witness.statement.signature_basis_commitment,
            witness.statement.decomposition_commitment,
            witness.statement.probe_commitment,
            witness.statement.quotient_commitment,
            witness.statement.witness_commitment,
            challenge,
        )
    }

    pub fn verify_actual(
        transcript: &KaniTranscript,
        statement: ProductIsogenyStatement,
        witness: &ActualProductIsogenyWitnessData,
        challenge: &[u8],
    ) -> Result<()> {
        if statement.probe_commitment != witness.quotient_profile()?.probe_commitment() {
            return Err(KaniError::InvalidTranscript);
        }
        if statement.quotient_commitment != witness.quotient_profile_commitment()? {
            return Err(KaniError::InvalidTranscript);
        }
        let expected = Self::construct_actual(statement, witness, challenge)?;
        if *transcript == expected {
            Ok(())
        } else {
            Err(KaniError::InvalidTranscript)
        }
    }
}

fn domain_hash(
    domain: &[u8],
    left_tag: &[u8; 32],
    left_basis: &[u8; 32],
    right_tag: &[u8; 32],
    right_basis: &[u8; 32],
    decomposition_commitment: &[u8; 32],
    probe_commitment: &[u8; 32],
    quotient_commitment: &[u8; 32],
    right_coefficients: &[u8; 32],
    challenge: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(left_tag);
    hasher.update(left_basis);
    hasher.update(right_tag);
    hasher.update(right_basis);
    hasher.update(decomposition_commitment);
    hasher.update(probe_commitment);
    hasher.update(quotient_commitment);
    hasher.update(right_coefficients);
    hasher.update((challenge.len() as u32).to_be_bytes());
    hasher.update(challenge);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn actual_domain_hash(
    domain: &[u8],
    statement: &ProductIsogenyStatement,
    witness_parts: &[[u8; 32]],
    challenge: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(statement.verifying_codomain_tag);
    hasher.update(statement.verifying_basis_commitment);
    hasher.update(statement.signature_codomain_tag);
    hasher.update(statement.signature_basis_commitment);
    hasher.update(statement.decomposition_commitment);
    hasher.update(statement.probe_commitment);
    hasher.update(statement.quotient_commitment);
    hasher.update(statement.witness_commitment);
    hasher.update((witness_parts.len() as u32).to_be_bytes());
    for part in witness_parts {
        hasher.update(part);
    }
    hasher.update((challenge.len() as u32).to_be_bytes());
    hasher.update(challenge);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn update_curve_hash(hasher: &mut Sha3_256, curve: &ShortWeierstrassCurve) {
    update_fp2_hash(hasher, &curve.a);
    update_fp2_hash(hasher, &curve.b);
}

fn curve_commitment(curve: &ShortWeierstrassCurve) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:isogeny:kani:curve:v1");
    update_curve_hash(&mut hasher, curve);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn update_point_hash(hasher: &mut Sha3_256, point: &CurvePoint) {
    hasher.update([u8::from(point.infinity)]);
    update_fp2_hash(hasher, &point.x);
    update_fp2_hash(hasher, &point.y);
}

fn update_proj1_hash(hasher: &mut Sha3_256, point: &Proj1) {
    update_fp2_hash(hasher, &point.x);
    update_fp2_hash(hasher, &point.z);
}

fn update_theta_couple_hash(hasher: &mut Sha3_256, point: &ThetaCouplePoint) {
    update_proj1_hash(hasher, &point.p1);
    update_proj1_hash(hasher, &point.p2);
}

fn update_fp2_hash(hasher: &mut Sha3_256, value: &crate::crypto::isogeny::field::Fp2) {
    let c0 = value.c0.to_be_bytes();
    let c1 = value.c1.to_be_bytes();
    hasher.update((c0.len() as u32).to_be_bytes());
    hasher.update(c0);
    hasher.update((c1.len() as u32).to_be_bytes());
    hasher.update(c1);
}

fn enumerate_small_curve_points(curve: &ShortWeierstrassCurve) -> Result<Vec<CurvePoint>> {
    let modulus = *curve.modulus();
    let mut points = Vec::new();
    for x0 in 0..=31u64 {
        for x1 in 0..=31u64 {
            let x = Fp2::new(Fp::from_u64(&modulus, x0), Fp::from_u64(&modulus, x1))
                .map_err(|_| KaniError::InvalidActualWitness)?;
            if let Some(y) = curve
                .rhs(&x)
                .map_err(|_| KaniError::InvalidActualWitness)?
                .sqrt()
            {
                let point = CurvePoint::affine(x, y);
                if curve
                    .is_on_curve(&point)
                    .map_err(|_| KaniError::InvalidActualWitness)?
                {
                    points.push(point);
                    let neg = point.negate();
                    if neg != point {
                        points.push(neg);
                    }
                }
            }
        }
    }
    Ok(points)
}

#[cfg(test)]
mod tests {
    use super::{
        ActualProductIsogeny, ActualProductIsogenyWitnessData, ActualProductKernel,
        EvalByKaniActualInput, KaniEngine, KaniError, ProductPoint,
    };
    use crate::crypto::isogeny::algorithms::IdealToIsogenyEngine;
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::curve::weierstrass::{
        MontgomeryIsomorphism, ShortWeierstrassCurve,
    };
    use crate::crypto::isogeny::field::{Fp2, FpModulus};

    fn point_of_order(curve: &ShortWeierstrassCurve, prime: u64, order: u64) -> CurvePoint {
        for x in 0..prime {
            let x = Fp2::from_u64(curve.modulus(), x);
            if let Some(y) = curve.rhs(&x).unwrap().sqrt() {
                for point in [CurvePoint::affine(x, y), CurvePoint::affine(x, y.neg())] {
                    if point.is_infinity() {
                        continue;
                    }
                    if curve.scalar_mul_u64(&point, order).unwrap() != curve.identity() {
                        continue;
                    }
                    if (1..order).all(|scalar| {
                        curve.scalar_mul_u64(&point, scalar).unwrap() != curve.identity()
                    }) {
                        return point;
                    }
                }
            }
        }
        panic!("expected point of order {order}");
    }

    fn invalid_target_left_point(curve: &ShortWeierstrassCurve, point: &CurvePoint) -> CurvePoint {
        for delta in 1..=8u64 {
            let x = point.x.add(&Fp2::from_u64(curve.modulus(), delta)).unwrap();
            let candidate = CurvePoint::affine(x, point.y);
            if !curve.is_on_curve(&candidate).unwrap() {
                return candidate;
            }
        }
        panic!("expected invalid target point");
    }

    #[test]
    fn transcript_is_deterministic_for_same_inputs() {
        let vk = [0x11u8; 32];
        let vk_basis = [0x12u8; 32];
        let sig = [0x22u8; 32];
        let sig_basis = [0x23u8; 32];
        let decomposition = [0x2Au8; 32];
        let probe = [0x2Cu8; 32];
        let quotient = [0x2Bu8; 32];
        let sig_coeffs = [0x24u8; 32];
        let first = KaniEngine::construct(
            vk,
            vk_basis,
            sig,
            sig_basis,
            decomposition,
            probe,
            quotient,
            sig_coeffs,
            b"challenge",
        );
        let second = KaniEngine::construct(
            vk,
            vk_basis,
            sig,
            sig_basis,
            decomposition,
            probe,
            quotient,
            sig_coeffs,
            b"challenge",
        );
        assert_eq!(first, second);
    }

    #[test]
    fn transcript_verification_rejects_modified_input() {
        let vk = [0x33u8; 32];
        let vk_basis = [0x34u8; 32];
        let sig = [0x44u8; 32];
        let sig_basis = [0x45u8; 32];
        let decomposition = [0x4Au8; 32];
        let probe = [0x4Cu8; 32];
        let quotient = [0x4Bu8; 32];
        let sig_coeffs = [0x46u8; 32];
        let transcript = KaniEngine::construct(
            vk,
            vk_basis,
            sig,
            sig_basis,
            decomposition,
            probe,
            quotient,
            sig_coeffs,
            b"challenge",
        );
        assert_eq!(
            KaniEngine::verify(
                &transcript,
                vk,
                vk_basis,
                sig,
                sig_basis,
                decomposition,
                probe,
                quotient,
                sig_coeffs,
                b"challenge"
            ),
            Ok(())
        );
        assert_eq!(
            KaniEngine::verify(
                &transcript,
                vk,
                vk_basis,
                sig,
                sig_basis,
                decomposition,
                probe,
                quotient,
                sig_coeffs,
                b"tampered"
            ),
            Err(KaniError::InvalidTranscript)
        );
    }

    #[test]
    fn transcript_changes_when_codomain_order_changes() {
        let left = KaniEngine::construct(
            [0x55u8; 32],
            [0x56u8; 32],
            [0x66u8; 32],
            [0x67u8; 32],
            [0x68u8; 32],
            [0x69u8; 32],
            [0x69u8; 32],
            [0x68u8; 32],
            b"challenge",
        );
        let right = KaniEngine::construct(
            [0x66u8; 32],
            [0x67u8; 32],
            [0x55u8; 32],
            [0x56u8; 32],
            [0x57u8; 32],
            [0x58u8; 32],
            [0x58u8; 32],
            [0x57u8; 32],
            b"challenge",
        );
        assert_ne!(
            left.kernel.pairing_commitment,
            right.kernel.pairing_commitment
        );
        assert_ne!(left.image.left_codomain_tag, right.image.left_codomain_tag);
    }

    #[test]
    fn witness_roundtrip_verifies() {
        let statement = KaniEngine::statement(
            [0x71u8; 32],
            [0x72u8; 32],
            [0x73u8; 32],
            [0x74u8; 32],
            [0x75u8; 32],
            [0x76u8; 32],
            [0x77u8; 32],
            [0x77u8; 32],
        );
        let witness = KaniEngine::construct_witness(statement, b"challenge");
        assert_eq!(KaniEngine::verify_witness(&witness, b"challenge"), Ok(()));
        assert_eq!(
            KaniEngine::verify_witness(&witness, b"wrong"),
            Err(KaniError::InvalidTranscript)
        );
    }

    #[test]
    fn actual_product_witness_constructs_and_verifies() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();

        let witness = witness_data.construct_witness(b"challenge").unwrap();
        assert_eq!(KaniEngine::verify_witness(&witness, b"challenge"), Ok(()));
    }

    #[test]
    fn actual_product_witness_rejects_non_kernel_generator() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();
        let non_kernel = point_of_order(&curve, 19, 2);

        let mut witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        witness_data.kernel = ActualProductKernel {
            p: ProductPoint::new(non_kernel, curve.identity()),
            q: ProductPoint::new(curve.identity(), right_generator),
        };

        assert_eq!(
            witness_data.validate(),
            Err(KaniError::InvalidActualWitness)
        );
    }

    #[test]
    fn actual_product_witness_rejects_tampered_sample_image() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let mut witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        witness_data.images[0] = witness_data.kernel.p;
        assert_eq!(
            witness_data.validate(),
            Err(KaniError::InvalidActualWitness)
        );
    }

    #[test]
    fn actual_product_witness_rejects_image_outside_target_curve() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let mut witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        witness_data.images[0].left = invalid_target_left_point(
            &witness_data.isogeny.left.target,
            &witness_data.images[0].left,
        );
        assert_eq!(
            witness_data.validate(),
            Err(KaniError::InvalidActualWitness)
        );
    }

    #[test]
    fn actual_product_witness_rejects_degenerate_kernel_basis() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let mut witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        witness_data.kernel = ActualProductKernel {
            p: witness_data.kernel.p,
            q: witness_data.kernel.p,
        };

        assert_eq!(
            witness_data.validate(),
            Err(KaniError::InvalidActualWitness)
        );
    }

    #[test]
    fn actual_product_witness_kernel_translation_preserves_images() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        for (sample, image) in witness_data.samples.iter().zip(witness_data.images.iter()) {
            for translated in witness_data.sample_orbit(sample).unwrap() {
                assert_eq!(witness_data.isogeny.map_point(&translated).unwrap(), *image);
            }
        }
    }

    #[test]
    fn actual_product_witness_coset_commitment_changes_when_sample_order_changes() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let mut witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let original = witness_data.coset_commitment().unwrap();
        witness_data.samples.reverse();
        witness_data.images.reverse();
        assert_ne!(original, witness_data.coset_commitment().unwrap());
    }

    #[test]
    fn quotient_profile_commitment_changes_when_sample_order_changes() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let mut witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let original = witness_data.quotient_profile_commitment().unwrap();
        witness_data.samples.reverse();
        witness_data.images.reverse();
        assert_ne!(
            original,
            witness_data.quotient_profile_commitment().unwrap()
        );
    }

    #[test]
    fn eval_by_kani_actual_matches_quotient_profile() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let profile = witness_data.quotient_profile().unwrap();
        let evaluation = KaniEngine::eval_by_kani_actual(
            &witness_data.isogeny,
            &EvalByKaniActualInput {
                generators: profile.generators,
                axis_probes: profile.axis_probes,
                samples: profile.samples.clone(),
            },
        )
        .unwrap();

        assert_eq!(evaluation.generator_images, profile.generator_images);
        assert_eq!(evaluation.generator_sum_image, profile.generator_sum_image);
        assert_eq!(
            evaluation.generator_diff_image,
            profile.generator_diff_image
        );
        assert_eq!(
            evaluation.generator_double_images,
            profile.generator_double_images
        );
        assert_eq!(
            &*evaluation.generator_triple_images,
            &*profile.generator_triple_images
        );
        assert_eq!(evaluation.axis_probe_images, profile.axis_probe_images);
        assert_eq!(
            evaluation.axis_probe_sum_image,
            profile.axis_probe_sum_image
        );
        assert_eq!(
            evaluation.axis_probe_diff_image,
            profile.axis_probe_diff_image
        );
        assert_eq!(
            evaluation.axis_probe_double_images,
            profile.axis_probe_double_images
        );
        assert_eq!(
            &*evaluation.axis_probe_triple_images,
            &*profile.axis_probe_triple_images
        );
        assert_eq!(evaluation.images, profile.images);
    }

    #[test]
    fn structured_quotient_backend_matches_witness_profile() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let isogeny = ActualProductIsogeny { left, right };
        let witness = super::StructuredQuotientBackend::witness_from_isogeny(isogeny).unwrap();
        let profile = super::StructuredQuotientBackend::profile_from_witness(&witness).unwrap();
        assert_eq!(profile, witness.quotient_profile().unwrap());
    }

    #[test]
    fn theta_quotient_backend_matches_eval_by_kani_actual() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let profile = witness_data.quotient_profile().unwrap();
        let theta = super::StructuredQuotientBackend::eval_theta_quotient(
            &witness_data.isogeny,
            &witness_data.kernel,
            &super::ThetaProductIsogenyInput {
                generators: profile.generators,
                axis_probes: profile.axis_probes,
                samples: profile.samples.clone(),
            },
        )
        .unwrap();
        let eval = KaniEngine::eval_by_kani_actual(
            &witness_data.isogeny,
            &EvalByKaniActualInput {
                generators: profile.generators,
                axis_probes: profile.axis_probes,
                samples: profile.samples.clone(),
            },
        )
        .unwrap();

        assert_eq!(theta.generator_images, eval.generator_images);
        assert_eq!(theta.generator_sum_image, eval.generator_sum_image);
        assert_eq!(theta.generator_diff_image, eval.generator_diff_image);
        assert_eq!(theta.generator_double_images, eval.generator_double_images);
        assert_eq!(
            &*theta.generator_triple_images,
            &*eval.generator_triple_images
        );
        assert_eq!(theta.axis_probe_images, eval.axis_probe_images);
        assert_eq!(theta.axis_probe_sum_image, eval.axis_probe_sum_image);
        assert_eq!(theta.axis_probe_diff_image, eval.axis_probe_diff_image);
        assert_eq!(
            theta.axis_probe_double_images,
            eval.axis_probe_double_images
        );
        assert_eq!(
            &*theta.axis_probe_triple_images,
            &*eval.axis_probe_triple_images
        );
        assert_eq!(theta.images, eval.images);
    }

    #[test]
    fn theta_quotient_backend_handles_pure_two_power_case() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 2);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 2)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let profile = witness_data.quotient_profile().unwrap();
        let theta = super::StructuredQuotientBackend::eval_theta_quotient(
            &witness_data.isogeny,
            &witness_data.kernel,
            &super::ThetaProductIsogenyInput {
                generators: profile.generators,
                axis_probes: profile.axis_probes,
                samples: profile.samples.clone(),
            },
        )
        .unwrap();

        if let Some(theta_data) = &theta.theta_data {
            assert_eq!(theta_data.sample_images_xonly.len(), profile.samples.len());
        }
    }

    #[test]
    fn quotient_profile_theta_commitment_matches_eval_theta_quotient() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 2);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 2)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let profile = witness_data.quotient_profile().unwrap();
        let theta = super::StructuredQuotientBackend::eval_theta_quotient(
            &witness_data.isogeny,
            &witness_data.kernel,
            &super::ThetaProductIsogenyInput {
                generators: profile.generators,
                axis_probes: profile.axis_probes,
                samples: profile.samples.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            profile
                .theta_commitment(&witness_data.isogeny, &witness_data.kernel)
                .unwrap(),
            theta
                .theta_data
                .as_ref()
                .map(super::ThetaQuotientData::commitment)
        );
    }

    #[test]
    fn quotient_profile_validate_accepts_theta_capable_profile() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 2);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 2)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let profile = witness_data.quotient_profile().unwrap();
        profile
            .validate(&witness_data.isogeny, &witness_data.kernel)
            .unwrap();
        let theta = super::StructuredQuotientBackend::eval_theta_quotient(
            &witness_data.isogeny,
            &witness_data.kernel,
            &super::ThetaProductIsogenyInput {
                generators: profile.generators,
                axis_probes: profile.axis_probes,
                samples: profile.samples.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            profile
                .theta_commitment(&witness_data.isogeny, &witness_data.kernel)
                .unwrap(),
            theta
                .theta_data
                .as_ref()
                .map(super::ThetaQuotientData::commitment)
        );
    }

    #[test]
    fn quotient_profile_theta_commitment_is_absent_for_mixed_degree_case() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let profile = witness_data.quotient_profile().unwrap();
        assert_eq!(
            profile
                .theta_commitment(&witness_data.isogeny, &witness_data.kernel)
                .unwrap(),
            None
        );
    }

    #[test]
    fn quotient_profile_rejects_tampered_generator_double_image() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let mut profile = witness_data.quotient_profile().unwrap();
        profile.generator_double_images[0] = witness_data.isogeny.target_identity();

        assert_eq!(
            profile.validate(&witness_data.isogeny, &witness_data.kernel),
            Err(KaniError::InvalidActualWitness)
        );
    }

    #[test]
    fn quotient_profile_rejects_tampered_axis_probe_double_image() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let mut profile = witness_data.quotient_profile().unwrap();
        profile.axis_probe_double_images[0] = witness_data.isogeny.target_identity();

        assert_eq!(
            profile.validate(&witness_data.isogeny, &witness_data.kernel),
            Err(KaniError::InvalidActualWitness)
        );
    }

    #[test]
    fn quotient_profile_rejects_tampered_generator_triple_image() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let witness_data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let mut profile = witness_data.quotient_profile().unwrap();
        profile.generator_triple_images[0] = witness_data.isogeny.target_identity();

        assert_eq!(
            profile.validate(&witness_data.isogeny, &witness_data.kernel),
            Err(KaniError::InvalidActualWitness)
        );
    }

    #[test]
    fn actual_product_witness_can_be_derived_from_isogeny() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let witness = data.construct_witness(b"challenge").unwrap();
        assert_eq!(KaniEngine::verify_witness(&witness, b"challenge"), Ok(()));
    }

    #[test]
    fn derived_kernel_basis_prefers_mixed_generators_when_available() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();

        let data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let non_identity_coordinates = [
            !data.kernel.p.left.is_infinity(),
            !data.kernel.p.right.is_infinity(),
            !data.kernel.q.left.is_infinity(),
            !data.kernel.q.right.is_infinity(),
        ]
        .into_iter()
        .filter(|value| *value)
        .count();
        assert!(non_identity_coordinates >= 3);
        assert!(!data.kernel.p.left.is_infinity());
        assert!(!data.kernel.p.right.is_infinity());
    }

    #[test]
    fn actual_transcript_verifies_against_public_statement() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let left_generator = point_of_order(&curve, 19, 3);
        let left =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(left_generator, 3)]).unwrap();
        let right_generator = point_of_order(&curve, 19, 2);
        let right =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(right_generator, 2)]).unwrap();
        let data =
            ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny { left, right })
                .unwrap();
        let statement = KaniEngine::statement(
            [0x81u8; 32],
            [0x82u8; 32],
            [0x83u8; 32],
            [0x84u8; 32],
            [0u8; 32],
            data.quotient_profile().unwrap().probe_commitment(),
            data.quotient_profile_commitment().unwrap(),
            data.isogeny.commitment(),
        );
        let transcript = KaniEngine::construct_actual(statement, &data, b"challenge").unwrap();
        assert_eq!(
            KaniEngine::verify_actual(&transcript, statement, &data, b"challenge"),
            Ok(())
        );
        assert_eq!(
            KaniEngine::verify_actual(&transcript, statement, &data, b"wrong"),
            Err(KaniError::InvalidTranscript)
        );
    }
}
