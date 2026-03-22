//! Ideal-to-isogeny translation entry points.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_256};

use crate::crypto::isogeny::algorithms::qlapoti::{QlapotiEngine, QlapotiPlan, QlapotiStrategy};
use crate::crypto::isogeny::algorithms::velu::{VeluError, VeluIsogeny};
use crate::crypto::isogeny::arith::IsogenyInteger;
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::curve::weierstrass::{ShortWeierstrassCurve, WeierstrassError};
use crate::crypto::isogeny::ideal::ideal::IdealError;
use crate::crypto::isogeny::ideal::ideal::LeftIdeal;
use crate::crypto::isogeny::ideal::lattice::BasisLattice;
use crate::crypto::isogeny::ideal::quaternion::{QuaternionElement, QuaternionError};

pub type Result<T> = core::result::Result<T, IdealToIsogenyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdealToIsogenyError {
    InvalidTorsionPower,
    Curve(WeierstrassError),
    Velu(VeluError),
    Ideal(IdealError),
    Quaternion(QuaternionError),
    InvalidChain,
    UnsupportedActualDegree,
    ActualEnumerationUnsupported,
    KernelSearchFailed,
}

impl From<WeierstrassError> for IdealToIsogenyError {
    fn from(value: WeierstrassError) -> Self {
        Self::Curve(value)
    }
}

impl From<VeluError> for IdealToIsogenyError {
    fn from(value: VeluError) -> Self {
        Self::Velu(value)
    }
}

impl From<IdealError> for IdealToIsogenyError {
    fn from(value: IdealError) -> Self {
        Self::Ideal(value)
    }
}

impl From<QuaternionError> for IdealToIsogenyError {
    fn from(value: QuaternionError) -> Self {
        Self::Quaternion(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceCurveDescriptor {
    pub tag: [u8; 32],
    pub hint: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceBasisDescriptor {
    pub p_tag: [u8; 32],
    pub q_tag: [u8; 32],
    pub power: u16,
    pub hint: u16,
}

impl ReferenceBasisDescriptor {
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:reference:basis-commitment:v1");
        hasher.update(self.p_tag);
        hasher.update(self.q_tag);
        hasher.update(self.power.to_be_bytes());
        hasher.update(self.hint.to_be_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceIsogeny {
    pub degree: IsogenyInteger,
    pub codomain: ReferenceCurveDescriptor,
    pub torsion_basis: ReferenceBasisDescriptor,
    pub qlapoti_plan: QlapotiPlan,
    pub chain: ReferenceIsogenyChain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceKernelDescriptor {
    pub tag: [u8; 32],
    pub degree: IsogenyInteger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceIsogenyStep {
    pub source: ReferenceCurveDescriptor,
    pub target: ReferenceCurveDescriptor,
    pub kernel: ReferenceKernelDescriptor,
    pub degree: IsogenyInteger,
    pub strategy: QlapotiStrategy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceIsogenyChain {
    pub source: ReferenceCurveDescriptor,
    pub target: ReferenceCurveDescriptor,
    pub steps: Vec<ReferenceIsogenyStep>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActualIsogenyStep {
    pub degree: usize,
    pub domain: ShortWeierstrassCurve,
    pub codomain: ShortWeierstrassCurve,
    pub kernel_generator: CurvePoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualIsogenyChain {
    pub source: ShortWeierstrassCurve,
    pub target: ShortWeierstrassCurve,
    pub steps: Vec<ActualIsogenyStep>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActualKernelHint {
    pub degree: IsogenyInteger,
    pub candidate_index: u16,
    pub stage_binding: [u8; 32],
    pub generator_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualKernelExtraction {
    pub source: ShortWeierstrassCurve,
    pub hints: Vec<ActualKernelHint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageIdealDecomposition {
    pub input: LeftIdeal,
    pub principal: LeftIdeal,
    pub stage: LeftIdeal,
    pub next: LeftIdeal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualKernelSearchContext {
    pub seed: [u8; 32],
    pub binding: [u8; 32],
    pub stage_bindings: Vec<[u8; 32]>,
    pub cofactor: u32,
    pub two_torsion_bits: u16,
    pub use_base_two_torsion: bool,
}

impl ActualIsogenyStep {
    pub fn evaluate(&self) -> Result<VeluIsogeny> {
        let isogeny = VeluIsogeny::from_kernel(self.domain, self.kernel_generator, self.degree)?;
        if *isogeny.codomain() != self.codomain {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        Ok(isogeny)
    }

    pub fn map_point(&self, point: &CurvePoint) -> Result<CurvePoint> {
        Ok(self.evaluate()?.map_point(point)?)
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:actual-step:v1");
        hasher.update((self.degree as u64).to_be_bytes());
        update_curve_hash(&mut hasher, &self.domain);
        update_curve_hash(&mut hasher, &self.codomain);
        update_point_hash(&mut hasher, &self.kernel_generator);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

impl ActualIsogenyChain {
    pub fn validate(&self) -> Result<()> {
        let mut current = self.source;
        for step in &self.steps {
            if step.domain != current {
                return Err(IdealToIsogenyError::InvalidChain);
            }
            let realized = step.evaluate()?;
            current = *realized.codomain();
        }
        if current != self.target {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        Ok(())
    }

    pub fn map_point(&self, point: &CurvePoint) -> Result<CurvePoint> {
        self.source.validate_point(point)?;
        let mut current = *point;
        for step in &self.steps {
            current = step.map_point(&current)?;
        }
        self.target.validate_point(&current)?;
        Ok(current)
    }

    pub fn map_points(&self, points: &[CurvePoint]) -> Result<Vec<CurvePoint>> {
        let mut images = Vec::with_capacity(points.len());
        for point in points {
            images.push(self.map_point(point)?);
        }
        Ok(images)
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:actual-chain:v1");
        update_curve_hash(&mut hasher, &self.source);
        update_curve_hash(&mut hasher, &self.target);
        hasher.update((self.steps.len() as u32).to_be_bytes());
        for step in &self.steps {
            hasher.update(step.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

impl ActualKernelHint {
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:actual-kernel-hint:v1");
        hasher.update(self.degree.to_be_bytes_fixed());
        hasher.update(self.candidate_index.to_be_bytes());
        hasher.update(self.stage_binding);
        hasher.update(self.generator_commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

impl ActualKernelExtraction {
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:actual-kernel-extraction:v1");
        update_curve_hash(&mut hasher, &self.source);
        hasher.update((self.hints.len() as u32).to_be_bytes());
        for hint in &self.hints {
            hasher.update(hint.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IdealToIsogenyEngine;

impl IdealToIsogenyEngine {
    pub fn translate(ideal: &LeftIdeal, torsion_power: usize) -> Result<ReferenceIsogeny> {
        let torsion_power =
            u16::try_from(torsion_power).map_err(|_| IdealToIsogenyError::InvalidTorsionPower)?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:ideal-to-isogeny:v1");
        hasher.update(ideal.left_order().algebra().ramified_prime().to_be_bytes());
        hasher.update(ideal.norm().to_be_bytes_fixed());
        for coeff in ideal.generator().coeffs() {
            hasher.update(coeff.to_be_bytes());
        }

        let mut codomain_tag = [0u8; 32];
        codomain_tag.copy_from_slice(&hasher.finalize());
        let codomain = Self::curve_descriptor_from_tag(codomain_tag);
        let qlapoti_plan = QlapotiEngine::plan_for_ideal(ideal);
        let chain = derive_isogeny_chain(ideal, &codomain, &qlapoti_plan);
        Ok(ReferenceIsogeny {
            degree: ideal.norm(),
            codomain,
            torsion_basis: Self::basis_descriptor_from_tag(codomain_tag, torsion_power as usize)?,
            qlapoti_plan,
            chain,
        })
    }

    pub fn curve_descriptor_from_tag(codomain_tag: [u8; 32]) -> ReferenceCurveDescriptor {
        derive_curve_descriptor(&codomain_tag)
    }

    pub fn basis_descriptor_from_tag(
        codomain_tag: [u8; 32],
        torsion_power: usize,
    ) -> Result<ReferenceBasisDescriptor> {
        let torsion_power =
            u16::try_from(torsion_power).map_err(|_| IdealToIsogenyError::InvalidTorsionPower)?;
        Ok(derive_basis_descriptor(&codomain_tag, torsion_power))
    }

    pub fn realize_small_chain(
        source: ShortWeierstrassCurve,
        kernel_generators: &[(CurvePoint, usize)],
    ) -> Result<ActualIsogenyChain> {
        let mut current = source;
        let mut steps = Vec::with_capacity(kernel_generators.len());
        for (generator, degree) in kernel_generators {
            let isogeny = VeluIsogeny::from_kernel(current, *generator, *degree)?;
            let codomain = *isogeny.codomain();
            steps.push(ActualIsogenyStep {
                degree: *degree,
                domain: current,
                codomain,
                kernel_generator: *generator,
            });
            current = codomain;
        }
        let chain = ActualIsogenyChain {
            source,
            target: current,
            steps,
        };
        chain.validate()?;
        Ok(chain)
    }

    pub fn realize_small_qlapoti_chain(
        source: ShortWeierstrassCurve,
        ideal: &LeftIdeal,
    ) -> Result<ActualIsogenyChain> {
        let extraction = Self::extract_small_kernel_hints(source, ideal)?;
        Self::realize_small_qlapoti_chain_from_hints(source, ideal, &extraction)
    }

    pub fn find_small_qlapoti_curve(ideal: &LeftIdeal) -> Result<ShortWeierstrassCurve> {
        for prime in SMALL_CURVE_SEARCH_PRIMES {
            let modulus = crate::crypto::isogeny::field::FpModulus::from_u64(prime)
                .map_err(crate::crypto::isogeny::curve::weierstrass::WeierstrassError::from)?;
            for a in 0..prime {
                let montgomery =
                    match crate::crypto::isogeny::curve::montgomery::MontgomeryCurve::new(
                        crate::crypto::isogeny::field::Fp2::from_u64(&modulus, a),
                    ) {
                        Ok(curve) => curve,
                        Err(_) => continue,
                    };
                let iso =
                    match crate::crypto::isogeny::curve::weierstrass::MontgomeryIsomorphism::new(
                        montgomery,
                    ) {
                        Ok(iso) => iso,
                        Err(_) => continue,
                    };
                let curve = *iso.weierstrass_curve();
                if Self::realize_small_qlapoti_chain(curve, ideal).is_ok() {
                    return Ok(curve);
                }
            }
        }
        Err(IdealToIsogenyError::KernelSearchFailed)
    }

    pub fn realize_small_qlapoti_chain_with_curve_search(
        ideal: &LeftIdeal,
    ) -> Result<ActualIsogenyChain> {
        Self::realize_small_qlapoti_chain(Self::find_small_qlapoti_curve(ideal)?, ideal)
    }

    pub fn extract_small_kernel_hints(
        source: ShortWeierstrassCurve,
        ideal: &LeftIdeal,
    ) -> Result<ActualKernelExtraction> {
        let plan = QlapotiEngine::plan_for_ideal(ideal);
        let degrees = expand_actual_degrees(&plan)?;
        let stages = derive_small_stage_decomposition(ideal, &degrees)?;
        let stage_bindings = derive_small_stage_bindings(ideal, &degrees)?;
        let (hints, _) = extract_actual_hints(source, &stages, &degrees, &stage_bindings, 0)?;
        Ok(ActualKernelExtraction { source, hints })
    }

    pub fn realize_small_qlapoti_chain_from_hints(
        source: ShortWeierstrassCurve,
        ideal: &LeftIdeal,
        extraction: &ActualKernelExtraction,
    ) -> Result<ActualIsogenyChain> {
        if extraction.source != source {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let plan = QlapotiEngine::plan_for_ideal(ideal);
        let degrees = expand_actual_degrees(&plan)?;
        if extraction.hints.len() != degrees.len() {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let stage_bindings = derive_small_stage_bindings(ideal, &degrees)?;
        let stages = derive_small_stage_decomposition(ideal, &degrees)?;
        let (steps, target) = realize_actual_steps_from_hints(
            source,
            &stages,
            &degrees,
            &stage_bindings,
            &extraction.hints,
        )?;
        let chain = ActualIsogenyChain {
            source,
            target,
            steps,
        };
        chain.validate()?;
        Ok(chain)
    }

    pub fn realize_small_odd_chain(
        source: ShortWeierstrassCurve,
        kernel_generators: &[(CurvePoint, usize)],
    ) -> Result<ActualIsogenyChain> {
        Self::realize_small_chain(source, kernel_generators)
    }

    pub fn derive_stage_decomposition(
        ideal: &LeftIdeal,
        degrees: &[IsogenyInteger],
    ) -> Result<Vec<StageIdealDecomposition>> {
        let mut stages = Vec::with_capacity(degrees.len());
        let mut current = *ideal;
        for (stage, degree) in degrees.iter().copied().enumerate() {
            if degree < 2u128 {
                return Err(IdealToIsogenyError::UnsupportedActualDegree);
            }
            let principal = derive_stage_principal_ideal(&current, degree, stage)?;
            let stage_ideal = derive_stage_intersection_ideal(&current, &principal, degree, stage)?;
            let next = derive_stage_transport_ideal(&current, &principal, stage)?;
            stages.push(StageIdealDecomposition {
                input: current,
                principal,
                stage: stage_ideal,
                next,
            });
            current = next;
        }
        Ok(stages)
    }

    pub fn replay_stage_decomposition_from_principals(
        ideal: &LeftIdeal,
        degrees: &[IsogenyInteger],
        principal_ideals: &[LeftIdeal],
    ) -> Result<Vec<StageIdealDecomposition>> {
        if degrees.len() != principal_ideals.len() {
            return Err(IdealToIsogenyError::InvalidChain);
        }

        let mut stages = Vec::with_capacity(degrees.len());
        let mut current = *ideal;
        for (stage, (&degree, principal)) in degrees.iter().zip(principal_ideals).enumerate() {
            if degree < 2u128 {
                return Err(IdealToIsogenyError::UnsupportedActualDegree);
            }
            if principal.norm() != degree
                || principal.left_order() != current.left_order()
                || principal.right_order() != current.right_order()
            {
                return Err(IdealToIsogenyError::InvalidChain);
            }
            let stage_ideal = derive_stage_intersection_ideal(&current, principal, degree, stage)?;
            let next = derive_stage_transport_ideal(&current, principal, stage)?;
            stages.push(StageIdealDecomposition {
                input: current,
                principal: *principal,
                stage: stage_ideal,
                next,
            });
            current = next;
        }
        Ok(stages)
    }

    pub fn derive_stage_ideals(
        ideal: &LeftIdeal,
        degrees: &[IsogenyInteger],
    ) -> Result<Vec<LeftIdeal>> {
        Ok(Self::derive_stage_decomposition(ideal, degrees)?
            .into_iter()
            .map(|stage| stage.stage)
            .collect())
    }

    pub fn derive_stage_bindings(
        ideal: &LeftIdeal,
        degrees: &[IsogenyInteger],
    ) -> Result<Vec<[u8; 32]>> {
        let stage_ideals = Self::derive_stage_ideals(ideal, degrees)?;
        Ok(Self::stage_bindings_for_ideals(&stage_ideals))
    }

    pub fn stage_bindings_for_ideals(stage_ideals: &[LeftIdeal]) -> Vec<[u8; 32]> {
        let mut bindings = Vec::with_capacity(stage_ideals.len());
        for (stage, stage_ideal) in stage_ideals.iter().enumerate() {
            bindings.push(stage_ideal_binding(stage_ideal, stage));
        }
        bindings
    }

    pub fn realize_bounded_step(
        source: ShortWeierstrassCurve,
        degree: IsogenyInteger,
        stage: usize,
        context: &ActualKernelSearchContext,
    ) -> Result<ActualIsogenyStep> {
        let degree = degree
            .try_to_usize()
            .ok_or(IdealToIsogenyError::UnsupportedActualDegree)?;
        let candidates = bounded_exact_order_candidates(&source, degree, stage, context)?;
        let generator = *candidates
            .first()
            .ok_or(IdealToIsogenyError::KernelSearchFailed)?;
        let isogeny = VeluIsogeny::from_kernel(source, generator, degree)?;
        Ok(ActualIsogenyStep {
            degree,
            domain: source,
            codomain: *isogeny.codomain(),
            kernel_generator: generator,
        })
    }

    pub fn realize_bounded_chain(
        source: ShortWeierstrassCurve,
        degrees: &[IsogenyInteger],
        context: &ActualKernelSearchContext,
    ) -> Result<ActualIsogenyChain> {
        let extraction = Self::extract_bounded_kernel_hints(source, degrees, context)?;
        Self::realize_bounded_chain_from_hints(source, degrees, context, &extraction)
    }

    pub fn extract_bounded_kernel_hints(
        source: ShortWeierstrassCurve,
        degrees: &[IsogenyInteger],
        context: &ActualKernelSearchContext,
    ) -> Result<ActualKernelExtraction> {
        let degrees = actual_degrees_from_integers(degrees)?;
        let (hints, _) = extract_bounded_actual_hints(source, &degrees, context, 0)?;
        Ok(ActualKernelExtraction { source, hints })
    }

    pub fn realize_bounded_chain_from_hints(
        source: ShortWeierstrassCurve,
        degrees: &[IsogenyInteger],
        context: &ActualKernelSearchContext,
        extraction: &ActualKernelExtraction,
    ) -> Result<ActualIsogenyChain> {
        if extraction.source != source {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let degrees = actual_degrees_from_integers(degrees)?;
        if extraction.hints.len() != degrees.len() {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let (steps, target) =
            realize_bounded_actual_steps_from_hints(source, &degrees, extraction, context)?;
        let chain = ActualIsogenyChain {
            source,
            target,
            steps,
        };
        chain.validate()?;
        Ok(chain)
    }
}

fn update_curve_hash(hasher: &mut Sha3_256, curve: &ShortWeierstrassCurve) {
    update_fp2_hash(hasher, &curve.a);
    update_fp2_hash(hasher, &curve.b);
}

fn update_point_hash(hasher: &mut Sha3_256, point: &CurvePoint) {
    hasher.update([u8::from(point.infinity)]);
    update_fp2_hash(hasher, &point.x);
    update_fp2_hash(hasher, &point.y);
}

fn update_fp2_hash(hasher: &mut Sha3_256, value: &crate::crypto::isogeny::field::Fp2) {
    let c0 = value.c0.to_be_bytes();
    let c1 = value.c1.to_be_bytes();
    hasher.update((c0.len() as u32).to_be_bytes());
    hasher.update(c0);
    hasher.update((c1.len() as u32).to_be_bytes());
    hasher.update(c1);
}

const ACTUAL_ENUMERATION_BOUND: u64 = 31;
const SMALL_CURVE_SEARCH_PRIMES: [u64; 9] = [19, 23, 29, 31, 37, 41, 43, 47, 53];
const BOUNDED_SEARCH_X_BOUND: u64 = 32;
const BOUNDED_SEARCH_Y_BOUND: u64 = 4;

fn expand_actual_degrees(plan: &QlapotiPlan) -> Result<Vec<usize>> {
    let mut degrees = Vec::new();
    for step in &plan.steps {
        match step.strategy {
            QlapotiStrategy::TwoPower => {
                if step.prime != 2 || step.degree == 0 {
                    return Err(IdealToIsogenyError::UnsupportedActualDegree);
                }
                for _ in 0..step.exponent {
                    degrees.push(2usize);
                }
            }
            QlapotiStrategy::OddPrimePower => {
                let degree = step
                    .degree
                    .try_to_usize()
                    .ok_or(IdealToIsogenyError::UnsupportedActualDegree)?;
                degrees.push(degree);
            }
            QlapotiStrategy::LargeComposite => {
                return Err(IdealToIsogenyError::UnsupportedActualDegree);
            }
        }
    }
    Ok(degrees)
}

fn actual_degrees_from_integers(degrees: &[IsogenyInteger]) -> Result<Vec<usize>> {
    let mut out = Vec::with_capacity(degrees.len());
    for degree in degrees {
        out.push(
            degree
                .try_to_usize()
                .ok_or(IdealToIsogenyError::UnsupportedActualDegree)?,
        );
    }
    Ok(out)
}

fn extract_actual_hints(
    current: ShortWeierstrassCurve,
    stages: &[StageIdealDecomposition],
    degrees: &[usize],
    stage_bindings: &[[u8; 32]],
    stage: usize,
) -> Result<(Vec<ActualKernelHint>, ShortWeierstrassCurve)> {
    if stage == degrees.len() {
        return Ok((Vec::new(), current));
    }

    let degree = degrees[stage];
    let candidates = exact_order_points(&current, degree)?;
    if candidates.is_empty() {
        return Err(IdealToIsogenyError::KernelSearchFailed);
    }

    let start =
        stage_candidate_start_index(&stages[stage], &current, degree, stage, candidates.len());
    for offset in 0..candidates.len() {
        let index = (start + offset) % candidates.len();
        let generator = candidates[index];
        let isogeny = match VeluIsogeny::from_kernel(current, generator, degree) {
            Ok(isogeny) => isogeny,
            Err(_) => continue,
        };
        let codomain = *isogeny.codomain();
        if let Ok((mut tail, target)) =
            extract_actual_hints(codomain, stages, degrees, stage_bindings, stage + 1)
        {
            let mut hints = Vec::with_capacity(tail.len() + 1);
            hints.push(ActualKernelHint {
                degree: IsogenyInteger::from(degree),
                candidate_index: u16::try_from(index)
                    .map_err(|_| IdealToIsogenyError::UnsupportedActualDegree)?,
                stage_binding: expected_stage_hint_binding(
                    &current,
                    degree,
                    stage,
                    stage_bindings.get(stage).copied(),
                ),
                generator_commitment: point_commitment(&generator),
            });
            hints.append(&mut tail);
            return Ok((hints, target));
        }
    }

    Err(IdealToIsogenyError::KernelSearchFailed)
}

fn realize_actual_steps_from_hints(
    source: ShortWeierstrassCurve,
    _stages: &[StageIdealDecomposition],
    degrees: &[usize],
    stage_bindings: &[[u8; 32]],
    hints: &[ActualKernelHint],
) -> Result<(Vec<ActualIsogenyStep>, ShortWeierstrassCurve)> {
    let mut current = source;
    let mut steps = Vec::with_capacity(hints.len());
    for (stage, (degree, hint)) in degrees.iter().copied().zip(hints.iter()).enumerate() {
        if hint.degree.try_to_usize() != Some(degree) {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let expected_stage_binding = expected_stage_hint_binding(
            &current,
            degree,
            stage,
            stage_bindings.get(stage).copied(),
        );
        if hint.stage_binding != expected_stage_binding {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let candidates = exact_order_points(&current, degree)?;
        let index = usize::from(hint.candidate_index);
        if index >= candidates.len() {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let generator = candidates[index];
        if point_commitment(&generator) != hint.generator_commitment {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let isogeny = VeluIsogeny::from_kernel(current, generator, degree)?;
        let codomain = *isogeny.codomain();
        steps.push(ActualIsogenyStep {
            degree,
            domain: current,
            codomain,
            kernel_generator: generator,
        });
        current = codomain;
    }
    Ok((steps, current))
}

fn extract_bounded_actual_hints(
    current: ShortWeierstrassCurve,
    degrees: &[usize],
    context: &ActualKernelSearchContext,
    stage: usize,
) -> Result<(Vec<ActualKernelHint>, ShortWeierstrassCurve)> {
    if stage == degrees.len() {
        return Ok((Vec::new(), current));
    }

    let degree = degrees[stage];
    let candidates = bounded_exact_order_candidates(&current, degree, stage, context)?;
    if candidates.is_empty() {
        return Err(IdealToIsogenyError::KernelSearchFailed);
    }

    for (index, generator) in candidates.iter().copied().enumerate() {
        let isogeny = match VeluIsogeny::from_kernel(current, generator, degree) {
            Ok(isogeny) => isogeny,
            Err(_) => continue,
        };
        let codomain = *isogeny.codomain();
        if let Ok((mut tail, target)) =
            extract_bounded_actual_hints(codomain, degrees, context, stage + 1)
        {
            let mut hints = Vec::with_capacity(tail.len() + 1);
            hints.push(ActualKernelHint {
                degree: IsogenyInteger::from(degree),
                candidate_index: u16::try_from(index)
                    .map_err(|_| IdealToIsogenyError::UnsupportedActualDegree)?,
                stage_binding: expected_stage_hint_binding(
                    &current,
                    degree,
                    stage,
                    context.stage_bindings.get(stage).copied(),
                ),
                generator_commitment: point_commitment(&generator),
            });
            hints.append(&mut tail);
            return Ok((hints, target));
        }
    }

    Err(IdealToIsogenyError::KernelSearchFailed)
}

fn realize_bounded_actual_steps_from_hints(
    source: ShortWeierstrassCurve,
    degrees: &[usize],
    extraction: &ActualKernelExtraction,
    context: &ActualKernelSearchContext,
) -> Result<(Vec<ActualIsogenyStep>, ShortWeierstrassCurve)> {
    let mut current = source;
    let mut steps = Vec::with_capacity(extraction.hints.len());
    for (stage, (degree, hint)) in degrees
        .iter()
        .copied()
        .zip(extraction.hints.iter())
        .enumerate()
    {
        if hint.degree.try_to_usize() != Some(degree) {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let expected_stage_binding = expected_stage_hint_binding(
            &current,
            degree,
            stage,
            context.stage_bindings.get(stage).copied(),
        );
        if hint.stage_binding != expected_stage_binding {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let candidates = bounded_exact_order_candidates(&current, degree, stage, context)?;
        let index = usize::from(hint.candidate_index);
        if index >= candidates.len() {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let generator = candidates[index];
        if point_commitment(&generator) != hint.generator_commitment {
            return Err(IdealToIsogenyError::InvalidChain);
        }
        let isogeny = VeluIsogeny::from_kernel(current, generator, degree)?;
        let codomain = *isogeny.codomain();
        steps.push(ActualIsogenyStep {
            degree,
            domain: current,
            codomain,
            kernel_generator: generator,
        });
        current = codomain;
    }
    Ok((steps, current))
}

fn derive_small_stage_bindings(ideal: &LeftIdeal, degrees: &[usize]) -> Result<Vec<[u8; 32]>> {
    let degrees = degrees
        .iter()
        .copied()
        .map(IsogenyInteger::from)
        .collect::<Vec<_>>();
    IdealToIsogenyEngine::derive_stage_bindings(ideal, &degrees)
}

fn derive_small_stage_decomposition(
    ideal: &LeftIdeal,
    degrees: &[usize],
) -> Result<Vec<StageIdealDecomposition>> {
    let degrees = degrees
        .iter()
        .copied()
        .map(IsogenyInteger::from)
        .collect::<Vec<_>>();
    IdealToIsogenyEngine::derive_stage_decomposition(ideal, &degrees)
}

fn stage_candidate_start_index(
    stage: &StageIdealDecomposition,
    current: &ShortWeierstrassCurve,
    degree: usize,
    stage_index: usize,
    len: usize,
) -> usize {
    debug_assert!(len > 0);
    let payload = stage_candidate_selector_payload(stage, current, degree, stage_index);
    structured_index_from_payload(&payload, len, stage_index)
}

fn stage_candidate_selector_payload(
    stage: &StageIdealDecomposition,
    current: &ShortWeierstrassCurve,
    degree: usize,
    stage_index: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"AURORA:isogeny:actual-stage-kernel-selection:v2");
    append_stage_ideal_selector_payload(&mut out, &stage.input);
    append_stage_ideal_selector_payload(&mut out, &stage.principal);
    append_stage_ideal_selector_payload(&mut out, &stage.stage);
    append_stage_ideal_selector_payload(&mut out, &stage.next);
    out.extend_from_slice(&(degree as u64).to_be_bytes());
    out.extend_from_slice(&(stage_index as u64).to_be_bytes());
    append_curve_selector_payload(&mut out, current);
    out
}

fn append_stage_ideal_selector_payload(out: &mut Vec<u8>, ideal: &LeftIdeal) {
    out.extend_from_slice(&ideal.norm().to_be_bytes_fixed());
    for coeff in ideal.generator().coeffs() {
        let bytes = coeff.to_be_bytes();
        out.extend_from_slice(&bytes);
    }
    append_lattice_selector_payload(out, ideal.basis());
    append_lattice_selector_payload(out, ideal.left_order().basis());
    append_lattice_selector_payload(out, ideal.right_order().basis());
}

fn append_lattice_selector_payload(out: &mut Vec<u8>, basis: [QuaternionElement; 4]) {
    let lattice = BasisLattice::from_basis(basis)
        .expect("selector payload only uses canonicalizable quaternion lattices");
    for encoded_row in lattice.row_commitment_payload() {
        out.extend_from_slice(&encoded_row);
    }
}

fn append_curve_selector_payload(out: &mut Vec<u8>, curve: &ShortWeierstrassCurve) {
    append_fp2_selector_payload(out, &curve.a);
    append_fp2_selector_payload(out, &curve.b);
}

fn append_fp2_selector_payload(out: &mut Vec<u8>, value: &crate::crypto::isogeny::field::Fp2) {
    let c0 = value.c0.to_be_bytes();
    let c1 = value.c1.to_be_bytes();
    out.extend_from_slice(&(c0.len() as u32).to_be_bytes());
    out.extend_from_slice(&c0);
    out.extend_from_slice(&(c1.len() as u32).to_be_bytes());
    out.extend_from_slice(&c1);
}

fn structured_index_from_payload(payload: &[u8], len: usize, bias: usize) -> usize {
    debug_assert!(len > 0);
    let mut index = bias % len;
    for (offset, byte) in payload.iter().enumerate() {
        let weight = (offset % 251) + 1;
        index = (index * 257 + usize::from(*byte) + weight) % len;
    }
    index
}

fn curve_commitment(curve: &ShortWeierstrassCurve) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:isogeny:actual-kernel-curve:v1");
    update_curve_hash(&mut hasher, curve);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn expected_stage_hint_binding(
    curve: &ShortWeierstrassCurve,
    degree: usize,
    stage: usize,
    stage_binding: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:isogeny:actual-kernel-hint-stage:v1");
    hasher.update(curve_commitment(curve));
    hasher.update((degree as u64).to_be_bytes());
    hasher.update((stage as u64).to_be_bytes());
    if let Some(stage_binding) = stage_binding {
        hasher.update(stage_binding);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn derive_stage_principal_ideal(
    ideal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> Result<LeftIdeal> {
    let delta = derive_stage_delta(ideal, degree, stage);
    match ideal.generator().multiply(&delta) {
        Ok(product) if !product.is_zero() => {
            let basis = derive_principal_basis(ideal, &delta, &product, degree, stage)?;
            LeftIdeal::with_basis(
                ideal.left_order(),
                ideal.right_order(),
                product,
                degree,
                basis,
            )
            .map_err(Into::into)
        }
        Ok(_) | Err(QuaternionError::CoefficientOverflow) => {
            if let Some(candidate) =
                derive_structured_principal_ideal(ideal, &delta, degree, stage)?
            {
                Ok(candidate)
            } else {
                let generator = compose_stage_generator(
                    &ideal.generator(),
                    &delta,
                    b"AURORA:isogeny:stage-principal-product:v1",
                )?;
                let basis = derive_principal_basis(ideal, &delta, &generator, degree, stage)?;
                LeftIdeal::with_basis(
                    ideal.left_order(),
                    ideal.right_order(),
                    generator,
                    degree,
                    basis,
                )
                .map_err(Into::into)
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn derive_principal_basis(
    ideal: &LeftIdeal,
    delta: &QuaternionElement,
    generator: &QuaternionElement,
    degree: IsogenyInteger,
    stage: usize,
) -> Result<[QuaternionElement; 4]> {
    let basis = ideal.basis();
    let order_basis = ideal.left_order().basis();
    let mut candidates = [None; 32];
    let mut len = 0usize;

    push_unique_stage_basis_candidate(&mut candidates, &mut len, ideal.generator())?;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, *delta)?;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, *generator)?;

    for index in 0..4 {
        for candidate in [
            Some(basis[index]),
            basis[index].multiply(delta).ok(),
            basis[index].add(delta).ok(),
            basis[index].sub(delta).ok(),
            order_basis[index].multiply(generator).ok(),
        ]
        .into_iter()
        .flatten()
        {
            if !candidate.is_zero() {
                push_unique_stage_basis_candidate(&mut candidates, &mut len, candidate)?;
            }
        }
    }

    let mut selector = Vec::new();
    selector.extend_from_slice(b"AURORA:isogeny:principal-basis-selection:v1");
    selector.extend_from_slice(&ideal.norm().to_be_bytes_fixed());
    selector.extend_from_slice(&degree.to_be_bytes_fixed());
    selector.extend_from_slice(&(stage as u64).to_be_bytes());
    for coeff in delta.coeffs() {
        selector.extend_from_slice(&coeff.to_be_bytes());
    }
    for coeff in generator.coeffs() {
        selector.extend_from_slice(&coeff.to_be_bytes());
    }
    select_structured_stage_basis(
        ideal.generator().algebra(),
        &candidates,
        len,
        &selector,
        stage,
        &order_basis,
        generator,
    )
}

fn derive_stage_intersection_ideal(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> Result<LeftIdeal> {
    match current.intersect(principal) {
        Ok(stage_intersection) => LeftIdeal::with_basis(
            current.left_order(),
            current.right_order(),
            stage_intersection.generator(),
            degree,
            stage_intersection.basis(),
        )
        .map_err(Into::into),
        Err(IdealError::Quaternion(QuaternionError::CoefficientOverflow)) => {
            let stage_marker = derive_structured_stage_marker(
                current,
                principal,
                degree,
                stage,
                b"AURORA:isogeny:stage-intersection-marker:v1",
            )?;
            if let Some(candidate) = derive_structured_stage_intersection_ideal(
                current,
                principal,
                degree,
                stage,
                stage_marker,
            )? {
                Ok(candidate)
            } else {
                derive_fallback_stage_ideal(
                    current,
                    principal,
                    degree,
                    stage_marker,
                    b"AURORA:isogeny:stage-intersection-fallback:v1",
                )
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn derive_stage_transport_ideal(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    stage: usize,
) -> Result<LeftIdeal> {
    let transport = if stage & 1 == 0 {
        current.product(&principal.conjugate())
    } else {
        principal.conjugate().product(current)
    };
    match transport {
        Ok(transport) => LeftIdeal::with_basis(
            current.left_order(),
            current.right_order(),
            transport.generator(),
            current.norm(),
            transport.basis(),
        )
        .map_err(Into::into),
        Err(IdealError::Quaternion(QuaternionError::CoefficientOverflow)) => {
            let stage_marker = derive_structured_stage_marker(
                current,
                principal,
                current.norm(),
                stage,
                if stage & 1 == 0 {
                    b"AURORA:isogeny:stage-transport-even-marker:v1"
                } else {
                    b"AURORA:isogeny:stage-transport-odd-marker:v1"
                },
            )?;
            if let Some(candidate) =
                derive_structured_stage_transport_ideal(current, principal, stage, stage_marker)?
            {
                Ok(candidate)
            } else {
                derive_fallback_stage_ideal(
                    current,
                    principal,
                    current.norm(),
                    stage_marker,
                    if stage & 1 == 0 {
                        b"AURORA:isogeny:stage-transport-even-fallback:v1"
                    } else {
                        b"AURORA:isogeny:stage-transport-odd-fallback:v1"
                    },
                )
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn derive_fallback_stage_ideal(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    norm: IsogenyInteger,
    stage_marker: QuaternionElement,
    _domain: &[u8],
) -> Result<LeftIdeal> {
    if let Some(candidate) =
        derive_structured_fallback_stage_ideal(current, principal, norm, stage_marker)?
    {
        Ok(candidate)
    } else {
        let generator =
            derive_algebraic_stage_fallback_generator(current, principal, norm, stage_marker)?
                .expect("nonzero stage data always yields an algebraic fallback generator");
        let basis =
            derive_fallback_stage_basis(current, principal, &generator, norm, stage_marker)?;
        LeftIdeal::with_basis(
            current.left_order(),
            current.right_order(),
            generator,
            norm,
            basis,
        )
        .map_err(Into::into)
    }
}

fn compose_stage_generator(
    left: &QuaternionElement,
    right: &QuaternionElement,
    _domain: &[u8],
) -> Result<QuaternionElement> {
    match left.multiply(right) {
        Ok(product) if !product.is_zero() => Ok(product),
        Ok(_) | Err(QuaternionError::CoefficientOverflow) => {
            Ok(derive_algebraic_pair_fallback_generator(left, right)?
                .expect("nonzero pair always yields an algebraic fallback"))
        }
        Err(error) => Err(error.into()),
    }
}

fn candidate_from_quaternion_result(
    candidate: core::result::Result<QuaternionElement, QuaternionError>,
) -> Result<Option<QuaternionElement>> {
    match candidate {
        Ok(candidate) if !candidate.is_zero() => Ok(Some(candidate)),
        Ok(_) | Err(QuaternionError::CoefficientOverflow) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn derive_algebraic_pair_fallback_generator(
    left: &QuaternionElement,
    right: &QuaternionElement,
) -> Result<Option<QuaternionElement>> {
    for candidate in [
        candidate_from_quaternion_result(left.add(right))?,
        candidate_from_quaternion_result(left.sub(right))?,
        candidate_from_quaternion_result(right.sub(left))?,
        candidate_from_quaternion_result(left.conjugate().add(right))?,
        candidate_from_quaternion_result(left.add(&right.conjugate()))?,
        (!left.is_zero()).then_some(*left),
        (!right.is_zero()).then_some(*right),
    ]
    .into_iter()
    .flatten()
    {
        return Ok(Some(candidate));
    }
    Ok(None)
}

fn derive_stage_delta(
    ideal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> QuaternionElement {
    if let Ok(delta) = derive_basis_combination_delta(ideal, degree, stage) {
        if !delta.is_zero() {
            return delta;
        }
    }
    if let Ok(Some(delta)) = derive_algebraic_stage_delta(ideal, degree, stage) {
        return delta;
    }
    derive_folded_stage_delta(ideal, degree, stage)
}

fn derive_basis_combination_delta(
    ideal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> Result<QuaternionElement> {
    let bytes = degree.to_be_bytes_fixed();
    let basis = BasisLattice::from_basis(ideal.basis())
        .map(|lattice| lattice.basis())
        .map_err(IdealError::from)
        .map_err(IdealToIsogenyError::from)?;
    let order_basis = BasisLattice::from_basis(ideal.left_order().basis())
        .map(|lattice| lattice.basis())
        .map_err(IdealError::from)
        .map_err(IdealToIsogenyError::from)?;
    let mut acc = QuaternionElement::zero(ideal.generator().algebra());
    let mut used_nonzero = false;

    for (index, basis_element) in basis.iter().enumerate() {
        let byte = bytes[(stage + index) % bytes.len()];
        let mut coeff = i128::from(((byte >> 1) % 7) + 1);
        coeff *= i128::from(((stage + index) % 3 + 1) as u8);
        if (byte & 1) != 0 {
            coeff = -coeff;
        }
        let term = basis_element.scale(coeff)?;
        acc = acc.add(&term)?;
        used_nonzero |= !term.is_zero();
    }
    for (index, basis_element) in order_basis.iter().enumerate() {
        let byte = bytes[(stage + index + basis.len()) % bytes.len()];
        let coeff = if (byte & 1) != 0 { -1i128 } else { 1i128 };
        let term = basis_element.scale(coeff)?;
        acc = acc.add(&term)?;
        used_nonzero |= !term.is_zero();
    }

    if !used_nonzero || acc.is_zero() {
        let fallback = basis[stage % basis.len()]
            .add(&ideal.generator())
            .or_else(|_| basis[stage % basis.len()].sub(&ideal.generator()))?;
        return Ok(fallback);
    }

    Ok(acc)
}

fn derive_folded_stage_delta(
    ideal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> QuaternionElement {
    let payload = stage_delta_selector_payload(ideal, degree, stage);
    let bytes = degree.to_be_bytes_fixed();
    let basis_lattice = BasisLattice::from_basis(ideal.basis())
        .expect("stage delta selector only uses canonicalizable ideal bases");
    let order_lattice = BasisLattice::from_basis(ideal.left_order().basis())
        .expect("stage delta selector only uses canonicalizable order bases");
    let basis = basis_lattice.basis();
    let order_basis = order_lattice.basis();
    let mut candidates = [None; 64];
    let mut len = 0usize;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, ideal.generator())
        .expect("ideal generator is non-zero");
    for index in 0..4 {
        let next = (index + 1) % 4;
        let scale = structured_delta_scalar(&bytes, stage + index + 2);
        push_unique_stage_basis_candidate(&mut candidates, &mut len, basis[index])
            .expect("canonical lattice basis row is non-zero");
        push_unique_stage_basis_candidate(&mut candidates, &mut len, order_basis[index])
            .expect("canonical order basis row is non-zero");
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            basis[index].add(&ideal.generator()),
        )
        .expect("selector candidate generation only fails on algebra mismatch");
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            basis[index].sub(&ideal.generator()),
        )
        .expect("selector candidate generation only fails on algebra mismatch");
        push_stage_candidate_from_result(&mut candidates, &mut len, basis[index].add(&basis[next]))
            .expect("selector candidate generation only fails on algebra mismatch");
        push_stage_candidate_from_result(&mut candidates, &mut len, basis[index].sub(&basis[next]))
            .expect("selector candidate generation only fails on algebra mismatch");
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            basis[index].multiply(&order_basis[next]),
        )
        .expect("selector candidate generation only fails on algebra mismatch");
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            order_basis[index].multiply(&basis[next]),
        )
        .expect("selector candidate generation only fails on algebra mismatch");
        push_stage_candidate_from_result(&mut candidates, &mut len, basis[index].scale(scale))
            .expect("selector candidate generation only fails on algebra mismatch");
    }
    select_structured_stage_candidate(&candidates, len, &payload, stage)
        .unwrap_or(ideal.generator())
}

fn stage_delta_selector_payload(
    ideal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"AURORA:isogeny:ideal-stage-delta:v3");
    append_stage_ideal_selector_payload(&mut out, ideal);
    out.extend_from_slice(&(stage as u64).to_be_bytes());
    out.extend_from_slice(&degree.to_be_bytes_fixed());
    out
}

fn derive_algebraic_stage_delta(
    ideal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> Result<Option<QuaternionElement>> {
    let basis = BasisLattice::from_basis(ideal.basis())
        .map(|lattice| lattice.basis())
        .map_err(IdealError::from)
        .map_err(IdealToIsogenyError::from)?;
    let order_basis = BasisLattice::from_basis(ideal.left_order().basis())
        .map(|lattice| lattice.basis())
        .map_err(IdealError::from)
        .map_err(IdealToIsogenyError::from)?;
    let bytes = degree.to_be_bytes_fixed();
    let primary = stage % basis.len();
    let secondary = usize::from(bytes[stage % bytes.len()]) % basis.len();
    let tertiary = usize::from(bytes[(stage + 1) % bytes.len()]) % basis.len();
    let primary_scale = structured_delta_scalar(&bytes, stage);
    let secondary_scale = structured_delta_scalar(&bytes, stage + 1);

    let scaled_primary = basis[primary].scale(primary_scale);
    let scaled_secondary = basis[secondary].scale(secondary_scale);
    let scaled_combo = match (scaled_primary, scaled_secondary) {
        (Ok(lhs), Ok(rhs)) => lhs.add(&rhs),
        (Err(QuaternionError::CoefficientOverflow), _)
        | (_, Err(QuaternionError::CoefficientOverflow)) => {
            Err(QuaternionError::CoefficientOverflow)
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
    };

    let generator = ideal.generator();
    let mut candidates = [None; 64];
    let mut len = 0usize;
    for candidate in [
        (!basis[primary].is_zero()).then_some(basis[primary]),
        (!basis[secondary].is_zero()).then_some(basis[secondary]),
        (!order_basis[tertiary].is_zero()).then_some(order_basis[tertiary]),
        (!generator.is_zero()).then_some(generator),
        candidate_from_quaternion_result(basis[primary].multiply(&basis[secondary]))?,
        candidate_from_quaternion_result(basis[primary].multiply(&generator))?,
        candidate_from_quaternion_result(generator.multiply(&basis[secondary]))?,
        candidate_from_quaternion_result(order_basis[tertiary].multiply(&generator))?,
        candidate_from_quaternion_result(basis[primary].add(&order_basis[secondary]))?,
        candidate_from_quaternion_result(basis[secondary].sub(&order_basis[tertiary]))?,
        candidate_from_quaternion_result(order_basis[secondary].add(&generator))?,
        candidate_from_quaternion_result(order_basis[tertiary].sub(&generator))?,
        candidate_from_quaternion_result(scaled_combo)?,
        candidate_from_quaternion_result(
            basis[primary]
                .scale(primary_scale)
                .and_then(|term| term.add(&generator)),
        )?,
        candidate_from_quaternion_result(
            basis[secondary]
                .scale(secondary_scale)
                .and_then(|term| generator.sub(&term)),
        )?,
    ]
    .into_iter()
    .flatten()
    {
        push_unique_stage_basis_candidate(&mut candidates, &mut len, candidate)?;
    }
    let selector = stage_delta_selector_payload(ideal, degree, stage);
    Ok(select_structured_stage_candidate(
        &candidates,
        len,
        &selector,
        stage,
    ))
}

fn structured_delta_scalar(bytes: &[u8], index: usize) -> i128 {
    let byte = bytes[index % bytes.len()];
    let magnitude = i128::from((byte & 0x0f) + 1);
    if (byte & 0x80) != 0 {
        -magnitude
    } else {
        magnitude
    }
}

fn derive_algebraic_stage_fallback_generator(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    norm: IsogenyInteger,
    stage_marker: QuaternionElement,
) -> Result<Option<QuaternionElement>> {
    let (candidates, len) =
        collect_algebraic_stage_fallback_generator_candidates(current, principal, stage_marker)?;
    let selector = fallback_stage_selector_payload(current, principal, norm, &stage_marker);
    Ok(select_structured_stage_candidate(
        &candidates,
        len,
        &selector,
        usize::from(norm.to_be_bytes_fixed()[0]),
    ))
}

fn canonicalize_stage_basis_element(element: QuaternionElement) -> Result<QuaternionElement> {
    if element.is_zero() {
        return Err(IdealToIsogenyError::InvalidChain);
    }
    let coeffs = element.coeffs();
    let needs_negation = coeffs
        .iter()
        .copied()
        .find(|coeff| !coeff.is_zero())
        .is_some_and(|coeff| coeff.is_negative());
    if needs_negation {
        Ok(element.neg()?)
    } else {
        Ok(element)
    }
}

fn push_unique_stage_basis_candidate(
    candidates: &mut [Option<QuaternionElement>],
    len: &mut usize,
    candidate: QuaternionElement,
) -> Result<()> {
    let candidate = canonicalize_stage_basis_element(candidate)?;
    if candidates[..*len]
        .iter()
        .flatten()
        .any(|existing| existing == &candidate)
    {
        return Ok(());
    }
    if *len < candidates.len() {
        candidates[*len] = Some(candidate);
        *len += 1;
    }
    Ok(())
}

fn push_stage_candidate_from_result(
    candidates: &mut [Option<QuaternionElement>],
    len: &mut usize,
    candidate: core::result::Result<QuaternionElement, QuaternionError>,
) -> Result<()> {
    match candidate {
        Ok(candidate) if !candidate.is_zero() => {
            push_unique_stage_basis_candidate(candidates, len, candidate)
        }
        Ok(_) | Err(QuaternionError::CoefficientOverflow) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn select_structured_stage_candidate(
    candidates: &[Option<QuaternionElement>],
    len: usize,
    selector: &[u8],
    bias: usize,
) -> Option<QuaternionElement> {
    if len == 0 {
        return None;
    }
    let mut index = bias % len;
    for byte in selector {
        index = (index * 257 + usize::from(*byte) + 1) % len;
    }
    for offset in 0..len {
        if let Some(candidate) = candidates[(index + offset) % len] {
            return Some(candidate);
        }
    }
    None
}

fn derive_structured_principal_generator(
    ideal: &LeftIdeal,
    delta: &QuaternionElement,
    degree: IsogenyInteger,
    stage: usize,
) -> Result<Option<QuaternionElement>> {
    let (candidates, len) = collect_structured_principal_generator_candidates(ideal, delta)?;
    let selector = principal_selector_payload(ideal, delta, degree, stage);
    Ok(select_structured_stage_candidate(
        &candidates,
        len,
        &selector,
        stage,
    ))
}

fn derive_structured_principal_ideal(
    ideal: &LeftIdeal,
    delta: &QuaternionElement,
    degree: IsogenyInteger,
    stage: usize,
) -> Result<Option<LeftIdeal>> {
    let (candidates, len) = collect_structured_principal_generator_candidates(ideal, delta)?;
    if len == 0 {
        return Ok(None);
    }
    let selector = principal_selector_payload(ideal, delta, degree, stage);
    let start = structured_index_from_payload(&selector, len, stage);
    for offset in 0..len {
        let Some(generator) = candidates[(start + offset) % len] else {
            continue;
        };
        let basis = match derive_principal_basis(ideal, delta, &generator, degree, stage) {
            Ok(basis) => basis,
            Err(IdealToIsogenyError::InvalidChain)
            | Err(IdealToIsogenyError::Ideal(IdealError::ZeroBasisElement)) => continue,
            Err(error) => return Err(error),
        };
        if let Ok(candidate) = LeftIdeal::with_basis(
            ideal.left_order(),
            ideal.right_order(),
            generator,
            degree,
            basis,
        ) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn derive_structured_stage_intersection_ideal(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
    stage_marker: QuaternionElement,
) -> Result<Option<LeftIdeal>> {
    let current_variants =
        collect_stage_variant_ideals(current, principal, current.norm(), stage_marker)?;
    let principal_variants =
        collect_stage_variant_ideals(principal, current, principal.norm(), stage_marker)?;
    if current_variants.is_empty() || principal_variants.is_empty() {
        return Ok(None);
    }

    let selector = stage_operation_selector_payload(
        b"AURORA:isogeny:stage-intersection-selection:v1",
        current,
        principal,
        degree,
        stage,
    );
    let total = current_variants
        .len()
        .checked_mul(principal_variants.len())
        .ok_or(IdealToIsogenyError::UnsupportedActualDegree)?;
    let start = structured_index_from_payload(&selector, total, stage);
    for offset in 0..total {
        let index = (start + offset) % total;
        let lhs = current_variants[index % current_variants.len()];
        let rhs = principal_variants[(index / current_variants.len()) % principal_variants.len()];
        let Ok(stage_intersection) = lhs.intersect(&rhs) else {
            continue;
        };
        if let Ok(candidate) = LeftIdeal::with_basis(
            current.left_order(),
            current.right_order(),
            stage_intersection.generator(),
            degree,
            stage_intersection.basis(),
        ) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn collect_structured_principal_generator_candidates(
    ideal: &LeftIdeal,
    delta: &QuaternionElement,
) -> Result<([Option<QuaternionElement>; 64], usize)> {
    let basis = ideal.basis();
    let order_basis = ideal.left_order().basis();
    let generator = ideal.generator();
    let mut candidates = [None; 64];
    let mut len = 0usize;

    push_unique_stage_basis_candidate(&mut candidates, &mut len, generator)?;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, *delta)?;

    for index in 0..4 {
        let next = (index + 1) % basis.len();
        push_stage_candidate_from_result(&mut candidates, &mut len, basis[index].multiply(delta))?;
        push_stage_candidate_from_result(&mut candidates, &mut len, delta.multiply(&basis[index]))?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            basis[index].multiply(&generator),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            generator.multiply(&basis[index]),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            order_basis[index].multiply(delta),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            order_basis[index].multiply(&generator),
        )?;
        push_stage_candidate_from_result(&mut candidates, &mut len, basis[index].add(delta))?;
        push_stage_candidate_from_result(&mut candidates, &mut len, basis[index].sub(delta))?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            basis[index].multiply(&basis[next]),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            basis[index].add(&basis[next]),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            basis[index].sub(&basis[next]),
        )?;
    }

    Ok((candidates, len))
}

fn collect_stage_variant_ideals(
    base: &LeftIdeal,
    peer: &LeftIdeal,
    norm: IsogenyInteger,
    stage_marker: QuaternionElement,
) -> Result<Vec<LeftIdeal>> {
    let mut candidates = Vec::with_capacity(24);
    push_unique_stage_ideal_candidate(&mut candidates, *base);
    if let Ok(intersection) = base.intersect(peer) {
        push_unique_stage_ideal_candidate(&mut candidates, intersection);
    }

    let (generator_candidates, generator_len) =
        collect_algebraic_stage_fallback_generator_candidates(base, peer, stage_marker)?;
    for generator in generator_candidates[..generator_len]
        .iter()
        .flatten()
        .copied()
    {
        let basis = match derive_fallback_stage_basis(base, peer, &generator, norm, stage_marker) {
            Ok(basis) => basis,
            Err(IdealToIsogenyError::InvalidChain)
            | Err(IdealToIsogenyError::Ideal(IdealError::ZeroBasisElement)) => continue,
            Err(error) => return Err(error),
        };
        if let Ok(candidate) = LeftIdeal::with_basis(
            base.left_order(),
            base.right_order(),
            generator,
            norm,
            basis,
        ) {
            push_unique_stage_ideal_candidate(&mut candidates, candidate);
        }
    }

    Ok(candidates)
}

fn push_unique_stage_ideal_candidate(candidates: &mut Vec<LeftIdeal>, candidate: LeftIdeal) {
    if candidates.iter().any(|existing| existing == &candidate) {
        return;
    }
    if candidates.len() < candidates.capacity() {
        candidates.push(candidate);
    }
}

fn principal_selector_payload(
    ideal: &LeftIdeal,
    delta: &QuaternionElement,
    degree: IsogenyInteger,
    stage: usize,
) -> Vec<u8> {
    let mut selector = Vec::new();
    selector.extend_from_slice(b"AURORA:isogeny:structured-principal-selection:v1");
    append_stage_ideal_selector_payload(&mut selector, ideal);
    selector.extend_from_slice(&degree.to_be_bytes_fixed());
    selector.extend_from_slice(&(stage as u64).to_be_bytes());
    for coeff in delta.coeffs() {
        let bytes = coeff.to_be_bytes();
        selector.extend_from_slice(&bytes);
    }
    selector
}

fn stage_marker_selector_payload(
    domain: &[u8],
    current: &LeftIdeal,
    principal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> Vec<u8> {
    let mut selector = Vec::new();
    selector.extend_from_slice(domain);
    append_stage_ideal_selector_payload(&mut selector, current);
    append_stage_ideal_selector_payload(&mut selector, principal);
    selector.extend_from_slice(&degree.to_be_bytes_fixed());
    selector.extend_from_slice(&(stage as u64).to_be_bytes());
    selector
}

fn stage_operation_selector_payload(
    domain: &[u8],
    current: &LeftIdeal,
    principal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
) -> Vec<u8> {
    let mut selector = Vec::new();
    selector.extend_from_slice(domain);
    append_stage_ideal_selector_payload(&mut selector, current);
    append_stage_ideal_selector_payload(&mut selector, principal);
    selector.extend_from_slice(&degree.to_be_bytes_fixed());
    selector.extend_from_slice(&(stage as u64).to_be_bytes());
    selector
}

fn derive_fallback_stage_basis(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    generator: &QuaternionElement,
    norm: IsogenyInteger,
    stage_marker: QuaternionElement,
) -> Result<[QuaternionElement; 4]> {
    let current_basis = current.basis();
    let principal_basis = principal.basis();
    let order_basis = current.left_order().basis();
    let mut candidates = [None; 64];
    let mut len = 0usize;

    for index in 0..4 {
        let next = (index + 1) % current_basis.len();
        for candidate in [
            current_basis[index],
            principal_basis[index],
            current_basis[index]
                .add(&principal_basis[index])
                .unwrap_or(order_basis[index]),
            current_basis[index]
                .sub(&principal_basis[index])
                .unwrap_or(order_basis[index]),
            current_basis[index]
                .add(&stage_marker)
                .unwrap_or(order_basis[index]),
            principal_basis[index]
                .sub(&stage_marker)
                .unwrap_or(order_basis[index]),
        ] {
            if !candidate.is_zero() {
                push_unique_stage_basis_candidate(&mut candidates, &mut len, candidate)?;
            }
        }
        for candidate in [
            current_basis[index].multiply(&principal_basis[next]),
            principal_basis[index].multiply(&current_basis[next]),
            current_basis[index].multiply(generator),
            principal_basis[index].multiply(generator),
            current_basis[index].multiply(&stage_marker),
            principal_basis[index].multiply(&stage_marker),
        ] {
            push_stage_candidate_from_result(&mut candidates, &mut len, candidate)?;
        }
    }

    push_unique_stage_basis_candidate(&mut candidates, &mut len, current.generator())?;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, principal.generator())?;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, stage_marker)?;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, *generator)?;

    let mut selector = Vec::new();
    selector.extend_from_slice(b"AURORA:isogeny:fallback-basis-selection:v1");
    selector.extend_from_slice(&norm.to_be_bytes_fixed());
    for coeff in stage_marker.coeffs() {
        selector.extend_from_slice(&coeff.to_be_bytes());
    }
    for coeff in generator.coeffs() {
        selector.extend_from_slice(&coeff.to_be_bytes());
    }
    select_structured_stage_basis(
        current.generator().algebra(),
        &candidates,
        len,
        &selector,
        usize::from(norm.to_be_bytes_fixed()[0]),
        &order_basis,
        generator,
    )
}

fn select_structured_stage_basis(
    algebra: crate::crypto::isogeny::ideal::quaternion::QuaternionAlgebra,
    candidates: &[Option<QuaternionElement>],
    len: usize,
    selector: &[u8],
    bias: usize,
    order_basis: &[QuaternionElement; 4],
    generator: &QuaternionElement,
) -> Result<[QuaternionElement; 4]> {
    let mut basis = [QuaternionElement::zero(algebra); 4];
    let mut basis_len = 0usize;

    if len > 0 {
        let start = structured_index_from_payload(selector, len, bias);
        for offset in 0..len {
            if basis_len == basis.len() {
                break;
            }
            if let Some(candidate) = candidates[(start + offset) % len] {
                if basis[..basis_len]
                    .iter()
                    .any(|existing| existing == &candidate)
                {
                    continue;
                }
                basis[basis_len] = candidate;
                basis_len += 1;
            }
        }
    }

    let mut fallback_index = 0usize;
    while basis_len < basis.len() {
        let candidate = order_basis[fallback_index]
            .multiply(generator)
            .ok()
            .filter(|candidate| !candidate.is_zero())
            .unwrap_or(order_basis[fallback_index]);
        let candidate = canonicalize_stage_basis_element(candidate)?;
        fallback_index += 1;
        if basis[..basis_len]
            .iter()
            .any(|existing| existing == &candidate)
        {
            continue;
        }
        basis[basis_len] = candidate;
        basis_len += 1;
    }

    Ok(basis)
}

fn derive_structured_fallback_stage_ideal(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    norm: IsogenyInteger,
    stage_marker: QuaternionElement,
) -> Result<Option<LeftIdeal>> {
    let (candidates, len) =
        collect_algebraic_stage_fallback_generator_candidates(current, principal, stage_marker)?;
    if len == 0 {
        return Ok(None);
    }
    let selector = fallback_stage_selector_payload(current, principal, norm, &stage_marker);
    let start =
        structured_index_from_payload(&selector, len, usize::from(norm.to_be_bytes_fixed()[0]));
    for offset in 0..len {
        let Some(generator) = candidates[(start + offset) % len] else {
            continue;
        };
        let basis =
            match derive_fallback_stage_basis(current, principal, &generator, norm, stage_marker) {
                Ok(basis) => basis,
                Err(IdealToIsogenyError::InvalidChain)
                | Err(IdealToIsogenyError::Ideal(IdealError::ZeroBasisElement)) => continue,
                Err(error) => return Err(error),
            };
        if let Ok(candidate) = LeftIdeal::with_basis(
            current.left_order(),
            current.right_order(),
            generator,
            norm,
            basis,
        ) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn derive_structured_stage_transport_ideal(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    stage: usize,
    stage_marker: QuaternionElement,
) -> Result<Option<LeftIdeal>> {
    let current_variants =
        collect_stage_variant_ideals(current, principal, current.norm(), stage_marker)?;
    let principal_variants =
        collect_stage_variant_ideals(principal, current, principal.norm(), stage_marker)?;
    if current_variants.is_empty() || principal_variants.is_empty() {
        return Ok(None);
    }

    let selector = stage_operation_selector_payload(
        if stage & 1 == 0 {
            b"AURORA:isogeny:stage-transport-even-selection:v1"
        } else {
            b"AURORA:isogeny:stage-transport-odd-selection:v1"
        },
        current,
        principal,
        current.norm(),
        stage,
    );
    let total = current_variants
        .len()
        .checked_mul(principal_variants.len())
        .ok_or(IdealToIsogenyError::UnsupportedActualDegree)?;
    let start = structured_index_from_payload(&selector, total, stage);
    for offset in 0..total {
        let index = (start + offset) % total;
        let lhs = current_variants[index % current_variants.len()];
        let rhs = principal_variants[(index / current_variants.len()) % principal_variants.len()];
        let transport = if stage & 1 == 0 {
            lhs.product(&rhs.conjugate())
        } else {
            rhs.conjugate().product(&lhs)
        };
        let Ok(transport) = transport else {
            continue;
        };
        if let Ok(candidate) = LeftIdeal::with_basis(
            current.left_order(),
            current.right_order(),
            transport.generator(),
            current.norm(),
            transport.basis(),
        ) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn derive_structured_stage_marker(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    degree: IsogenyInteger,
    stage: usize,
    domain: &[u8],
) -> Result<QuaternionElement> {
    let mut candidates = [None; 96];
    let mut len = 0usize;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, current.generator())?;
    push_unique_stage_basis_candidate(&mut candidates, &mut len, principal.generator())?;
    for index in 0..4 {
        let next = (index + 1) % 4;
        push_unique_stage_basis_candidate(&mut candidates, &mut len, current.basis()[index])?;
        push_unique_stage_basis_candidate(&mut candidates, &mut len, principal.basis()[index])?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            current.basis()[index].add(&principal.basis()[index]),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            current.basis()[index].sub(&principal.basis()[index]),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            current.basis()[index].multiply(&principal.basis()[next]),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            principal.basis()[index].multiply(&current.basis()[next]),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            current.basis()[index].multiply(&principal.generator()),
        )?;
        push_stage_candidate_from_result(
            &mut candidates,
            &mut len,
            principal.basis()[index].multiply(&current.generator()),
        )?;
    }
    let selector = stage_marker_selector_payload(domain, current, principal, degree, stage);
    Ok(
        select_structured_stage_candidate(&candidates, len, &selector, stage)
            .or_else(|| {
                derive_algebraic_pair_fallback_generator(
                    &current.generator(),
                    &principal.generator(),
                )
                .ok()
                .flatten()
            })
            .unwrap_or(current.generator()),
    )
}

fn collect_algebraic_stage_fallback_generator_candidates(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    stage_marker: QuaternionElement,
) -> Result<([Option<QuaternionElement>; 64], usize)> {
    let current_basis = BasisLattice::from_basis(current.basis())
        .map_err(IdealError::from)?
        .basis();
    let principal_basis = BasisLattice::from_basis(principal.basis())
        .map_err(IdealError::from)?
        .basis();
    let current_order_basis = BasisLattice::from_basis(current.left_order().basis())
        .map_err(IdealError::from)?
        .basis();
    let principal_order_basis = BasisLattice::from_basis(principal.left_order().basis())
        .map_err(IdealError::from)?
        .basis();
    let mut candidates = [None; 64];
    let mut len = 0usize;

    for candidate in [current.generator(), principal.generator(), stage_marker] {
        push_unique_stage_basis_candidate(&mut candidates, &mut len, candidate)?;
    }

    if let Some(candidate) =
        derive_algebraic_pair_fallback_generator(&current.generator(), &principal.generator())?
    {
        push_unique_stage_basis_candidate(&mut candidates, &mut len, candidate)?;
    }

    for index in 0..4 {
        let next = (index + 1) % current_basis.len();
        for candidate in [
            current_basis[index].add(&principal_basis[index]),
            current_basis[index].sub(&principal_basis[index]),
            current_basis[index].multiply(&principal_basis[index]),
            current_basis[index].multiply(&principal_basis[next]),
            principal_basis[index].multiply(&current_basis[next]),
            current_basis[index].multiply(&stage_marker),
            principal_basis[index].multiply(&stage_marker),
            current_order_basis[index].multiply(&principal_basis[next]),
            principal_order_basis[index].multiply(&current_basis[next]),
            current_basis[index].multiply(&principal_order_basis[index]),
            principal_basis[index].multiply(&current_order_basis[index]),
            current_order_basis[index].multiply(&stage_marker),
            principal_order_basis[index].multiply(&stage_marker),
            current_basis[index].add(&stage_marker),
            principal_basis[index].sub(&stage_marker),
            current_order_basis[index].add(&stage_marker),
            principal_order_basis[index].sub(&stage_marker),
            current.generator().add(&stage_marker),
            principal.generator().sub(&stage_marker),
        ] {
            push_stage_candidate_from_result(&mut candidates, &mut len, candidate)?;
        }
        for candidate in [
            current_basis[index],
            principal_basis[index],
            current_order_basis[index],
            principal_order_basis[index],
        ] {
            if !candidate.is_zero() {
                push_unique_stage_basis_candidate(&mut candidates, &mut len, candidate)?;
            }
        }
    }

    Ok((candidates, len))
}

fn fallback_stage_selector_payload(
    current: &LeftIdeal,
    principal: &LeftIdeal,
    norm: IsogenyInteger,
    stage_marker: &QuaternionElement,
) -> Vec<u8> {
    let mut selector = Vec::new();
    selector.extend_from_slice(b"AURORA:isogeny:stage-fallback-selection:v1");
    append_stage_ideal_selector_payload(&mut selector, current);
    append_stage_ideal_selector_payload(&mut selector, principal);
    selector.extend_from_slice(&norm.to_be_bytes_fixed());
    for coeff in stage_marker.coeffs() {
        selector.extend_from_slice(&coeff.to_be_bytes());
    }
    selector
}

fn stage_ideal_binding(stage_ideal: &LeftIdeal, stage: usize) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:isogeny:ideal-stage-binding:v1");
    hasher.update((stage as u64).to_be_bytes());
    hasher.update(stage_ideal.norm().to_be_bytes_fixed());
    for coeff in stage_ideal.generator().coeffs() {
        hasher.update(coeff.to_be_bytes());
    }
    for basis_element in stage_ideal.basis() {
        for coeff in basis_element.coeffs() {
            hasher.update(coeff.to_be_bytes());
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn bounded_exact_order_candidates(
    curve: &ShortWeierstrassCurve,
    degree: usize,
    stage: usize,
    context: &ActualKernelSearchContext,
) -> Result<Vec<CurvePoint>> {
    if degree < 2 {
        return Err(IdealToIsogenyError::UnsupportedActualDegree);
    }
    let degree_u64 =
        u64::try_from(degree).map_err(|_| IdealToIsogenyError::UnsupportedActualDegree)?;
    let mut candidates = Vec::new();
    if context.use_base_two_torsion && stage == 0 && degree == 2 {
        if let Some(point) = base_two_torsion_candidate(curve)? {
            candidates.push(point);
        }
    }

    let start = bounded_search_start(curve, stage, degree_u64, context);
    for x_offset in 0..BOUNDED_SEARCH_X_BOUND {
        for x1 in 0..BOUNDED_SEARCH_Y_BOUND {
            let x = crate::crypto::isogeny::field::Fp2::new(
                crate::crypto::isogeny::field::Fp::from_u64(
                    curve.modulus(),
                    start.wrapping_add(x_offset),
                ),
                crate::crypto::isogeny::field::Fp::from_u64(curve.modulus(), x1),
            )
            .expect("constructed from same modulus");
            let rhs = curve.rhs(&x)?;
            if let Some(y) = rhs.sqrt() {
                for y in [y, y.neg()] {
                    let point = CurvePoint::affine(x, y);
                    curve.validate_point(&point)?;
                    let projected = project_point_to_order(
                        curve,
                        &point,
                        degree_u64,
                        context.cofactor,
                        usize::from(context.two_torsion_bits),
                    )?;
                    if has_exact_order_u64(curve, &projected, degree_u64)?
                        && !candidates.contains(&projected)
                    {
                        candidates.push(projected);
                    }
                }
            }
        }
    }

    Ok(candidates)
}

fn base_two_torsion_candidate(curve: &ShortWeierstrassCurve) -> Result<Option<CurvePoint>> {
    let point = CurvePoint::affine(
        crate::crypto::isogeny::field::Fp2::zero(curve.modulus()),
        crate::crypto::isogeny::field::Fp2::zero(curve.modulus()),
    );
    if curve.validate_point(&point).is_err() {
        return Ok(None);
    }
    if curve.scalar_mul_u64(&point, 2)? == curve.identity() {
        Ok(Some(point))
    } else {
        Ok(None)
    }
}

fn bounded_search_start(
    curve: &ShortWeierstrassCurve,
    stage: usize,
    degree: u64,
    context: &ActualKernelSearchContext,
) -> u64 {
    let payload = bounded_search_selector_payload(curve, stage, degree, context);
    structured_u64_from_payload(&payload, degree ^ ((stage as u64) << 32))
}

fn bounded_search_selector_payload(
    curve: &ShortWeierstrassCurve,
    stage: usize,
    degree: u64,
    context: &ActualKernelSearchContext,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"AURORA:isogeny:bounded-kernel-search:v2");
    out.extend_from_slice(&context.seed);
    out.extend_from_slice(&context.binding);
    out.extend_from_slice(&(stage as u64).to_be_bytes());
    out.extend_from_slice(&degree.to_be_bytes());
    out.extend_from_slice(&u64::from(context.cofactor).to_be_bytes());
    out.extend_from_slice(&(context.two_torsion_bits as u64).to_be_bytes());
    out.push(u8::from(context.use_base_two_torsion));
    if let Some(stage_binding) = context.stage_bindings.get(stage) {
        out.push(1);
        out.extend_from_slice(stage_binding);
    } else {
        out.push(0);
    }
    append_curve_selector_payload(&mut out, curve);
    out
}

fn structured_u64_from_payload(payload: &[u8], bias: u64) -> u64 {
    let mut value = bias ^ ((payload.len() as u64) << 32) ^ 0x9E37_79B9_7F4A_7C15;
    for (offset, byte) in payload.iter().enumerate() {
        let weight = ((offset % 251) + 1) as u64;
        value = value
            .wrapping_mul(257)
            .wrapping_add(u64::from(*byte).wrapping_add(weight));
    }
    value
}

fn project_point_to_order(
    curve: &ShortWeierstrassCurve,
    point: &CurvePoint,
    degree: u64,
    cofactor: u32,
    two_torsion_bits: usize,
) -> Result<CurvePoint> {
    let odd_multiplier = if degree & 1 == 0 {
        1
    } else {
        u64::from(cofactor) / degree
    };
    let two_bits = if degree & 1 == 0 {
        two_torsion_bits.saturating_sub(1)
    } else {
        two_torsion_bits
    };
    let mut projected = mul_point_by_pow2(curve, point, two_bits)?;
    if odd_multiplier > 1 {
        projected = curve.scalar_mul_u64(&projected, odd_multiplier)?;
    }
    if degree & 1 == 0 {
        projected = curve.scalar_mul_u64(&projected, u64::from(cofactor))?;
    }
    Ok(projected)
}

fn mul_point_by_pow2(
    curve: &ShortWeierstrassCurve,
    point: &CurvePoint,
    bits: usize,
) -> Result<CurvePoint> {
    let mut acc = *point;
    for _ in 0..bits {
        acc = curve.double(&acc)?;
    }
    Ok(acc)
}

fn has_exact_order_u64(
    curve: &ShortWeierstrassCurve,
    point: &CurvePoint,
    degree: u64,
) -> Result<bool> {
    if point.is_infinity() {
        return Ok(false);
    }
    if curve.scalar_mul_u64(point, degree)? != curve.identity() {
        return Ok(false);
    }
    for prime in prime_divisors_u64(degree) {
        if curve.scalar_mul_u64(point, degree / prime)? == curve.identity() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn prime_divisors_u64(mut value: u64) -> Vec<u64> {
    let mut divisors = Vec::new();
    let mut divisor = 2u64;
    while divisor * divisor <= value {
        if value % divisor == 0 {
            divisors.push(divisor);
            while value % divisor == 0 {
                value /= divisor;
            }
        }
        divisor += if divisor == 2 { 1 } else { 2 };
    }
    if value > 1 {
        divisors.push(value);
    }
    divisors
}

fn exact_order_points(curve: &ShortWeierstrassCurve, degree: usize) -> Result<Vec<CurvePoint>> {
    if degree < 2 {
        return Err(IdealToIsogenyError::UnsupportedActualDegree);
    }
    let degree_u64 =
        u64::try_from(degree).map_err(|_| IdealToIsogenyError::UnsupportedActualDegree)?;
    let points = enumerate_curve_points(curve)?;
    Ok(points
        .into_iter()
        .filter(|point| {
            !point.is_infinity()
                && curve.scalar_mul_u64(point, degree_u64).ok() == Some(curve.identity())
                && prime_divisors_usize(degree).into_iter().all(|prime| {
                    curve.scalar_mul_u64(point, (degree / prime) as u64).ok()
                        != Some(curve.identity())
                })
        })
        .collect())
}

fn point_commitment(point: &CurvePoint) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:isogeny:actual-kernel-point:v1");
    update_point_hash(&mut hasher, point);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn enumerate_curve_points(curve: &ShortWeierstrassCurve) -> Result<Vec<CurvePoint>> {
    let prime = curve
        .modulus()
        .to_u64()
        .filter(|prime| *prime <= ACTUAL_ENUMERATION_BOUND)
        .ok_or(IdealToIsogenyError::ActualEnumerationUnsupported)?;
    let mut points = Vec::new();
    for x0 in 0..prime {
        for x1 in 0..prime {
            let x = crate::crypto::isogeny::field::Fp2::new(
                crate::crypto::isogeny::field::Fp::from_u64(curve.modulus(), x0),
                crate::crypto::isogeny::field::Fp::from_u64(curve.modulus(), x1),
            )
            .map_err(WeierstrassError::from)?;
            if let Some(y) = curve.rhs(&x)?.sqrt() {
                let point = CurvePoint::affine(x, y);
                if curve.is_on_curve(&point)? {
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

fn prime_divisors_usize(mut value: usize) -> Vec<usize> {
    let mut divisors = Vec::new();
    let mut divisor = 2usize;
    while divisor * divisor <= value {
        if value % divisor == 0 {
            divisors.push(divisor);
            while value % divisor == 0 {
                value /= divisor;
            }
        }
        divisor += if divisor == 2 { 1 } else { 2 };
    }
    if value > 1 {
        divisors.push(value);
    }
    divisors
}

fn derive_curve_descriptor(codomain_tag: &[u8; 32]) -> ReferenceCurveDescriptor {
    let hint_hash = hash32(b"AURORA:isogeny:reference:curve-hint:v1", codomain_tag, &[]);
    let mut hint = [0u8; 16];
    hint.copy_from_slice(&hint_hash[..16]);
    ReferenceCurveDescriptor {
        tag: *codomain_tag,
        hint,
    }
}

fn derive_basis_descriptor(
    codomain_tag: &[u8; 32],
    torsion_power: u16,
) -> ReferenceBasisDescriptor {
    let p_tag = hash32(
        b"AURORA:isogeny:reference:basis-p:v1",
        codomain_tag,
        &torsion_power.to_be_bytes(),
    );
    let q_tag = hash32(
        b"AURORA:isogeny:reference:basis-q:v1",
        codomain_tag,
        &torsion_power.to_be_bytes(),
    );
    let hint_hash = hash32(
        b"AURORA:isogeny:reference:basis-hint:v1",
        codomain_tag,
        &torsion_power.to_be_bytes(),
    );
    ReferenceBasisDescriptor {
        p_tag,
        q_tag,
        power: torsion_power,
        hint: u16::from_be_bytes([hint_hash[0], hint_hash[1]]),
    }
}

fn hash32(domain: &[u8], primary: &[u8; 32], suffix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(primary);
    hasher.update((suffix.len() as u32).to_be_bytes());
    hasher.update(suffix);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn derive_isogeny_chain(
    ideal: &LeftIdeal,
    codomain: &ReferenceCurveDescriptor,
    qlapoti_plan: &QlapotiPlan,
) -> ReferenceIsogenyChain {
    if qlapoti_plan.steps.is_empty() {
        return ReferenceIsogenyChain {
            source: *codomain,
            target: *codomain,
            steps: Vec::new(),
        };
    }

    let source_tag = hash32(
        b"AURORA:isogeny:reference:chain-source:v1",
        &codomain.tag,
        &ideal.norm().to_be_bytes_fixed(),
    );
    let source = derive_curve_descriptor(&source_tag);
    let mut current = source;
    let mut steps = Vec::with_capacity(qlapoti_plan.steps.len());

    for (index, step) in qlapoti_plan.steps.iter().enumerate() {
        let payload = step_payload(index, step.degree, step.prime, step.exponent);
        let target = if index + 1 == qlapoti_plan.steps.len() {
            *codomain
        } else {
            let target_tag = hash32(
                b"AURORA:isogeny:reference:chain-target:v1",
                &current.tag,
                &payload,
            );
            derive_curve_descriptor(&target_tag)
        };
        let kernel = ReferenceKernelDescriptor {
            tag: hash32(
                b"AURORA:isogeny:reference:chain-kernel:v1",
                &current.tag,
                &payload,
            ),
            degree: step.degree,
        };
        steps.push(ReferenceIsogenyStep {
            source: current,
            target,
            kernel,
            degree: step.degree,
            strategy: step.strategy,
        });
        current = target;
    }

    ReferenceIsogenyChain {
        source,
        target: *codomain,
        steps,
    }
}

fn step_payload(
    index: usize,
    degree: IsogenyInteger,
    prime: IsogenyInteger,
    exponent: u32,
) -> [u8; 204] {
    let mut out = [0u8; 204];
    out[..8].copy_from_slice(&(index as u64).to_be_bytes());
    out[8..8 + IsogenyInteger::BYTES].copy_from_slice(&degree.to_be_bytes_fixed());
    out[8 + IsogenyInteger::BYTES..8 + (2 * IsogenyInteger::BYTES)]
        .copy_from_slice(&prime.to_be_bytes_fixed());
    out[8 + (2 * IsogenyInteger::BYTES)..].copy_from_slice(&exponent.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::{ActualKernelSearchContext, IdealToIsogenyEngine, IdealToIsogenyError};
    use crate::crypto::isogeny::arith::{IsogenyInteger, QuaternionInteger};
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::curve::weierstrass::{
        MontgomeryIsomorphism, ShortWeierstrassCurve,
    };
    use crate::crypto::isogeny::field::{Fp2, FpModulus};
    use crate::crypto::isogeny::ideal::ideal::{IdealError, LeftIdeal};
    use crate::crypto::isogeny::ideal::order::MaximalOrder;
    use crate::crypto::isogeny::ideal::quaternion::{
        QuaternionAlgebra, QuaternionElement, QuaternionError,
    };
    use crate::crypto::isogeny::params::SupersingularParameters;

    fn enumerate_points(
        curve: &crate::crypto::isogeny::curve::weierstrass::ShortWeierstrassCurve,
        prime: u64,
    ) -> Vec<CurvePoint> {
        let mut points = Vec::new();
        for x in 0..prime {
            let x = Fp2::from_u64(curve.modulus(), x);
            if let Some(y) = curve.rhs(&x).unwrap().sqrt() {
                let point = CurvePoint::affine(x, y);
                if curve.is_on_curve(&point).unwrap() {
                    points.push(point);
                    let neg = point.negate();
                    if neg != point {
                        points.push(neg);
                    }
                }
            }
        }
        points
    }

    fn point_of_order(
        curve: &crate::crypto::isogeny::curve::weierstrass::ShortWeierstrassCurve,
        prime: u64,
        order: u64,
    ) -> CurvePoint {
        enumerate_points(curve, prime)
            .into_iter()
            .find(|point| {
                !point.is_infinity()
                    && curve.scalar_mul_u64(point, order).unwrap() == curve.identity()
                    && (1..order).all(|scalar| {
                        curve.scalar_mul_u64(point, scalar).unwrap() != curve.identity()
                    })
            })
            .expect("expected point of requested order")
    }

    fn bounded_test_context(
        params: SupersingularParameters,
        degrees: &[IsogenyInteger],
        binding: [u8; 32],
    ) -> (ShortWeierstrassCurve, ActualKernelSearchContext) {
        let source =
            ShortWeierstrassCurve::new(Fp2::one(&params.modulus), Fp2::zero(&params.modulus))
                .unwrap();
        for counter in 0..256u64 {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&counter.to_be_bytes());
            let context = ActualKernelSearchContext {
                seed,
                binding,
                stage_bindings: Vec::new(),
                cofactor: params.cofactor,
                two_torsion_bits: u16::try_from(params.two_torsion_bits).unwrap(),
                use_base_two_torsion: true,
            };
            if IdealToIsogenyEngine::extract_bounded_kernel_hints(source, degrees, &context).is_ok()
            {
                return (source, context);
            }
        }
        panic!("expected bounded-search context for degrees {degrees:?}");
    }

    fn wide_coeff(bit: usize) -> QuaternionInteger {
        let mut bytes = vec![0u8; QuaternionInteger::BYTES];
        let byte_from_end = bit / 8;
        let bit_offset = bit % 8;
        let index = QuaternionInteger::BYTES - 1 - byte_from_end;
        bytes[index] = 1u8 << bit_offset;
        QuaternionInteger::from_be_slice(&bytes).unwrap()
    }

    #[test]
    fn translation_is_deterministic_and_degree_preserving() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [2, 1, -1, 3]),
            45,
        )
        .unwrap();

        let first = IdealToIsogenyEngine::translate(&ideal, 192).unwrap();
        let second = IdealToIsogenyEngine::translate(&ideal, 192).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.degree, IsogenyInteger::from(45u64));
        assert_eq!(first.qlapoti_plan.total_degree, IsogenyInteger::from(45u64));
        assert_eq!(first.torsion_basis.power, 192);
        assert_eq!(first.chain.target, first.codomain);
        assert_eq!(first.chain.steps.len(), first.qlapoti_plan.steps.len());
    }

    #[test]
    fn translation_changes_when_generator_changes() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(7).unwrap());
        let i1 = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 0]),
            17,
        )
        .unwrap();
        let i2 = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 0, 1, 0]),
            17,
        )
        .unwrap();

        let iso1 = IdealToIsogenyEngine::translate(&i1, 128).unwrap();
        let iso2 = IdealToIsogenyEngine::translate(&i2, 128).unwrap();
        assert_ne!(iso1.codomain.tag, iso2.codomain.tag);
        assert_ne!(iso1.torsion_basis.p_tag, iso2.torsion_basis.p_tag);
    }

    #[test]
    fn translation_rejects_oversized_torsion_power() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(7).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 0]),
            17,
        )
        .unwrap();
        assert_eq!(
            IdealToIsogenyEngine::translate(&ideal, usize::from(u16::MAX) + 1),
            Err(IdealToIsogenyError::InvalidTorsionPower)
        );
    }

    #[test]
    fn basis_commitment_is_stable() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [2, 3, 1, 0]),
            29,
        )
        .unwrap();
        let iso = IdealToIsogenyEngine::translate(&ideal, 64).unwrap();
        assert_eq!(
            iso.torsion_basis.commitment(),
            iso.torsion_basis.commitment()
        );
    }

    #[test]
    fn chain_links_steps_into_final_codomain() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]),
            72,
        )
        .unwrap();
        let iso = IdealToIsogenyEngine::translate(&ideal, 32).unwrap();
        assert_eq!(iso.chain.steps.first().unwrap().source, iso.chain.source);
        assert_eq!(iso.chain.steps.last().unwrap().target, iso.codomain);
        assert_eq!(iso.chain.steps[0].degree, IsogenyInteger::from(8u64));
        assert_eq!(iso.chain.steps[1].degree, IsogenyInteger::from(9u64));
    }

    #[test]
    fn realizes_small_odd_chain_via_velu() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let generator = {
            let mut found = None;
            for x in 0..19u64 {
                let point = crate::crypto::isogeny::curve::point::CurvePoint::affine(
                    Fp2::from_u64(&modulus, x),
                    Fp2::from_u64(&modulus, 0),
                );
                if !curve.is_on_curve(&point).unwrap() || point.is_infinity() {
                    continue;
                }
                if curve.scalar_mul_u64(&point, 3).unwrap() == curve.identity() {
                    found = Some(point);
                    break;
                }
            }
            found.unwrap_or_else(|| {
                for x in 0..19u64 {
                    let rhs = curve.rhs(&Fp2::from_u64(&modulus, x)).unwrap();
                    if let Some(y) = rhs.sqrt() {
                        let point = crate::crypto::isogeny::curve::point::CurvePoint::affine(
                            Fp2::from_u64(&modulus, x),
                            y,
                        );
                        if !point.is_infinity()
                            && curve.scalar_mul_u64(&point, 3).unwrap() == curve.identity()
                            && curve.scalar_mul_u64(&point, 1).unwrap() != curve.identity()
                        {
                            return point;
                        }
                    }
                }
                panic!("expected point of order 3")
            })
        };

        let chain =
            IdealToIsogenyEngine::realize_small_odd_chain(curve, &[(generator, 3)]).unwrap();
        assert_eq!(chain.source, curve);
        assert_eq!(chain.steps.len(), 1);
        assert_eq!(chain.steps[0].degree, 3);
        assert_eq!(chain.steps[0].domain, curve);
        assert_eq!(chain.steps[0].codomain, chain.target);
    }

    #[test]
    fn actual_chain_maps_points_by_composing_steps() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let order3 = point_of_order(&curve, 19, 3);
        let first = IdealToIsogenyEngine::realize_small_chain(curve, &[(order3, 3)]).unwrap();
        let order2 = point_of_order(&first.target, 19, 2);
        let chain =
            IdealToIsogenyEngine::realize_small_chain(curve, &[(order3, 3), (order2, 2)]).unwrap();
        let point = enumerate_points(&curve, 19)
            .into_iter()
            .find(|candidate| {
                !candidate.is_infinity() && *candidate != order3 && *candidate != order2
            })
            .unwrap();

        let image = chain.map_point(&point).unwrap();
        assert!(chain.target.is_on_curve(&image).unwrap());

        let first_step = chain.steps[0].map_point(&point).unwrap();
        let second_step = chain.steps[1].map_point(&first_step).unwrap();
        assert_eq!(image, second_step);
    }

    #[test]
    fn actual_chain_commitment_changes_with_kernel() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();

        let order3 = point_of_order(&curve, 19, 3);
        let order2 = point_of_order(&curve, 19, 2);
        let left = IdealToIsogenyEngine::realize_small_chain(curve, &[(order3, 3)]).unwrap();
        let right = IdealToIsogenyEngine::realize_small_chain(curve, &[(order2, 2)]).unwrap();
        assert_ne!(left.commitment(), right.commitment());
    }

    #[test]
    fn realizes_two_power_plan_as_degree_two_chain() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 0, 1]),
            8,
        )
        .unwrap();
        let chain =
            IdealToIsogenyEngine::realize_small_qlapoti_chain_with_curve_search(&ideal).unwrap();
        let curve = chain.source;
        assert_eq!(chain.source, curve);
        assert_eq!(chain.steps.len(), 3);
        assert!(chain.steps.iter().all(|step| step.degree == 2));
    }

    #[test]
    fn realizes_mixed_two_and_odd_prime_power_plan() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]),
            18,
        )
        .unwrap();
        let chain =
            IdealToIsogenyEngine::realize_small_qlapoti_chain_with_curve_search(&ideal).unwrap();
        let curve = chain.source;
        assert_eq!(chain.source, curve);
        assert_eq!(chain.steps.len(), 2);
        assert_eq!(chain.steps[0].degree, 2);
        assert_eq!(chain.steps[1].degree, 9);
    }

    #[test]
    fn actual_kernel_extraction_roundtrip_recovers_chain() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]),
            18,
        )
        .unwrap();
        let source = IdealToIsogenyEngine::find_small_qlapoti_curve(&ideal).unwrap();
        let extraction = IdealToIsogenyEngine::extract_small_kernel_hints(source, &ideal).unwrap();
        let extracted = IdealToIsogenyEngine::realize_small_qlapoti_chain_from_hints(
            source,
            &ideal,
            &extraction,
        )
        .unwrap();
        let direct = IdealToIsogenyEngine::realize_small_qlapoti_chain(source, &ideal).unwrap();

        assert_eq!(extracted.commitment(), direct.commitment());
        assert_eq!(extraction.hints.len(), direct.steps.len());
    }

    #[test]
    fn actual_kernel_extraction_rejects_tampered_hint() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 0, 1]),
            8,
        )
        .unwrap();
        let source = IdealToIsogenyEngine::find_small_qlapoti_curve(&ideal).unwrap();
        let mut extraction =
            IdealToIsogenyEngine::extract_small_kernel_hints(source, &ideal).unwrap();
        extraction.hints[0].generator_commitment[0] ^= 1;
        assert_eq!(
            IdealToIsogenyEngine::realize_small_qlapoti_chain_from_hints(
                source,
                &ideal,
                &extraction,
            ),
            Err(IdealToIsogenyError::InvalidChain)
        );
    }

    #[test]
    fn actual_kernel_extraction_rejects_tampered_stage_binding() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 0, 1]),
            8,
        )
        .unwrap();
        let source = IdealToIsogenyEngine::find_small_qlapoti_curve(&ideal).unwrap();
        let mut extraction =
            IdealToIsogenyEngine::extract_small_kernel_hints(source, &ideal).unwrap();
        extraction.hints[0].stage_binding[0] ^= 1;
        assert_eq!(
            IdealToIsogenyEngine::realize_small_qlapoti_chain_from_hints(
                source,
                &ideal,
                &extraction,
            ),
            Err(IdealToIsogenyError::InvalidChain)
        );
    }

    #[test]
    fn curve_search_supports_extended_odd_prime_norms() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        for norm in [5u128, 7u128] {
            let ideal = LeftIdeal::new(
                order,
                order,
                QuaternionElement::from_coeffs(order.algebra(), [norm as i128, 1, 0, 1]),
                norm,
            )
            .unwrap();
            let chain = IdealToIsogenyEngine::realize_small_qlapoti_chain_with_curve_search(&ideal)
                .unwrap();
            assert_eq!(
                chain
                    .steps
                    .iter()
                    .fold(1u128, |acc, step| acc * step.degree as u128),
                norm
            );
        }
    }

    #[test]
    fn stage_bindings_are_deterministic_and_degree_sensitive() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]),
            45,
        )
        .unwrap();
        let first = IdealToIsogenyEngine::derive_stage_bindings(
            &ideal,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();
        let second = IdealToIsogenyEngine::derive_stage_bindings(
            &ideal,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();
        let swapped = IdealToIsogenyEngine::derive_stage_bindings(
            &ideal,
            &[IsogenyInteger::from(3u64), IsogenyInteger::from(5u64)],
        )
        .unwrap();

        assert_eq!(first, second);
        assert_ne!(first, swapped);
        assert_eq!(first.len(), 2);
    }

    #[test]
    fn stage_ideals_preserve_requested_norms_and_depend_on_generator() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let left = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]),
            45,
        )
        .unwrap();
        let right = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 3, 0, 1]),
            45,
        )
        .unwrap();

        let left_stages = IdealToIsogenyEngine::derive_stage_ideals(
            &left,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();
        let right_stages = IdealToIsogenyEngine::derive_stage_ideals(
            &right,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();

        assert_eq!(
            left_stages.iter().map(LeftIdeal::norm).collect::<Vec<_>>(),
            vec![IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)]
        );
        assert_eq!(
            right_stages.iter().map(LeftIdeal::norm).collect::<Vec<_>>(),
            vec![IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)]
        );
        assert_ne!(left_stages[0].generator(), right_stages[0].generator());
    }

    #[test]
    fn stage_decomposition_replays_from_principal_ideals() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]),
            45,
        )
        .unwrap();

        let derived = IdealToIsogenyEngine::derive_stage_decomposition(
            &ideal,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();
        let principals = derived
            .iter()
            .map(|stage| stage.principal)
            .collect::<Vec<_>>();
        let replayed = IdealToIsogenyEngine::replay_stage_decomposition_from_principals(
            &ideal,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
            &principals,
        )
        .unwrap();

        assert_eq!(derived, replayed);
        assert_eq!(derived[0].principal.norm(), IsogenyInteger::from(5u64));
        assert_eq!(derived[1].principal.norm(), IsogenyInteger::from(3u64));
        assert_eq!(derived[0].stage.norm(), IsogenyInteger::from(5u64));
        assert_eq!(derived[1].stage.norm(), IsogenyInteger::from(3u64));
    }

    #[test]
    fn stage_decomposition_uses_actual_intersection_and_transport() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]),
            45,
        )
        .unwrap();

        let derived = IdealToIsogenyEngine::derive_stage_decomposition(
            &ideal,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();

        let first_intersection = derived[0].input.intersect(&derived[0].principal).unwrap();
        let first_transport = derived[0]
            .input
            .product(&derived[0].principal.conjugate())
            .unwrap();
        assert_eq!(derived[0].stage.generator(), first_intersection.generator());
        assert_eq!(derived[0].stage.basis(), first_intersection.basis());
        assert_eq!(derived[0].next.generator(), first_transport.generator());
        assert_eq!(derived[0].next.basis(), first_transport.basis());
        assert_eq!(derived[0].next.norm(), derived[0].input.norm());

        let second_intersection = derived[1].input.intersect(&derived[1].principal).unwrap();
        let second_transport = derived[1]
            .principal
            .conjugate()
            .product(&derived[1].input)
            .unwrap();
        assert_eq!(
            derived[1].stage.generator(),
            second_intersection.generator()
        );
        assert_eq!(derived[1].stage.basis(), second_intersection.basis());
        assert_eq!(derived[1].next.generator(), second_transport.generator());
        assert_eq!(derived[1].next.basis(), second_transport.basis());
        assert_eq!(derived[1].next.norm(), derived[1].input.norm());
    }

    #[test]
    fn stage_decomposition_depends_on_explicit_basis() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let generator = QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]);
        let canonical = LeftIdeal::new(order, order, generator, 45).unwrap();
        let alternate = LeftIdeal::with_basis(
            order,
            order,
            generator,
            45,
            [
                QuaternionElement::from_coeffs(order.algebra(), [7, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 7, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 7, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 0, 7]),
            ],
        )
        .unwrap();

        let canonical_stages = IdealToIsogenyEngine::derive_stage_decomposition(
            &canonical,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();
        let alternate_stages = IdealToIsogenyEngine::derive_stage_decomposition(
            &alternate,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();

        assert_ne!(
            canonical_stages[0].principal.generator(),
            alternate_stages[0].principal.generator()
        );
        assert_ne!(
            canonical_stages[0].principal.basis(),
            alternate_stages[0].principal.basis()
        );
    }

    #[test]
    fn stage_candidate_selector_payload_depends_on_explicit_basis() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let generator = QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]);
        let canonical = LeftIdeal::new(order, order, generator, 45).unwrap();
        let alternate = LeftIdeal::with_basis(
            order,
            order,
            generator,
            45,
            [
                QuaternionElement::from_coeffs(order.algebra(), [7, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 7, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 7, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 0, 7]),
            ],
        )
        .unwrap();

        let canonical_stages = IdealToIsogenyEngine::derive_stage_decomposition(
            &canonical,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();
        let alternate_stages = IdealToIsogenyEngine::derive_stage_decomposition(
            &alternate,
            &[IsogenyInteger::from(5u64), IsogenyInteger::from(3u64)],
        )
        .unwrap();
        let modulus = FpModulus::from_u64(order.algebra().ramified_prime() as u64).unwrap();
        let curve = ShortWeierstrassCurve::new(Fp2::one(&modulus), Fp2::zero(&modulus)).unwrap();

        let canonical_payload =
            super::stage_candidate_selector_payload(&canonical_stages[0], &curve, 5, 0);
        let alternate_payload =
            super::stage_candidate_selector_payload(&alternate_stages[0], &curve, 5, 0);
        assert_ne!(canonical_payload, alternate_payload);
    }

    #[test]
    fn stage_delta_selector_payload_depends_on_explicit_basis() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let generator = QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]);
        let canonical = LeftIdeal::new(order, order, generator, 45).unwrap();
        let alternate = LeftIdeal::with_basis(
            order,
            order,
            generator,
            45,
            [
                QuaternionElement::from_coeffs(order.algebra(), [7, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 7, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 7, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 0, 7]),
            ],
        )
        .unwrap();
        let degree = IsogenyInteger::from(5u64);

        let canonical_payload = super::stage_delta_selector_payload(&canonical, degree, 1);
        let alternate_payload = super::stage_delta_selector_payload(&alternate, degree, 1);
        assert_ne!(canonical_payload, alternate_payload);
    }

    #[test]
    fn fallback_stage_ideal_depends_on_explicit_basis() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let current = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [5, 1, 0, 1]),
            45,
        )
        .unwrap();
        let principal_generator = QuaternionElement::from_coeffs(order.algebra(), [2, 1, 1, 0]);
        let canonical_principal =
            LeftIdeal::with_basis(order, order, principal_generator, 5, current.basis()).unwrap();
        let alternate_principal = LeftIdeal::with_basis(
            order,
            order,
            principal_generator,
            5,
            [
                QuaternionElement::from_coeffs(order.algebra(), [9, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 9, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 9, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 0, 9]),
            ],
        )
        .unwrap();
        let marker = QuaternionElement::from_coeffs(order.algebra(), [7, 2, 0, 0]);

        let canonical = super::derive_fallback_stage_ideal(
            &current,
            &canonical_principal,
            IsogenyInteger::from(5u64),
            marker,
            b"AURORA:test:stage-fallback:v1",
        )
        .unwrap();
        let alternate = super::derive_fallback_stage_ideal(
            &current,
            &alternate_principal,
            IsogenyInteger::from(5u64),
            marker,
            b"AURORA:test:stage-fallback:v1",
        )
        .unwrap();

        assert_eq!(canonical.norm(), IsogenyInteger::from(5u64));
        assert_eq!(alternate.norm(), IsogenyInteger::from(5u64));
        assert_ne!(canonical.basis(), alternate.basis());
        assert!(canonical
            .basis()
            .iter()
            .all(|basis: &QuaternionElement| !basis.is_zero()));
        assert!(alternate
            .basis()
            .iter()
            .all(|basis: &QuaternionElement| !basis.is_zero()));
    }

    #[test]
    fn structured_stage_marker_depends_on_explicit_basis() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let current = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [5, 1, 0, 1]),
            45,
        )
        .unwrap();
        let principal_generator = QuaternionElement::from_coeffs(order.algebra(), [2, 1, 1, 0]);
        let canonical_principal =
            LeftIdeal::with_basis(order, order, principal_generator, 5, current.basis()).unwrap();
        let alternate_principal = LeftIdeal::with_basis(
            order,
            order,
            principal_generator,
            5,
            [
                QuaternionElement::from_coeffs(order.algebra(), [9, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 9, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 9, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 0, 9]),
            ],
        )
        .unwrap();

        let canonical = super::derive_structured_stage_marker(
            &current,
            &canonical_principal,
            IsogenyInteger::from(5u64),
            1,
            b"AURORA:test:stage-marker:v1",
        )
        .unwrap();
        let alternate = super::derive_structured_stage_marker(
            &current,
            &alternate_principal,
            IsogenyInteger::from(5u64),
            1,
            b"AURORA:test:stage-marker:v1",
        )
        .unwrap();

        assert_ne!(canonical, alternate);
    }

    #[test]
    fn compose_stage_generator_prefers_product_when_wide_coefficients_fit() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let left = QuaternionElement::from_coeffs(algebra, [1i128 << 100, 0, 0, 0]);
        let right = QuaternionElement::from_coeffs(algebra, [1i128 << 40, 1, 0, 0]);

        let expected = left.multiply(&right).unwrap();
        let actual = super::compose_stage_generator(
            &left,
            &right,
            b"AURORA:test:compose-stage-generator:v1",
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn structured_principal_generator_handles_product_overflow() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(
                order.algebra(),
                [
                    wide_coeff(2047),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                ],
            ),
            45,
            [
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
                QuaternionElement::one(order.algebra()),
            ],
        )
        .unwrap();
        let delta = QuaternionElement::from_coeffs(
            order.algebra(),
            [
                wide_coeff(2047),
                QuaternionInteger::from(1i32),
                QuaternionInteger::zero(),
                QuaternionInteger::zero(),
            ],
        );
        let degree = IsogenyInteger::from_be_slice(&[0x5a; IsogenyInteger::BYTES]).unwrap();

        assert!(matches!(
            ideal.generator().multiply(&delta),
            Err(QuaternionError::CoefficientOverflow)
        ));
        let generator = super::derive_structured_principal_generator(&ideal, &delta, degree, 2)
            .unwrap()
            .expect("expected structured principal candidate");
        assert!(!generator.is_zero());
    }

    #[test]
    fn structured_principal_ideal_handles_product_overflow() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(
                order.algebra(),
                [
                    wide_coeff(2047),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                ],
            ),
            45,
            [
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
                QuaternionElement::one(order.algebra()),
            ],
        )
        .unwrap();
        let degree = IsogenyInteger::from(5u64);

        let principal = super::derive_stage_principal_ideal(&ideal, degree, 2).unwrap();
        assert_eq!(principal.norm(), degree);
        assert!(principal.basis().iter().all(|basis| !basis.is_zero()));
    }

    #[test]
    fn structured_stage_intersection_handles_generator_overflow() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let current = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(
                order.algebra(),
                [
                    wide_coeff(2047),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                ],
            ),
            45,
            [
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
                QuaternionElement::one(order.algebra()),
            ],
        )
        .unwrap();
        let principal = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(
                order.algebra(),
                [
                    wide_coeff(2047),
                    QuaternionInteger::from(1i32),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                ],
            ),
            5,
            [
                QuaternionElement::one(order.algebra()),
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
            ],
        )
        .unwrap();

        assert!(matches!(
            current.intersect(&principal),
            Err(IdealError::Quaternion(QuaternionError::CoefficientOverflow))
        ));
        let stage = super::derive_stage_intersection_ideal(
            &current,
            &principal,
            IsogenyInteger::from(5u64),
            1,
        )
        .unwrap();
        assert_eq!(stage.norm(), IsogenyInteger::from(5u64));
        assert!(stage.basis().iter().all(|basis| !basis.is_zero()));
    }

    #[test]
    fn structured_stage_transport_handles_generator_overflow() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let current = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(
                order.algebra(),
                [
                    wide_coeff(2047),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                ],
            ),
            45,
            [
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
                QuaternionElement::one(order.algebra()),
            ],
        )
        .unwrap();
        let principal = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(
                order.algebra(),
                [
                    wide_coeff(2047),
                    QuaternionInteger::from(1i32),
                    QuaternionInteger::zero(),
                    QuaternionInteger::zero(),
                ],
            ),
            5,
            [
                QuaternionElement::one(order.algebra()),
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
            ],
        )
        .unwrap();

        assert!(matches!(
            current.product(&principal.conjugate()),
            Err(IdealError::Quaternion(QuaternionError::CoefficientOverflow))
        ));
        let next = super::derive_stage_transport_ideal(&current, &principal, 0).unwrap();
        assert_eq!(next.norm(), current.norm());
        assert!(next.basis().iter().all(|basis| !basis.is_zero()));
    }

    #[test]
    fn stage_variant_collection_includes_actual_intersections() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let current = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 0, 0]),
            15,
            [
                QuaternionElement::one(order.algebra()),
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
            ],
        )
        .unwrap();
        let principal = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [2, 1, 1, 0]),
            5,
            [
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
                QuaternionElement::one(order.algebra()),
            ],
        )
        .unwrap();
        let stage_marker = QuaternionElement::basis_i(order.algebra());

        let variants =
            super::collect_stage_variant_ideals(&current, &principal, current.norm(), stage_marker)
                .unwrap();
        let direct_intersection = current.intersect(&principal).unwrap();

        assert!(variants.contains(&current));
        assert!(variants.contains(&direct_intersection));
    }

    #[test]
    fn structured_stage_basis_selection_depends_on_selector_payload() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let order_basis = MaximalOrder::reference(algebra).basis();
        let generator = QuaternionElement::from_coeffs(algebra, [3, 1, 1, 1]);
        let candidates = [
            Some(QuaternionElement::one(algebra)),
            Some(QuaternionElement::basis_i(algebra)),
            Some(QuaternionElement::basis_j(algebra)),
            Some(QuaternionElement::basis_k(algebra)),
            Some(QuaternionElement::from_coeffs(algebra, [7, 0, 0, 0])),
            Some(QuaternionElement::from_coeffs(algebra, [0, 7, 0, 0])),
            None,
            None,
        ];

        let first = super::select_structured_stage_basis(
            algebra,
            &candidates,
            6,
            b"AURORA:test:stage-basis-selector:first",
            0,
            &order_basis,
            &generator,
        )
        .unwrap();
        let second = super::select_structured_stage_basis(
            algebra,
            &candidates,
            6,
            b"AURORA:test:stage-basis-selector:second",
            0,
            &order_basis,
            &generator,
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn stage_delta_uses_structured_algebraic_fallback_before_selector_fallback() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [3, 1, 1, 1]),
            45,
            [
                QuaternionElement::from_coeffs(
                    order.algebra(),
                    [
                        wide_coeff(2047),
                        QuaternionInteger::zero(),
                        QuaternionInteger::zero(),
                        QuaternionInteger::zero(),
                    ],
                ),
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
            ],
        )
        .unwrap();
        let degree = IsogenyInteger::from_be_slice(&[0xff; IsogenyInteger::BYTES]).unwrap();

        assert!(super::derive_basis_combination_delta(&ideal, degree, 0).is_err());
        let delta = super::derive_algebraic_stage_delta(&ideal, degree, 0)
            .unwrap()
            .expect("expected algebraic delta");
        let folded = super::derive_folded_stage_delta(&ideal, degree, 0);

        assert!(!delta.is_zero());
        assert!(!folded.is_zero());
    }

    #[test]
    fn bounded_kernel_extraction_roundtrip_recovers_large_field_chain() {
        let params = SupersingularParameters::new(5, 8);
        let degrees = [IsogenyInteger::from(2u64), IsogenyInteger::from(5u64)];
        let (source, context) = bounded_test_context(params, &degrees, [0xA5; 32]);
        let extraction =
            IdealToIsogenyEngine::extract_bounded_kernel_hints(source, &degrees, &context).unwrap();
        let extracted = IdealToIsogenyEngine::realize_bounded_chain_from_hints(
            source,
            &degrees,
            &context,
            &extraction,
        )
        .unwrap();
        let direct =
            IdealToIsogenyEngine::realize_bounded_chain(source, &degrees, &context).unwrap();

        assert_eq!(extracted.commitment(), direct.commitment());
        assert_eq!(extraction.hints.len(), degrees.len());
    }

    #[test]
    fn bounded_kernel_extraction_rejects_tampered_large_field_hint() {
        let params = SupersingularParameters::new(5, 8);
        let degrees = [IsogenyInteger::from(2u64), IsogenyInteger::from(5u64)];
        let (source, context) = bounded_test_context(params, &degrees, [0x5A; 32]);
        let mut extraction =
            IdealToIsogenyEngine::extract_bounded_kernel_hints(source, &degrees, &context).unwrap();
        extraction.hints[1].generator_commitment[0] ^= 1;
        assert_eq!(
            IdealToIsogenyEngine::realize_bounded_chain_from_hints(
                source,
                &degrees,
                &context,
                &extraction,
            ),
            Err(IdealToIsogenyError::InvalidChain)
        );
    }

    #[test]
    fn bounded_kernel_extraction_rejects_tampered_stage_binding() {
        let params = SupersingularParameters::new(5, 8);
        let degrees = [IsogenyInteger::from(2u64), IsogenyInteger::from(5u64)];
        let (source, context) = bounded_test_context(params, &degrees, [0x3C; 32]);
        let mut extraction =
            IdealToIsogenyEngine::extract_bounded_kernel_hints(source, &degrees, &context).unwrap();
        extraction.hints[1].stage_binding[0] ^= 1;
        assert_eq!(
            IdealToIsogenyEngine::realize_bounded_chain_from_hints(
                source,
                &degrees,
                &context,
                &extraction,
            ),
            Err(IdealToIsogenyError::InvalidChain)
        );
    }

    #[test]
    fn bounded_search_selector_payload_depends_on_binding_stage_and_curve() {
        let params = SupersingularParameters::new(5, 8);
        let degrees = [IsogenyInteger::from(2u64), IsogenyInteger::from(5u64)];
        let (source, mut context) = bounded_test_context(params, &degrees, [0x11; 32]);
        context.stage_bindings = vec![[0x22; 32], [0x33; 32]];

        let original = super::bounded_search_selector_payload(&source, 1, 5, &context);

        let mut different_binding = context.clone();
        different_binding.binding[0] ^= 1;
        assert_ne!(
            original,
            super::bounded_search_selector_payload(&source, 1, 5, &different_binding)
        );

        let mut different_stage_binding = context.clone();
        different_stage_binding.stage_bindings[1][0] ^= 1;
        assert_ne!(
            original,
            super::bounded_search_selector_payload(&source, 1, 5, &different_stage_binding)
        );

        let shifted_curve =
            ShortWeierstrassCurve::new(source.a, Fp2::one(source.modulus())).unwrap();
        assert_ne!(
            original,
            super::bounded_search_selector_payload(&shifted_curve, 1, 5, &context)
        );
    }

    #[test]
    fn bounded_search_start_is_deterministic_and_binding_sensitive() {
        let params = SupersingularParameters::new(5, 8);
        let degrees = [IsogenyInteger::from(2u64), IsogenyInteger::from(5u64)];
        let (source, mut context) = bounded_test_context(params, &degrees, [0x44; 32]);
        context.stage_bindings = vec![[0x55; 32], [0x66; 32]];

        let first = super::bounded_search_start(&source, 1, 5, &context);
        let second = super::bounded_search_start(&source, 1, 5, &context);
        assert_eq!(first, second);

        let mut different_context = context.clone();
        different_context.stage_bindings[1][0] ^= 1;
        assert_ne!(
            first,
            super::bounded_search_start(&source, 1, 5, &different_context)
        );
    }

    #[test]
    fn rejects_large_composite_actual_translation() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 0, 1, 1]),
            (1u128 << 80) + 7,
        )
        .unwrap();
        let modulus = FpModulus::from_u64(19).unwrap();
        let montgomery = MontgomeryCurve::new(Fp2::from_u64(&modulus, 5)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let curve = *iso.weierstrass_curve();
        assert_eq!(
            IdealToIsogenyEngine::realize_small_qlapoti_chain(curve, &ideal),
            Err(IdealToIsogenyError::UnsupportedActualDegree)
        );
    }
}
