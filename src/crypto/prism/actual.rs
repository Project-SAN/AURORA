//! Canonical PRISM backend that requires encoded actual witnesses.

use alloc::{vec, vec::Vec};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Sha3_256};

use super::backend::PrismBackend;
use super::encoding::SignatureEncoding;
use super::params::SaltPrismParameters;
use super::reference::{
    qlapoti_step_hint_commitment, ReferenceActualWitness, ReferenceIdealTrace,
    ReferencePrismBackend, ReferencePrismError, ReferenceSignatureBody, ReferenceSigningKey,
    ReferenceVerifyingKey,
};
use super::types::ChallengePrime;
use crate::crypto::isogeny::algorithms::{
    ActualIsogenyChain, ActualKernelSearchContext, ActualProductIsogeny,
    ActualProductIsogenyWitnessData, IdealToIsogenyEngine, IdealToIsogenyError, KaniEngine,
    KaniError, QlapotiEngine, QlapotiPlan, QlapotiStrategy, RandomIdealError, RandomIdealSampler,
    VeluError,
};
use crate::crypto::isogeny::arith::IsogenyInteger;
use crate::crypto::isogeny::curve::weierstrass::{ShortWeierstrassCurve, WeierstrassError};
use crate::crypto::isogeny::field::Fp2;
use crate::crypto::isogeny::ideal::{MaximalOrder, QuaternionAlgebra};

const SMALL_MODEL_SUPPORTED_DEGREES: [IsogenyInteger; 7] = [
    IsogenyInteger::from_u64(2),
    IsogenyInteger::from_u64(3),
    IsogenyInteger::from_u64(4),
    IsogenyInteger::from_u64(5),
    IsogenyInteger::from_u64(7),
    IsogenyInteger::from_u64(8),
    IsogenyInteger::from_u64(9),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActualPrismError {
    Reference(ReferencePrismError),
    MissingActualWitness,
}

impl From<ReferencePrismError> for ActualPrismError {
    fn from(value: ReferencePrismError) -> Self {
        Self::Reference(value)
    }
}

impl From<KaniError> for ActualPrismError {
    fn from(value: KaniError) -> Self {
        Self::Reference(ReferencePrismError::from(value))
    }
}

pub trait ActualWitnessProvider {
    fn prepare_signature(
        &self,
        _params: &'static SaltPrismParameters,
        _verifying_key: &ReferenceVerifyingKey,
        _challenge: &ChallengePrime,
        _signature: &mut ReferenceSignatureBody,
    ) -> core::result::Result<(), ActualPrismError> {
        Ok(())
    }

    fn derive_witness(
        &self,
        params: &'static SaltPrismParameters,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> core::result::Result<ReferenceActualWitness, ActualPrismError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActualWitnessSide {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualChainRequest {
    pub side: ActualWitnessSide,
    pub seed: [u8; 32],
    pub total_degree: IsogenyInteger,
    pub selected_degree: IsogenyInteger,
    pub selected_degrees: Vec<IsogenyInteger>,
    pub qlapoti_plan: QlapotiPlan,
    pub ideal_trace: Option<ReferenceIdealTrace>,
    pub stage_traces: Vec<ReferenceIdealTrace>,
    pub stage_principal_traces: Vec<ReferenceIdealTrace>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualWitnessRequest {
    pub left: ActualChainRequest,
    pub right: ActualChainRequest,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallModelActualWitnessProvider;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BaseCurveTwoIsogenyActualWitnessProvider;

impl SmallModelActualWitnessProvider {
    pub const fn new() -> Self {
        Self
    }

    fn reference_order(
        &self,
        params: &'static SaltPrismParameters,
    ) -> core::result::Result<MaximalOrder, ActualPrismError> {
        let algebra =
            QuaternionAlgebra::new(params.base.cofactor).map_err(ReferencePrismError::from)?;
        Ok(MaximalOrder::reference(algebra))
    }

    fn seed(
        &self,
        domain: &[u8],
        primary: &[u8; 32],
        secondary: &[u8; 32],
        challenge: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(domain);
        hasher.update(primary);
        hasher.update(secondary);
        hasher.update((challenge.len() as u32).to_be_bytes());
        hasher.update(challenge);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn norm(&self, seed: &[u8; 32]) -> IsogenyInteger {
        let index = usize::from(seed[0]) % SMALL_MODEL_SUPPORTED_DEGREES.len();
        SMALL_MODEL_SUPPORTED_DEGREES[index]
    }

    fn supported_degrees_from_plan(&self, plan: &QlapotiPlan) -> Vec<IsogenyInteger> {
        let mut supported = Vec::new();
        for step in &plan.steps {
            match step.strategy {
                QlapotiStrategy::TwoPower => {
                    let mut degree = IsogenyInteger::from(2u64);
                    while step.degree >= degree {
                        if SMALL_MODEL_SUPPORTED_DEGREES.contains(&degree) {
                            supported.push(degree);
                        }
                        degree = match degree.checked_mul(&IsogenyInteger::from(2u64)) {
                            Some(next) => next,
                            None => break,
                        };
                    }
                }
                QlapotiStrategy::OddPrimePower => {
                    let Some(prime) = step.prime.try_to_u64() else {
                        continue;
                    };
                    let mut degree = IsogenyInteger::from(prime);
                    for _ in 0..step.exponent {
                        if SMALL_MODEL_SUPPORTED_DEGREES.contains(&degree) {
                            supported.push(degree);
                        }
                        match degree.checked_mul(&IsogenyInteger::from(prime)) {
                            Some(next) => degree = next,
                            None => break,
                        }
                    }
                }
                QlapotiStrategy::LargeComposite => {}
            }
        }
        supported.sort_unstable();
        supported.dedup();
        supported
    }

    fn select_degree(&self, seed: &[u8; 32], plan: &QlapotiPlan) -> IsogenyInteger {
        let supported = self.supported_degrees_from_plan(plan);
        if supported.is_empty() {
            self.norm(seed).into()
        } else {
            supported[usize::from(seed[1]) % supported.len()]
        }
    }

    pub fn build_request(
        &self,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> ActualWitnessRequest {
        let plan = QlapotiEngine::plan_for_degree(signature.degree);
        let left_seed = self.seed(
            b"AURORA:prism:reference:actual-left:v1",
            &verifying_key.codomain.tag,
            &verifying_key.torsion_basis.commitment(),
            challenge.as_bytes(),
        );
        let right_seed = self.seed(
            b"AURORA:prism:reference:actual-right:v1",
            &signature.codomain.tag,
            &seed_witness_commitment(signature),
            challenge.as_bytes(),
        );
        let left_selected = preferred_step_degrees(
            &signature.ideal_witness.left_step_degrees_integers(),
            self.select_degree(&left_seed, &plan),
        );
        let right_selected = preferred_step_degrees(
            &signature.ideal_witness.right_step_degrees_integers(),
            self.select_degree(&right_seed, &plan),
        );
        ActualWitnessRequest {
            left: ActualChainRequest {
                side: ActualWitnessSide::Left,
                seed: left_seed,
                total_degree: signature.degree,
                selected_degree: left_selected[0],
                selected_degrees: left_selected,
                qlapoti_plan: plan.clone(),
                ideal_trace: Some(signature.ideal_witness.left),
                stage_traces: signature.ideal_witness.left_stage_traces.clone(),
                stage_principal_traces: signature.ideal_witness.left_stage_principal_traces.clone(),
            },
            right: ActualChainRequest {
                side: ActualWitnessSide::Right,
                seed: right_seed,
                total_degree: signature.degree,
                selected_degree: right_selected[0],
                selected_degrees: right_selected,
                qlapoti_plan: plan,
                ideal_trace: Some(signature.ideal_witness.right),
                stage_traces: signature.ideal_witness.right_stage_traces.clone(),
                stage_principal_traces: signature
                    .ideal_witness
                    .right_stage_principal_traces
                    .clone(),
            },
        }
    }

    fn derive_chain(
        &self,
        params: &'static SaltPrismParameters,
        request: &ActualChainRequest,
    ) -> core::result::Result<
        crate::crypto::isogeny::algorithms::ActualIsogenyChain,
        ActualPrismError,
    > {
        if let Some(ideal_trace) = request.ideal_trace {
            if SMALL_MODEL_SUPPORTED_DEGREES.contains(&ideal_trace.norm) {
                let ideal = ideal_trace
                    .to_ideal(params)
                    .map_err(ActualPrismError::from)?;
                let source = IdealToIsogenyEngine::find_small_qlapoti_curve(&ideal)
                    .map_err(ReferencePrismError::from)
                    .map_err(ActualPrismError::from)?;
                let extraction = IdealToIsogenyEngine::extract_small_kernel_hints(source, &ideal)
                    .map_err(ReferencePrismError::from)
                    .map_err(ActualPrismError::from)?;
                return IdealToIsogenyEngine::realize_small_qlapoti_chain_from_hints(
                    source,
                    &ideal,
                    &extraction,
                )
                .map_err(ReferencePrismError::from)
                .map_err(ActualPrismError::from);
            }
        }
        let order = self.reference_order(params)?;
        let mut rng = ChaCha20Rng::from_seed(request.seed);
        let ideal =
            RandomIdealSampler::sample_given_norm(&order, request.selected_degree, &mut rng)
                .map_err(ReferencePrismError::from)?;
        Ok(
            IdealToIsogenyEngine::realize_small_qlapoti_chain_with_curve_search(&ideal)
                .map_err(ReferencePrismError::from)?,
        )
    }
}

impl BaseCurveTwoIsogenyActualWitnessProvider {
    const MAX_STEP_DEGREE: u64 = 257;

    pub const fn new() -> Self {
        Self
    }

    fn build_request(
        &self,
        params: &'static SaltPrismParameters,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> ActualWitnessRequest {
        let small = SmallModelActualWitnessProvider::new();
        let mut request = small.build_request(verifying_key, challenge, signature);
        let left_plan_degrees = self.select_plan_degrees(params, &request.left);
        request.left.selected_degrees = if !left_plan_degrees.is_empty() {
            left_plan_degrees
        } else if signature.ideal_witness.left_step_degrees.is_empty() {
            vec![IsogenyInteger::from(2u64)]
        } else {
            signature.ideal_witness.left_step_degrees_integers()
        };
        request.left.selected_degree = request.left.selected_degrees[0];
        let right_plan_degrees = self.select_plan_degrees(params, &request.right);
        request.right.selected_degrees = if !right_plan_degrees.is_empty() {
            right_plan_degrees
        } else if signature.ideal_witness.right_step_degrees.is_empty() {
            vec![IsogenyInteger::from(2u64)]
        } else {
            signature.ideal_witness.right_step_degrees_integers()
        };
        request.right.selected_degree = request.right.selected_degrees[0];
        self.refresh_stage_traces(params, &mut request.left);
        self.refresh_stage_traces(params, &mut request.right);
        request
    }

    fn refresh_stage_traces(
        &self,
        params: &'static SaltPrismParameters,
        request: &mut ActualChainRequest,
    ) {
        let Some(ideal_trace) = request.ideal_trace else {
            return;
        };
        let Ok(ideal) = ideal_trace.to_ideal(params) else {
            return;
        };
        let Ok(decomposition) =
            IdealToIsogenyEngine::derive_stage_decomposition(&ideal, &request.selected_degrees)
        else {
            return;
        };
        request.stage_traces = decomposition
            .iter()
            .map(|stage| ReferenceIdealTrace::from_ideal(&stage.stage))
            .collect();
        request.stage_principal_traces = decomposition
            .iter()
            .map(|stage| ReferenceIdealTrace::from_ideal(&stage.principal))
            .collect();
    }

    fn select_plan_degrees(
        &self,
        params: &'static SaltPrismParameters,
        request: &ActualChainRequest,
    ) -> Vec<IsogenyInteger> {
        let mut supported = Vec::new();
        for step in &request.qlapoti_plan.steps {
            match step.strategy {
                QlapotiStrategy::TwoPower => {
                    for _ in 0..step.exponent {
                        supported.push(IsogenyInteger::from(2u64));
                    }
                }
                QlapotiStrategy::OddPrimePower => {
                    if let (Some(step_degree), Some(step_prime)) =
                        (step.degree.try_to_u64(), step.prime.try_to_u64())
                    {
                        let Ok(step_exponent) = usize::try_from(step.exponent) else {
                            continue;
                        };
                        if step_prime <= Self::MAX_STEP_DEGREE
                            && step_prime > 1
                            && u64::from(params.base.cofactor) % step_prime == 0
                        {
                            let available_exponent =
                                prime_exponent_in_u32(params.base.cofactor, step_prime);
                            let decomposition = if step_exponent <= available_exponent
                                && step_degree <= Self::MAX_STEP_DEGREE
                            {
                                vec![IsogenyInteger::from(step_degree)]
                            } else if available_exponent >= 2
                                && step_prime.saturating_mul(step_prime) <= Self::MAX_STEP_DEGREE
                            {
                                let mut remaining = step_exponent;
                                let mut degrees = Vec::new();
                                while remaining >= 2 {
                                    degrees.push(IsogenyInteger::from(step_prime * step_prime));
                                    remaining -= 2;
                                }
                                while remaining > 0 {
                                    degrees.push(IsogenyInteger::from(step_prime));
                                    remaining -= 1;
                                }
                                degrees
                            } else {
                                core::iter::repeat_n(IsogenyInteger::from(step_prime), step_exponent)
                                    .collect()
                            };
                            supported.extend(decomposition);
                        }
                    }
                }
                QlapotiStrategy::LargeComposite => {}
            }
        }
        supported
    }

    fn base_curve(
        &self,
        params: &'static SaltPrismParameters,
    ) -> core::result::Result<ShortWeierstrassCurve, ActualPrismError> {
        ShortWeierstrassCurve::new(
            Fp2::one(&params.base.modulus),
            Fp2::zero(&params.base.modulus),
        )
        .map_err(map_weierstrass_error)
    }

    fn search_context(
        &self,
        params: &'static SaltPrismParameters,
        request: &ActualChainRequest,
    ) -> core::result::Result<ActualKernelSearchContext, ActualPrismError> {
        let (stage_bindings, stage_input_ideals, stage_principal_ideals, stage_ideals, stage_next_ideals) = if !request
            .stage_principal_traces
            .is_empty()
        {
            let ideal_trace = request.ideal_trace.ok_or(ActualPrismError::Reference(
                ReferencePrismError::IdealToIsogeny(IdealToIsogenyError::InvalidChain),
            ))?;
            let ideal = ideal_trace
                .to_ideal(params)
                .map_err(ActualPrismError::from)?;
            let principal_ideals = request
                .stage_principal_traces
                .iter()
                .map(|trace| trace.to_ideal_with_orders(ideal.left_order(), ideal.right_order()))
                .collect::<core::result::Result<Vec<_>, _>>()
                .map_err(ActualPrismError::from)?;
            let decomposition = IdealToIsogenyEngine::replay_stage_decomposition_from_principals(
                &ideal,
                &request.selected_degrees,
                &principal_ideals,
            )
            .map_err(ReferencePrismError::from)
            .map_err(ActualPrismError::from)?;
            if !request.stage_traces.is_empty()
                && !decomposition
                    .iter()
                    .map(|stage| ReferenceIdealTrace::from_ideal(&stage.stage))
                    .eq(request.stage_traces.iter().copied())
            {
                return Err(ActualPrismError::Reference(
                    ReferencePrismError::IdealToIsogeny(IdealToIsogenyError::InvalidChain),
                ));
            }
            let mut stage_inputs = Vec::with_capacity(decomposition.len());
            let mut stage_principals = Vec::with_capacity(decomposition.len());
            let mut stage_ideals = Vec::with_capacity(decomposition.len());
            let mut stage_next_ideals = Vec::with_capacity(decomposition.len());
            for stage in decomposition {
                stage_inputs.push(stage.input);
                stage_principals.push(stage.principal);
                stage_ideals.push(stage.stage);
                stage_next_ideals.push(stage.next);
            }
            (
                IdealToIsogenyEngine::stage_bindings_for_ideals(&stage_ideals),
                stage_inputs,
                stage_principals,
                stage_ideals,
                stage_next_ideals,
            )
        } else if !request.stage_traces.is_empty() {
            let stage_ideals = request
                .stage_traces
                .iter()
                .map(|trace| trace.to_ideal(params))
                .collect::<core::result::Result<Vec<_>, _>>()
                .map_err(ActualPrismError::from)?;
            (
                IdealToIsogenyEngine::stage_bindings_for_ideals(&stage_ideals),
                Vec::new(),
                Vec::new(),
                stage_ideals,
                Vec::new(),
            )
        } else if request.ideal_trace.is_some() {
            // During plan probing we only have the root ideal; deriving a stage
            // decomposition from the provisional selected degrees overconstrains
            // the search and can suppress valid later steps.
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new())
        } else {
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };
        Ok(ActualKernelSearchContext {
            seed: request.seed,
            binding: request_binding(request),
            root_ideal: request
                .ideal_trace
                .and_then(|trace| trace.to_ideal(params).ok()),
            stage_bindings,
            stage_input_ideals,
            stage_principal_ideals,
            stage_ideals,
            stage_next_ideals,
            cofactor: params.base.cofactor,
            two_torsion_bits: u16::try_from(params.base.two_torsion_bits).map_err(|_| {
                ActualPrismError::Reference(ReferencePrismError::IdealToIsogeny(
                    IdealToIsogenyError::UnsupportedActualDegree,
                ))
            })?,
            use_base_two_torsion: true,
        })
    }

    fn derive_chain(
        &self,
        params: &'static SaltPrismParameters,
        request: &ActualChainRequest,
    ) -> core::result::Result<ActualIsogenyChain, ActualPrismError> {
        let source = self.base_curve(params)?;
        let context = self.search_context(params, request)?;
        let extraction = IdealToIsogenyEngine::extract_bounded_kernel_hints(
            source,
            &request.selected_degrees,
            &context,
        )
        .map_err(ReferencePrismError::from)
        .map_err(ActualPrismError::from)?;
        IdealToIsogenyEngine::realize_bounded_chain_from_hints(
            source,
            &request.selected_degrees,
            &context,
            &extraction,
        )
        .map_err(ReferencePrismError::from)
        .map_err(ActualPrismError::from)
    }
}

impl ActualWitnessProvider for SmallModelActualWitnessProvider {
    fn prepare_signature(
        &self,
        params: &'static SaltPrismParameters,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &mut ReferenceSignatureBody,
    ) -> core::result::Result<(), ActualPrismError> {
        let request = self.build_request(verifying_key, challenge, signature);
        let plan = QlapotiEngine::plan_for_degree(signature.degree);
        let supported = self.supported_degrees_from_plan(&plan);
        let left_hints = if supported.is_empty() {
            Vec::new()
        } else {
            request.left.selected_degrees.clone()
        };
        let right_hints = if supported.is_empty() {
            Vec::new()
        } else {
            request.right.selected_degrees.clone()
        };
        signature
            .ideal_witness
            .set_step_degrees(&left_hints, &right_hints)
            .ok_or(ActualPrismError::Reference(
                ReferencePrismError::IdealToIsogeny(IdealToIsogenyError::UnsupportedActualDegree),
            ))?;
        let left_ideal = signature
            .ideal_witness
            .left
            .to_ideal(params)
            .map_err(ActualPrismError::from)?;
        let right_ideal = signature
            .ideal_witness
            .right
            .to_ideal(params)
            .map_err(ActualPrismError::from)?;
        signature
            .ideal_witness
            .set_stage_traces_from_ideals(
                &left_ideal,
                &request.left.selected_degrees,
                &right_ideal,
                &request.right.selected_degrees,
            )
            .map_err(ActualPrismError::from)
    }

    fn derive_witness(
        &self,
        params: &'static SaltPrismParameters,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> core::result::Result<ReferenceActualWitness, ActualPrismError> {
        let request = self.build_request(verifying_key, challenge, signature);
        let actual = ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny {
            left: self.derive_chain(params, &request.left)?,
            right: self.derive_chain(params, &request.right)?,
        })
        .map_err(ReferencePrismError::from)?;
        ReferenceActualWitness::from_actual(&actual).ok_or_else(|| {
            ActualPrismError::Reference(ReferencePrismError::IdealToIsogeny(
                IdealToIsogenyError::UnsupportedActualDegree,
            ))
        })
    }
}

impl ActualWitnessProvider for BaseCurveTwoIsogenyActualWitnessProvider {
    fn prepare_signature(
        &self,
        params: &'static SaltPrismParameters,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &mut ReferenceSignatureBody,
    ) -> core::result::Result<(), ActualPrismError> {
        let small = SmallModelActualWitnessProvider::new();
        let request = small.build_request(verifying_key, challenge, signature);
        let left_hints = self.select_plan_degrees(params, &request.left);
        let right_hints = self.select_plan_degrees(params, &request.right);
        signature
            .ideal_witness
            .set_step_degrees(&left_hints, &right_hints)
            .ok_or(ActualPrismError::Reference(
                ReferencePrismError::IdealToIsogeny(IdealToIsogenyError::UnsupportedActualDegree),
            ))?;
        let left_ideal = signature
            .ideal_witness
            .left
            .to_ideal(params)
            .map_err(ActualPrismError::from)?;
        let right_ideal = signature
            .ideal_witness
            .right
            .to_ideal(params)
            .map_err(ActualPrismError::from)?;
        signature
            .ideal_witness
            .set_stage_traces_from_ideals(&left_ideal, &left_hints, &right_ideal, &right_hints)
            .map_err(ActualPrismError::from)
    }

    fn derive_witness(
        &self,
        params: &'static SaltPrismParameters,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> core::result::Result<ReferenceActualWitness, ActualPrismError> {
        let request = self.build_request(params, verifying_key, challenge, signature);
        let actual = ActualProductIsogenyWitnessData::from_isogeny(ActualProductIsogeny {
            left: self.derive_chain(params, &request.left)?,
            right: self.derive_chain(params, &request.right)?,
        })
        .map_err(ReferencePrismError::from)
        .map_err(ActualPrismError::from)?;
        ReferenceActualWitness::from_actual(&actual).ok_or_else(|| {
            ActualPrismError::Reference(ReferencePrismError::IdealToIsogeny(
                IdealToIsogenyError::UnsupportedActualDegree,
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct ActualPrismBackend<P = BaseCurveTwoIsogenyActualWitnessProvider> {
    inner: ReferencePrismBackend,
    provider: P,
}

impl ActualPrismBackend<BaseCurveTwoIsogenyActualWitnessProvider> {
    pub const fn new(params: &'static SaltPrismParameters) -> Self {
        Self::with_provider(params, BaseCurveTwoIsogenyActualWitnessProvider::new())
    }
}

impl<P> ActualPrismBackend<P> {
    pub const fn with_provider(params: &'static SaltPrismParameters, provider: P) -> Self {
        Self {
            inner: ReferencePrismBackend::new(params),
            provider,
        }
    }

    pub const fn with_signature_encoding(mut self, encoding: SignatureEncoding) -> Self {
        self.inner = self.inner.with_signature_encoding(encoding);
        self
    }

    pub const fn signature_encoding(&self) -> SignatureEncoding {
        self.inner.signature_encoding()
    }

    pub const fn inner(&self) -> &ReferencePrismBackend {
        &self.inner
    }

    pub const fn provider(&self) -> &P {
        &self.provider
    }

    fn require_actual(
        signature: ReferenceSignatureBody,
    ) -> core::result::Result<ReferenceSignatureBody, ActualPrismError> {
        if signature.actual_witness.is_some() {
            Ok(signature)
        } else {
            Err(ActualPrismError::MissingActualWitness)
        }
    }

    fn unsigned_signature(signature: &ReferenceSignatureBody) -> ReferenceSignatureBody {
        ReferenceSignatureBody {
            encoding: signature.encoding,
            degree: signature.degree,
            codomain: signature.codomain,
            torsion_basis: signature.torsion_basis,
            basis_coefficients: signature.basis_coefficients.clone(),
            signature_points: signature.signature_points.clone(),
            ideal_witness: signature.ideal_witness.clone(),
            actual_witness: None,
            kani: crate::crypto::isogeny::algorithms::KaniTranscript {
                kernel: crate::crypto::isogeny::algorithms::KaniKernel {
                    pairing_commitment: [0u8; 32],
                    torsion_commitment: [0u8; 32],
                },
                image: crate::crypto::isogeny::algorithms::KaniImage {
                    left_codomain_tag: [0u8; 32],
                    right_codomain_tag: [0u8; 32],
                },
            },
        }
    }

    fn is_nonfatal_actual_error(error: &ActualPrismError) -> bool {
        matches!(
            error,
            ActualPrismError::MissingActualWitness
                | ActualPrismError::Reference(ReferencePrismError::Kani(
                    KaniError::InvalidActualWitness
                ))
                | ActualPrismError::Reference(ReferencePrismError::RandomIdeal(
                    RandomIdealError::InvalidNorm
                ))
                | ActualPrismError::Reference(ReferencePrismError::IdealToIsogeny(
                    IdealToIsogenyError::KernelSearchFailed
                ))
                | ActualPrismError::Reference(ReferencePrismError::IdealToIsogeny(
                    IdealToIsogenyError::UnsupportedActualDegree
                ))
        )
    }
}

fn seed_witness_commitment(signature: &ReferenceSignatureBody) -> [u8; 32] {
    let payload = match signature.encoding {
        SignatureEncoding::CurveAndBasisCoefficients => signature.basis_coefficients.commitment(),
        SignatureEncoding::CurveAndPoints => signature.signature_points.commitment(),
    };
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:prism:actual:seed-witness:v1");
    hasher.update(payload);
    hasher.update(signature.ideal_witness.root_commitment());
    hasher.update(signature.ideal_witness.step_hint_commitment());
    hasher.update(signature.ideal_witness.stage_commitment());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn request_binding(request: &ActualChainRequest) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:prism:actual:request-binding:v1");
    hasher.update(request.seed);
    hasher.update(match request.side {
        ActualWitnessSide::Left => [0u8],
        ActualWitnessSide::Right => [1u8],
    });
    hasher.update(request.total_degree.to_be_bytes_fixed());
    hasher.update(request.selected_degree.to_be_bytes_fixed());
    hasher.update((request.selected_degrees.len() as u32).to_be_bytes());
    for degree in &request.selected_degrees {
        hasher.update(degree.to_be_bytes_fixed());
    }
    if let Some(annotation_commitment) = request
        .qlapoti_plan
        .selected_degree_commitment(&request.selected_degrees)
    {
        hasher.update(annotation_commitment);
    } else {
        hasher.update([0xff; 32]);
    }
    hasher.update((request.stage_traces.len() as u32).to_be_bytes());
    for trace in &request.stage_traces {
        hasher.update(trace.commitment());
    }
    hasher.update((request.stage_principal_traces.len() as u32).to_be_bytes());
    for trace in &request.stage_principal_traces {
        hasher.update(trace.commitment());
    }
    hasher.update(request.qlapoti_plan.total_degree.to_be_bytes_fixed());
    hasher.update((request.qlapoti_plan.steps.len() as u32).to_be_bytes());
    for step in &request.qlapoti_plan.steps {
        hasher.update(step.degree.to_be_bytes_fixed());
        hasher.update(step.prime.to_be_bytes_fixed());
        hasher.update(step.exponent.to_be_bytes());
        hasher.update([match step.strategy {
            QlapotiStrategy::TwoPower => 0,
            QlapotiStrategy::OddPrimePower => 1,
            QlapotiStrategy::LargeComposite => 2,
        }]);
    }
    if let Some(ideal_trace) = request.ideal_trace {
        hasher.update(ideal_trace.commitment());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn map_weierstrass_error(error: WeierstrassError) -> ActualPrismError {
    ActualPrismError::Reference(ReferencePrismError::IdealToIsogeny(
        IdealToIsogenyError::from(VeluError::from(error)),
    ))
}

fn public_kani_statement(
    params: &'static SaltPrismParameters,
    verifying_key: &ReferenceVerifyingKey,
    signature: &ReferenceSignatureBody,
    actual_witness: &ReferenceActualWitness,
) -> core::result::Result<
    crate::crypto::isogeny::algorithms::ProductIsogenyStatement,
    ActualPrismError,
> {
    Ok(KaniEngine::statement(
        verifying_key.codomain.tag,
        verifying_key.torsion_basis.commitment(),
        signature.codomain.tag,
        signature.torsion_basis.commitment(),
        signature.ideal_witness.stage_commitment(),
        actual_witness
            .actual_probe_commitment()
            .map_err(ActualPrismError::from)?,
        actual_witness
            .actual_quotient_commitment()
            .map_err(ActualPrismError::from)?,
        actual_kani_binding_commitment(params, actual_witness, &signature.ideal_witness),
    ))
}

fn actual_kani_binding_commitment(
    params: &'static SaltPrismParameters,
    actual_witness: &ReferenceActualWitness,
    ideal_witness: &crate::crypto::prism::ReferenceIdealWitness,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:prism:actual:kani-binding:v1");
    hasher.update(actual_witness.chain_commitment());
    hasher.update(actual_witness.kernel_commitment());
    hasher.update(actual_witness.probe_commitment());
    hasher.update(actual_witness.quotient_commitment());
    hasher.update(ideal_witness.root_commitment());
    hasher.update(ideal_witness.step_hint_commitment());
    hasher.update(qlapoti_step_hint_commitment(params, ideal_witness));
    hasher.update(ideal_witness.stage_commitment());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn preferred_step_degrees(
    hinted: &[IsogenyInteger],
    fallback: IsogenyInteger,
) -> Vec<IsogenyInteger> {
    if hinted.is_empty() {
        vec![fallback]
    } else {
        hinted.to_vec()
    }
}

fn prime_exponent_in_u32(mut value: u32, prime: u64) -> usize {
    if prime <= 1 {
        return 0;
    }
    let prime_u32 = match u32::try_from(prime) {
        Ok(v) if v > 1 => v,
        _ => return 0,
    };
    let mut exponent = 0usize;
    while value % prime_u32 == 0 {
        value /= prime_u32;
        exponent += 1;
    }
    exponent
}

#[cfg(test)]
fn test_step_degrees(values: &[u128]) -> Vec<IsogenyInteger> {
    values.iter().copied().map(IsogenyInteger::from).collect()
}

impl<P> ActualPrismBackend<P>
where
    P: ActualWitnessProvider,
{
    fn derive_actual_witness(
        &self,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        signature: &ReferenceSignatureBody,
    ) -> core::result::Result<ReferenceActualWitness, ActualPrismError> {
        self.provider
            .derive_witness(self.params(), verifying_key, challenge, signature)
    }

    fn attach_actual_witness(
        &self,
        verifying_key: &ReferenceVerifyingKey,
        challenge: &ChallengePrime,
        mut signature: ReferenceSignatureBody,
    ) -> core::result::Result<ReferenceSignatureBody, ActualPrismError> {
        self.provider
            .prepare_signature(self.params(), verifying_key, challenge, &mut signature)?;
        let unsigned = Self::unsigned_signature(&signature);
        let actual_witness = self.derive_actual_witness(verifying_key, challenge, &unsigned)?;
        let actual = actual_witness.to_actual().map_err(ActualPrismError::from)?;
        let statement =
            public_kani_statement(self.params(), verifying_key, &unsigned, &actual_witness)?;
        signature.actual_witness = Some(actual_witness);
        signature.kani = KaniEngine::construct_actual(statement, &actual, challenge.as_bytes())
            .map_err(ActualPrismError::from)?;
        Ok(signature)
    }
}

impl<P> PrismBackend for ActualPrismBackend<P>
where
    P: ActualWitnessProvider,
{
    type Error = ActualPrismError;
    type VerifyingKey = ReferenceVerifyingKey;
    type SigningKey = ReferenceSigningKey;
    type SignatureBody = ReferenceSignatureBody;

    fn params(&self) -> &'static SaltPrismParameters {
        self.inner.params()
    }

    fn keygen(
        &mut self,
    ) -> core::result::Result<(Self::VerifyingKey, Self::SigningKey), Self::Error> {
        self.inner.keygen().map_err(ActualPrismError::from)
    }

    fn encode_verifying_key(&self, verifying_key: &Self::VerifyingKey) -> Vec<u8> {
        self.inner.encode_verifying_key(verifying_key)
    }

    fn sign_challenge(
        &mut self,
        verifying_key: &Self::VerifyingKey,
        signing_key: &Self::SigningKey,
        challenge: &ChallengePrime,
    ) -> core::result::Result<Self::SignatureBody, Self::Error> {
        let signature = self
            .inner
            .sign_challenge(verifying_key, signing_key, challenge)
            .map_err(ActualPrismError::from)?;
        Self::require_actual(self.attach_actual_witness(verifying_key, challenge, signature)?)
    }

    fn encode_signature_body(&self, signature: &Self::SignatureBody) -> Vec<u8> {
        self.inner.encode_signature_body(signature)
    }

    fn decode_signature_body(&self, bytes: &[u8]) -> Option<Self::SignatureBody> {
        let signature = self.inner.decode_signature_body(bytes)?;
        signature.actual_witness.as_ref()?;
        Some(signature)
    }

    fn verify_challenge(
        &self,
        verifying_key: &Self::VerifyingKey,
        challenge: &ChallengePrime,
        signature: &Self::SignatureBody,
    ) -> core::result::Result<bool, Self::Error> {
        if signature.actual_witness.is_none() {
            return Ok(false);
        }
        if !self
            .inner
            .verify_public_consistency(verifying_key, challenge, signature)
            .map_err(ActualPrismError::from)?
        {
            return Ok(false);
        }

        let unsigned = Self::unsigned_signature(signature);
        let actual_witness = match &signature.actual_witness {
            Some(actual_witness) => actual_witness,
            None => return Ok(false),
        };
        let expected = match self.derive_actual_witness(verifying_key, challenge, &unsigned) {
            Ok(expected) => expected,
            Err(error) if Self::is_nonfatal_actual_error(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        if &expected != actual_witness {
            return Ok(false);
        }
        let actual = actual_witness.to_actual().map_err(ActualPrismError::from)?;
        let statement =
            public_kani_statement(self.params(), verifying_key, &unsigned, actual_witness)?;
        match KaniEngine::verify_actual(&signature.kani, statement, &actual, challenge.as_bytes()) {
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

    use crate::crypto::isogeny::algorithms::{KaniEngine, KaniError};
    use crate::crypto::isogeny::arith::{IsogenyInteger, QuaternionInteger};
    use crate::crypto::isogeny::params::SupersingularParameters;
    use crate::crypto::prism::{
        keygen_with_backend, sign_with_backend, verify_with_backend, PrismBackend,
        ReferencePrismBackend, SaltPrismParameters, SignatureEncoding, SALT_PRISM_LEVEL1,
        SALT_PRISM_LEVEL3, SALT_PRISM_LEVEL5,
    };

    use super::{
        test_step_degrees, ActualPrismBackend, ActualPrismError, ActualWitnessProvider,
        ActualWitnessSide, BaseCurveTwoIsogenyActualWitnessProvider,
        SmallModelActualWitnessProvider, SMALL_MODEL_SUPPORTED_DEGREES,
    };

    const TEST_BASE: SupersingularParameters = SupersingularParameters::new(5, 2);

    const TEST_PARAMS: SaltPrismParameters = SaltPrismParameters {
        security_bits: 16,
        base: TEST_BASE,
        challenge_bits: 16,
        hash_bits: 16,
        salt_bits: 16,
        max_signatures_log2: 8,
    };

    const TEST_BASE_ODD3: SupersingularParameters = SupersingularParameters::new(9, 3);

    const TEST_PARAMS_ODD3: SaltPrismParameters = SaltPrismParameters {
        security_bits: 16,
        base: TEST_BASE_ODD3,
        challenge_bits: 16,
        hash_bits: 16,
        salt_bits: 16,
        max_signatures_log2: 8,
    };

    fn smoke_roundtrip_for_params(params: &'static SaltPrismParameters, seed: [u8; 32]) {
        let mut backend = ActualPrismBackend::new(params)
            .with_signature_encoding(SignatureEncoding::CurveAndPoints);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"paper-smoke",
            &mut rng,
            256,
        )
        .unwrap();
        assert!(verify_with_backend(&backend, &verifying_key, b"paper-smoke", &signature).unwrap());
        assert!(!verify_with_backend(
            &backend,
            &verifying_key,
            b"paper-smoke-tampered",
            &signature
        )
        .unwrap());
    }

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
    #[ignore = "paper-sized actual backend smoke test"]
    fn actual_backend_smoke_roundtrip_level1_parameters() {
        smoke_roundtrip_for_params(&SALT_PRISM_LEVEL1, [0xA1; 32]);
    }

    #[test]
    #[ignore = "paper-sized actual backend smoke test"]
    fn actual_backend_smoke_roundtrip_level3_parameters() {
        smoke_roundtrip_for_params(&SALT_PRISM_LEVEL3, [0xB3; 32]);
    }

    #[test]
    #[ignore = "paper-sized actual backend smoke test"]
    fn actual_backend_smoke_roundtrip_level5_parameters() {
        smoke_roundtrip_for_params(&SALT_PRISM_LEVEL5, [0xC5; 32]);
    }

    #[test]
    fn actual_backend_roundtrip_verifies() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut backend = ActualPrismBackend::new(&TEST_PARAMS)
                    .with_signature_encoding(SignatureEncoding::CurveAndPoints);
                let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
                let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
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
                let challenge = crate::crypto::prism::hash_to_prime_with_salt(
                    &TEST_PARAMS.hash_to_prime_config(256),
                    &backend.encode_verifying_key(&verifying_key),
                    b"message",
                    &signature.salt,
                )
                .unwrap()
                .unwrap();
                assert!(decoded.actual_witness.is_some());
                assert!(!backend.inner().actual_small_model());
                assert_eq!(
                    decoded.ideal_witness.left_stage_traces.len(),
                    decoded.ideal_witness.left_step_degrees.len()
                );
                assert_eq!(
                    decoded.ideal_witness.left_stage_principal_traces.len(),
                    decoded.ideal_witness.left_step_degrees.len()
                );
                let actual = decoded.actual_witness.clone().unwrap().to_actual().unwrap();
                assert_eq!(
                    actual.isogeny.left.source.modulus(),
                    &TEST_PARAMS.base.modulus
                );
                assert_eq!(actual.isogeny.left.steps.len(), 1);
                assert!([2u128, 5].contains(&(actual.isogeny.left.steps[0].degree as u128)));
                assert!(
                    backend
                        .inner()
                        .verify_public_consistency(&verifying_key, &challenge, &decoded,)
                        .unwrap(),
                    "degree={:?} left={:?} right={:?}",
                    decoded.degree,
                    decoded.ideal_witness.left_step_degrees,
                    decoded.ideal_witness.right_step_degrees
                );
                let expected = backend
                    .derive_actual_witness(
                        &verifying_key,
                        &challenge,
                        &ActualPrismBackend::<
                            BaseCurveTwoIsogenyActualWitnessProvider,
                        >::unsigned_signature(&decoded),
                    )
                    .unwrap();
                assert_eq!(expected, decoded.actual_witness.clone().unwrap());
                assert!(
                    verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap()
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn stage_traces_bind_actual_witness_derivation() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS_ODD3);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 36u128.into();

        let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
        provider
            .prepare_signature(
                &TEST_PARAMS_ODD3,
                &verifying_key,
                &challenge,
                &mut signature,
            )
            .unwrap();
        let request =
            provider.build_request(&TEST_PARAMS_ODD3, &verifying_key, &challenge, &signature);
        assert!(!request.left.stage_principal_traces.is_empty());
        let honest = provider
            .search_context(&TEST_PARAMS_ODD3, &request.left)
            .unwrap();

        let mut tampered = request.left.clone();
        tampered.stage_principal_traces[0].generator_coeffs[0] = tampered.stage_principal_traces[0]
            .generator_coeffs[0]
            .checked_add(&QuaternionInteger::from(1i32))
            .unwrap();
        match provider.search_context(&TEST_PARAMS_ODD3, &tampered) {
            Ok(tampered_context) => {
                assert_ne!(honest.binding, tampered_context.binding);
                assert_ne!(honest.stage_bindings, tampered_context.stage_bindings);
            }
            Err(_) => {}
        }
    }

    #[test]
    fn actual_kani_statement_is_bound_to_ideal_witness() {
        run_on_large_stack(|| {
            let mut backend = ActualPrismBackend::new(&TEST_PARAMS)
                .with_signature_encoding(SignatureEncoding::CurveAndPoints);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([77u8; 32]);
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
            let challenge = crate::crypto::prism::hash_to_prime_with_salt(
                &TEST_PARAMS.hash_to_prime_config(256),
                &backend.encode_verifying_key(&verifying_key),
                b"message",
                &signature.salt,
            )
            .unwrap()
            .unwrap();
            let actual_witness = decoded.actual_witness.clone().unwrap();
            let actual = actual_witness.to_actual().unwrap();

            let honest_statement = super::public_kani_statement(
                &TEST_PARAMS,
                &verifying_key,
                &decoded,
                &actual_witness,
            )
            .unwrap();
            let mut tampered = decoded.clone();
            tampered.ideal_witness.left.generator_coeffs[0] =
                tampered.ideal_witness.left.generator_coeffs[0]
                    .checked_add(&QuaternionInteger::from(1i32))
                    .unwrap();
            let tampered_statement = super::public_kani_statement(
                &TEST_PARAMS,
                &verifying_key,
                &tampered,
                &actual_witness,
            )
            .unwrap();

            assert_ne!(
                honest_statement.witness_commitment,
                tampered_statement.witness_commitment
            );
            assert_eq!(
                KaniEngine::verify_actual(
                    &decoded.kani,
                    tampered_statement,
                    &actual,
                    challenge.as_bytes()
                ),
                Err(KaniError::InvalidTranscript)
            );
        });
    }

    #[test]
    fn stage_commitment_is_separate_from_root_commitment() {
        run_on_large_stack(|| {
            let mut backend = ReferencePrismBackend::new(&TEST_PARAMS_ODD3);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
            let mut signature = backend
                .sign_challenge(&verifying_key, &signing_key, &challenge)
                .unwrap();
            signature.degree = 36u128.into();

            let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
            provider
                .prepare_signature(
                    &TEST_PARAMS_ODD3,
                    &verifying_key,
                    &challenge,
                    &mut signature,
                )
                .unwrap();
            let actual_witness = provider
                .derive_witness(&TEST_PARAMS_ODD3, &verifying_key, &challenge, &signature)
                .unwrap();

            let mut tampered = signature.clone();
            assert!(!tampered
                .ideal_witness
                .left_stage_principal_traces
                .is_empty());
            tampered.ideal_witness.left_stage_principal_traces[0].basis_coeffs[0][0] =
                tampered.ideal_witness.left_stage_principal_traces[0].basis_coeffs[0][0]
                    .checked_add(&QuaternionInteger::from(1i32))
                    .unwrap();

            assert_eq!(
                signature.ideal_witness.root_commitment(),
                tampered.ideal_witness.root_commitment()
            );
            assert_ne!(
                signature.ideal_witness.stage_commitment(),
                tampered.ideal_witness.stage_commitment()
            );
            assert_ne!(
                super::public_kani_statement(
                    &TEST_PARAMS_ODD3,
                    &verifying_key,
                    &signature,
                    &actual_witness
                )
                .unwrap()
                .decomposition_commitment,
                super::public_kani_statement(
                    &TEST_PARAMS_ODD3,
                    &verifying_key,
                    &tampered,
                    &actual_witness
                )
                .unwrap()
                .decomposition_commitment
            );
            assert_ne!(
                super::public_kani_statement(
                    &TEST_PARAMS_ODD3,
                    &verifying_key,
                    &signature,
                    &actual_witness
                )
                .unwrap()
                .witness_commitment,
                super::public_kani_statement(
                    &TEST_PARAMS_ODD3,
                    &verifying_key,
                    &tampered,
                    &actual_witness
                )
                .unwrap()
                .witness_commitment
            );
        });
    }

    #[test]
    fn quotient_commitment_is_publicly_separate_from_decomposition_commitment() {
        run_on_large_stack(|| {
            let mut backend = ActualPrismBackend::new(&TEST_PARAMS);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([48u8; 32]);
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

            let honest_statement = super::public_kani_statement(
                &TEST_PARAMS,
                &verifying_key,
                &decoded,
                &actual_witness,
            )
            .unwrap();
            let mut tampered_actual = actual_witness.to_actual().unwrap();
            assert!(tampered_actual.samples.len() > 1);
            tampered_actual.samples.swap(0, 1);
            tampered_actual.images.swap(0, 1);
            let tampered_witness =
                crate::crypto::prism::ReferenceActualWitness::from_actual(&tampered_actual)
                    .unwrap();
            let tampered_statement = super::public_kani_statement(
                &TEST_PARAMS,
                &verifying_key,
                &decoded,
                &tampered_witness,
            )
            .unwrap();

            assert_eq!(
                honest_statement.decomposition_commitment,
                tampered_statement.decomposition_commitment
            );
            assert_ne!(
                honest_statement.probe_commitment,
                tampered_statement.probe_commitment
            );
            assert_ne!(
                honest_statement.quotient_commitment,
                tampered_statement.quotient_commitment
            );
            assert_ne!(
                honest_statement.witness_commitment,
                tampered_statement.witness_commitment
            );
        });
    }

    #[test]
    fn actual_backend_rejects_reference_only_signature() {
        run_on_large_stack(|| {
            let mut actual = ActualPrismBackend::new(&TEST_PARAMS);
            let (verifying_key, signing_key) = keygen_with_backend(&mut actual).unwrap();

            let mut reference = ReferencePrismBackend::new(&TEST_PARAMS);
            let mut rng = ChaCha20Rng::from_seed([43u8; 32]);
            let signature = sign_with_backend(
                &mut reference,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                256,
            )
            .unwrap();

            assert!(actual.decode_signature_body(&signature.body).is_none());
            assert!(!verify_with_backend(&actual, &verifying_key, b"message", &signature).unwrap());
        });
    }

    #[test]
    fn actual_backend_sign_requires_actual_witness() {
        let mut backend = ActualPrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        assert!(signature.actual_witness.is_some());

        let err = ActualPrismBackend::<SmallModelActualWitnessProvider>::require_actual(
            crate::crypto::prism::ReferenceSignatureBody {
                actual_witness: None,
                ..signature
            },
        );
        assert_eq!(err, Err(ActualPrismError::MissingActualWitness));
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct EchoProvider;

    impl ActualWitnessProvider for EchoProvider {
        fn derive_witness(
            &self,
            params: &'static SaltPrismParameters,
            verifying_key: &crate::crypto::prism::ReferenceVerifyingKey,
            challenge: &crate::crypto::prism::ChallengePrime,
            signature: &crate::crypto::prism::ReferenceSignatureBody,
        ) -> core::result::Result<crate::crypto::prism::ReferenceActualWitness, ActualPrismError>
        {
            SmallModelActualWitnessProvider::new().derive_witness(
                params,
                verifying_key,
                challenge,
                signature,
            )
        }
    }

    #[test]
    fn actual_backend_supports_explicit_provider_injection() {
        run_on_large_stack(|| {
            let mut backend = ActualPrismBackend::with_provider(&TEST_PARAMS, EchoProvider)
                .with_signature_encoding(SignatureEncoding::CurveAndBasisCoefficients);
            let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
            let mut rng = ChaCha20Rng::from_seed([45u8; 32]);
            let signature = sign_with_backend(
                &mut backend,
                &verifying_key,
                &signing_key,
                b"provider",
                &mut rng,
                256,
            )
            .unwrap();

            assert!(
                verify_with_backend(&backend, &verifying_key, b"provider", &signature).unwrap()
            );
        });
    }

    #[test]
    fn base_curve_provider_derives_large_field_witness() {
        let mut reference = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut reference).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let signature = reference
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();

        let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
        let witness = provider
            .derive_witness(&TEST_PARAMS, &verifying_key, &challenge, &signature)
            .unwrap();
        let actual = witness.to_actual().unwrap();

        assert_eq!(
            actual.isogeny.left.source.modulus(),
            &TEST_PARAMS.base.modulus
        );
        assert_eq!(
            actual.isogeny.right.source.modulus(),
            &TEST_PARAMS.base.modulus
        );
        assert_eq!(actual.isogeny.left.steps.len(), 1);
        assert_eq!(actual.isogeny.right.steps.len(), 1);
        assert!([2u128, 5].contains(&(actual.isogeny.left.steps[0].degree as u128)));
        assert!([2u128, 5].contains(&(actual.isogeny.right.steps[0].degree as u128)));
    }

    #[test]
    fn base_curve_provider_selects_supported_odd_prime_power_from_plan() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 45u128.into();

        let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
        let request = provider.build_request(&TEST_PARAMS, &verifying_key, &challenge, &signature);

        assert_eq!(request.left.selected_degree, IsogenyInteger::from(5u64));
        assert_eq!(request.right.selected_degree, IsogenyInteger::from(5u64));
        assert_eq!(request.left.selected_degrees, test_step_degrees(&[5]));
        assert_eq!(request.right.selected_degrees, test_step_degrees(&[5]));
    }

    #[test]
    fn base_curve_provider_derives_degree_five_chain_when_supported() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 45u128.into();

        let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
        let witness = provider
            .derive_witness(&TEST_PARAMS, &verifying_key, &challenge, &signature)
            .unwrap();
        let actual = witness.to_actual().unwrap();

        assert_eq!(actual.isogeny.left.steps.len(), 1);
        assert_eq!(actual.isogeny.right.steps.len(), 1);
        assert_eq!(actual.isogeny.left.steps[0].degree, 5);
        assert_eq!(actual.isogeny.right.steps[0].degree, 5);
    }

    #[test]
    fn base_curve_provider_derives_multistep_chain_from_qlapoti_plan() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 360u128.into();

        let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
        let request = provider.build_request(&TEST_PARAMS, &verifying_key, &challenge, &signature);
        assert_eq!(
            request.left.selected_degrees,
            test_step_degrees(&[2, 2, 2, 5])
        );
        assert_eq!(
            request.right.selected_degrees,
            test_step_degrees(&[2, 2, 2, 5])
        );

        let witness = provider
            .derive_witness(&TEST_PARAMS, &verifying_key, &challenge, &signature)
            .unwrap();
        let actual = witness.to_actual().unwrap();
        let left_degrees: Vec<_> = actual
            .isogeny
            .left
            .steps
            .iter()
            .map(|step| step.degree)
            .collect();
        let right_degrees: Vec<_> = actual
            .isogeny
            .right
            .steps
            .iter()
            .map(|step| step.degree)
            .collect();
        assert_eq!(left_degrees, vec![2, 2, 2, 5]);
        assert_eq!(right_degrees, vec![2, 2, 2, 5]);
    }

    #[test]
    fn base_curve_provider_prefers_direct_odd_prime_power_step_when_available() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS_ODD3);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 36u128.into();

        let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
        let request =
            provider.build_request(&TEST_PARAMS_ODD3, &verifying_key, &challenge, &signature);
        assert_eq!(request.left.selected_degrees, test_step_degrees(&[2, 2, 9]));
        assert_eq!(
            request.right.selected_degrees,
            test_step_degrees(&[2, 2, 9])
        );

        let witness = provider
            .derive_witness(&TEST_PARAMS_ODD3, &verifying_key, &challenge, &signature)
            .unwrap();
        let actual = witness.to_actual().unwrap();
        let left_degrees: Vec<_> = actual
            .isogeny
            .left
            .steps
            .iter()
            .map(|step| step.degree)
            .collect();
        let right_degrees: Vec<_> = actual
            .isogeny
            .right
            .steps
            .iter()
            .map(|step| step.degree)
            .collect();
        assert_eq!(left_degrees, vec![2, 2, 9]);
        assert_eq!(right_degrees, vec![2, 2, 9]);
    }

    #[test]
    fn base_curve_provider_falls_back_to_repeated_prime_steps_when_needed() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS_ODD3);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 108u128.into();

        let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
        let request =
            provider.build_request(&TEST_PARAMS_ODD3, &verifying_key, &challenge, &signature);
        assert_eq!(
            request.left.selected_degrees,
            test_step_degrees(&[2, 2, 9, 3])
        );
        assert_eq!(
            request.right.selected_degrees,
            test_step_degrees(&[2, 2, 9, 3])
        );

        let witness = provider
            .derive_witness(&TEST_PARAMS_ODD3, &verifying_key, &challenge, &signature)
            .unwrap();
        let actual = witness.to_actual().unwrap();
        let left_degrees: Vec<_> = actual
            .isogeny
            .left
            .steps
            .iter()
            .map(|step| step.degree)
            .collect();
        let right_degrees: Vec<_> = actual
            .isogeny
            .right
            .steps
            .iter()
            .map(|step| step.degree)
            .collect();
        assert_eq!(left_degrees, vec![2, 2, 9, 3]);
        assert_eq!(right_degrees, vec![2, 2, 9, 3]);
    }

    #[test]
    fn search_context_binding_depends_on_ideal_trace_and_selected_steps() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 360u128.into();

        let provider = BaseCurveTwoIsogenyActualWitnessProvider::new();
        let request = provider.build_request(&TEST_PARAMS, &verifying_key, &challenge, &signature);
        let base_context = provider
            .search_context(&TEST_PARAMS, &request.left)
            .unwrap();
        let base_binding = base_context.binding;
        assert_eq!(
            base_context.stage_bindings.len(),
            request.left.selected_degrees.len()
        );

        let mut different_ideal = request.left.clone();
        let algebra =
            crate::crypto::isogeny::ideal::QuaternionAlgebra::new(TEST_PARAMS.base.cofactor)
                .unwrap();
        let order = crate::crypto::isogeny::ideal::MaximalOrder::reference(algebra);
        let alternate_ideal = crate::crypto::isogeny::ideal::LeftIdeal::new(
            order,
            order,
            crate::crypto::isogeny::ideal::QuaternionElement::from_coeffs(algebra, [9, 1, 0, 0]),
            request.left.ideal_trace.unwrap().norm,
        )
        .unwrap();
        different_ideal.ideal_trace = Some(crate::crypto::prism::ReferenceIdealTrace::from_ideal(
            &alternate_ideal,
        ));
        different_ideal.stage_traces.clear();
        different_ideal.stage_principal_traces.clear();
        let different_ideal_binding = provider
            .search_context(&TEST_PARAMS, &different_ideal)
            .unwrap()
            .binding;

        let mut different_steps = request.left.clone();
        different_steps.selected_degrees = test_step_degrees(&[5, 2, 2, 2]);
        different_steps.selected_degree = IsogenyInteger::from(5u64);
        different_steps.stage_traces.clear();
        different_steps.stage_principal_traces.clear();
        let different_steps_binding = provider
            .search_context(&TEST_PARAMS, &different_steps)
            .unwrap()
            .binding;

        assert_ne!(base_binding, different_ideal_binding);
        assert_ne!(base_binding, different_steps_binding);
    }

    #[test]
    fn small_model_request_prefers_supported_qlapoti_components() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 72u128.into();

        let provider = SmallModelActualWitnessProvider::new();
        let request = provider.build_request(&verifying_key, &challenge, &signature);

        assert_eq!(request.left.side, ActualWitnessSide::Left);
        assert_eq!(request.right.side, ActualWitnessSide::Right);
        assert_eq!(request.left.total_degree, IsogenyInteger::from(72u64));
        assert_eq!(request.right.total_degree, IsogenyInteger::from(72u64));
        assert_eq!(
            request.left.qlapoti_plan.total_degree,
            IsogenyInteger::from(72u64)
        );
        assert_eq!(
            request.right.qlapoti_plan.total_degree,
            IsogenyInteger::from(72u64)
        );
        let supported = test_step_degrees(&[2, 3, 4, 8, 9]);
        assert!(supported.contains(&request.left.selected_degree));
        assert!(supported.contains(&request.right.selected_degree));
        assert_eq!(
            request.left.selected_degrees,
            vec![request.left.selected_degree]
        );
        assert_eq!(
            request.right.selected_degrees,
            vec![request.right.selected_degree]
        );
    }

    #[test]
    fn small_model_request_falls_back_for_unsupported_degree() {
        let mut backend = ReferencePrismBackend::new(&TEST_PARAMS);
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let challenge = crate::crypto::prism::ChallengePrime::new(vec![0x80, 0x03]);
        let mut signature = backend
            .sign_challenge(&verifying_key, &signing_key, &challenge)
            .unwrap();
        signature.degree = 11u128.into();

        let provider = SmallModelActualWitnessProvider::new();
        let request = provider.build_request(&verifying_key, &challenge, &signature);

        assert_eq!(
            request.left.qlapoti_plan.total_degree,
            IsogenyInteger::from(11u64)
        );
        assert_eq!(
            request.right.qlapoti_plan.total_degree,
            IsogenyInteger::from(11u64)
        );
        assert!(SMALL_MODEL_SUPPORTED_DEGREES.contains(&request.left.selected_degree));
        assert!(SMALL_MODEL_SUPPORTED_DEGREES.contains(&request.right.selected_degree));
        assert_eq!(
            request.left.selected_degrees,
            vec![request.left.selected_degree]
        );
        assert_eq!(
            request.right.selected_degrees,
            vec![request.right.selected_degree]
        );
    }
}
