//! Qlapoti subroutines used by the modern IdealToIsogeny pipeline.

use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};

use crate::crypto::isogeny::arith::IsogenyInteger;
use crate::crypto::isogeny::ideal::ideal::LeftIdeal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QlapotiStrategy {
    TwoPower,
    OddPrimePower,
    LargeComposite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QlapotiStep {
    pub degree: IsogenyInteger,
    pub prime: IsogenyInteger,
    pub exponent: u32,
    pub strategy: QlapotiStrategy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QlapotiPlan {
    pub total_degree: IsogenyInteger,
    pub steps: Vec<QlapotiStep>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QlapotiStepAnnotation {
    pub step_index: u16,
    pub selected_start: u16,
    pub selected_len: u16,
    pub selected_degree_commitment: [u8; 32],
}

impl QlapotiStepAnnotation {
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:qlapoti:step-annotation:v1");
        hasher.update(self.step_index.to_be_bytes());
        hasher.update(self.selected_start.to_be_bytes());
        hasher.update(self.selected_len.to_be_bytes());
        hasher.update(self.selected_degree_commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QlapotiEngine;

impl QlapotiEngine {
    pub fn plan_for_ideal(ideal: &LeftIdeal) -> QlapotiPlan {
        Self::plan_for_degree(ideal.norm())
    }

    pub fn plan_for_degree(total_degree: impl Into<IsogenyInteger>) -> QlapotiPlan {
        let total_degree = total_degree.into();
        let mut remaining = total_degree;
        let mut steps = Vec::new();
        const TRIAL_DIVISION_LIMIT: u64 = 1 << 20;
        if remaining.rem_u64(2) == Some(0) {
            let mut exponent = 0u32;
            let mut degree = IsogenyInteger::from(1u64);
            while remaining.rem_u64(2) == Some(0) {
                remaining = remaining.div_rem_u64(2).expect("non-zero divisor").0;
                exponent += 1;
                degree = degree
                    .checked_mul(&IsogenyInteger::from(2u64))
                    .expect("power-of-two degree fits in IsogenyInteger");
            }
            steps.push(QlapotiStep {
                degree,
                prime: 2u64.into(),
                exponent,
                strategy: QlapotiStrategy::TwoPower,
            });
        }

        if remaining == 1 {
            return QlapotiPlan {
                total_degree,
                steps,
            };
        }

        let mut divisor = 3u64;
        while divisor <= TRIAL_DIVISION_LIMIT {
            let divisor_wide = IsogenyInteger::from(divisor);
            let Some(divisor_sq) = divisor_wide.checked_mul(&divisor_wide) else {
                break;
            };
            if divisor_sq > remaining {
                break;
            }
            if remaining.rem_u64(divisor) != Some(0) {
                divisor += 2;
                continue;
            }

            let mut exponent = 0u32;
            let mut degree = IsogenyInteger::one();
            while remaining.rem_u64(divisor) == Some(0) {
                remaining = remaining.div_rem_u64(divisor).expect("non-zero divisor").0;
                exponent += 1;
                degree = degree
                    .checked_mul(&divisor_wide)
                    .expect("trial division degree fits in IsogenyInteger");
            }
            steps.push(QlapotiStep {
                degree,
                prime: divisor_wide,
                exponent,
                strategy: QlapotiStrategy::OddPrimePower,
            });
            divisor += 2;
        }

        if remaining > 1 {
            let strategy = if divisor > TRIAL_DIVISION_LIMIT {
                QlapotiStrategy::LargeComposite
            } else {
                QlapotiStrategy::OddPrimePower
            };
            steps.push(QlapotiStep {
                degree: remaining,
                prime: remaining,
                exponent: 1,
                strategy,
            });
        }

        QlapotiPlan {
            total_degree,
            steps,
        }
    }
}

impl QlapotiPlan {
    pub fn annotate_selected_degrees(
        &self,
        selected: &[IsogenyInteger],
    ) -> Option<Vec<QlapotiStepAnnotation>> {
        let mut cursor = 0usize;
        let mut annotations = Vec::with_capacity(self.steps.len());
        for (step_index, step) in self.steps.iter().enumerate() {
            let start = cursor;
            cursor = consume_selected_degrees_for_step(step, selected, cursor)?;
            annotations.push(QlapotiStepAnnotation {
                step_index: u16::try_from(step_index).ok()?,
                selected_start: u16::try_from(start).ok()?,
                selected_len: u16::try_from(cursor.checked_sub(start)?).ok()?,
                selected_degree_commitment: degree_list_commitment(&selected[start..cursor]),
            });
        }
        if cursor == selected.len() {
            Some(annotations)
        } else {
            None
        }
    }

    pub fn selected_degree_commitment(&self, selected: &[IsogenyInteger]) -> Option<[u8; 32]> {
        let annotations = self.annotate_selected_degrees(selected)?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"AURORA:isogeny:qlapoti:selected-degree-commitment:v1");
        hasher.update(self.total_degree.to_be_bytes_fixed());
        hasher.update((self.steps.len() as u32).to_be_bytes());
        for step in &self.steps {
            hasher.update(step.degree.to_be_bytes_fixed());
            hasher.update(step.prime.to_be_bytes_fixed());
            hasher.update(step.exponent.to_be_bytes());
            hasher.update([match step.strategy {
                QlapotiStrategy::TwoPower => 0,
                QlapotiStrategy::OddPrimePower => 1,
                QlapotiStrategy::LargeComposite => 2,
            }]);
        }
        hasher.update((annotations.len() as u32).to_be_bytes());
        for annotation in &annotations {
            hasher.update(annotation.commitment());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Some(out)
    }
}

fn degree_list_commitment(degrees: &[IsogenyInteger]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"AURORA:isogeny:qlapoti:selected-degrees:v1");
    hasher.update((degrees.len() as u32).to_be_bytes());
    for degree in degrees {
        hasher.update(degree.to_be_bytes_fixed());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn consume_selected_degrees_for_step(
    step: &QlapotiStep,
    selected: &[IsogenyInteger],
    mut cursor: usize,
) -> Option<usize> {
    if cursor >= selected.len() {
        return Some(cursor);
    }
    match step.strategy {
        QlapotiStrategy::TwoPower | QlapotiStrategy::OddPrimePower => {
            let prime = step.prime.try_to_u64()?;
            let mut remaining_exponent = step.exponent;
            while cursor < selected.len() {
                let Some(consumed_exponent) =
                    consume_prime_power_exponent(selected[cursor], prime, remaining_exponent)
                else {
                    break;
                };
                remaining_exponent -= consumed_exponent;
                cursor += 1;
                if remaining_exponent == 0 {
                    break;
                }
            }
            Some(cursor)
        }
        QlapotiStrategy::LargeComposite => {
            if selected[cursor] == step.degree {
                Some(cursor + 1)
            } else {
                Some(cursor)
            }
        }
    }
}

fn consume_prime_power_exponent(
    degree: IsogenyInteger,
    prime: u64,
    max_exponent: u32,
) -> Option<u32> {
    if degree < IsogenyInteger::from(prime) {
        return None;
    }
    let mut remaining = degree;
    let mut exponent = 0u32;
    while remaining.rem_u64(prime) == Some(0) && exponent < max_exponent {
        remaining = remaining.div_rem_u64(prime)?.0;
        exponent += 1;
    }
    if exponent == 0 || remaining != IsogenyInteger::one() {
        None
    } else {
        Some(exponent)
    }
}

#[cfg(test)]
mod tests {
    use super::{QlapotiEngine, QlapotiStrategy};
    use crate::crypto::isogeny::arith::IsogenyInteger;
    use crate::crypto::isogeny::ideal::ideal::LeftIdeal;
    use crate::crypto::isogeny::ideal::order::MaximalOrder;
    use crate::crypto::isogeny::ideal::quaternion::{QuaternionAlgebra, QuaternionElement};

    #[test]
    fn qlapoti_plan_splits_small_smooth_norm() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 1]),
            72,
        )
        .unwrap();
        let plan = QlapotiEngine::plan_for_ideal(&ideal);
        assert_eq!(plan.total_degree, 72);
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].degree, 8);
        assert_eq!(plan.steps[0].strategy, QlapotiStrategy::TwoPower);
        assert_eq!(plan.steps[1].degree, 9);
        assert_eq!(plan.steps[1].strategy, QlapotiStrategy::OddPrimePower);
    }

    #[test]
    fn qlapoti_plan_for_degree_matches_ideal_norm_plan() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 1]),
            72,
        )
        .unwrap();
        assert_eq!(
            QlapotiEngine::plan_for_degree(ideal.norm()),
            QlapotiEngine::plan_for_ideal(&ideal)
        );
    }

    #[test]
    fn qlapoti_plan_marks_large_composites() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 0, 1, 1]),
            (1u128 << 80) + 7,
        )
        .unwrap();
        let plan = QlapotiEngine::plan_for_ideal(&ideal);
        assert_eq!(
            plan.steps.last().unwrap().strategy,
            QlapotiStrategy::LargeComposite
        );
    }

    #[test]
    fn qlapoti_plan_trial_divides_wide_smooth_degrees() {
        let degree = IsogenyInteger::pow2(140)
            .unwrap()
            .checked_mul(&IsogenyInteger::from(45u64))
            .unwrap();
        let plan = QlapotiEngine::plan_for_degree(degree);
        assert_eq!(plan.total_degree, degree);
        assert_eq!(plan.steps.len(), 3);
        assert_eq!(plan.steps[0].degree, IsogenyInteger::pow2(140).unwrap());
        assert_eq!(plan.steps[0].strategy, QlapotiStrategy::TwoPower);
        assert_eq!(plan.steps[1].degree, IsogenyInteger::from(9u64));
        assert_eq!(plan.steps[1].strategy, QlapotiStrategy::OddPrimePower);
        assert_eq!(plan.steps[2].degree, IsogenyInteger::from(5u64));
        assert_eq!(plan.steps[2].strategy, QlapotiStrategy::OddPrimePower);
    }

    #[test]
    fn qlapoti_annotations_accept_ordered_subdecompositions() {
        let plan = QlapotiEngine::plan_for_degree(360u64);
        let annotations = plan
            .annotate_selected_degrees(&[
                IsogenyInteger::from(4u64),
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(9u64),
            ])
            .unwrap();
        assert_eq!(annotations.len(), 3);
        assert_eq!(annotations[0].selected_start, 0);
        assert_eq!(annotations[0].selected_len, 2);
        assert_eq!(annotations[1].selected_start, 2);
        assert_eq!(annotations[1].selected_len, 1);
        assert_eq!(annotations[2].selected_len, 0);
    }

    #[test]
    fn qlapoti_annotations_reject_out_of_order_subdecompositions() {
        let plan = QlapotiEngine::plan_for_degree(360u64);
        assert!(plan
            .annotate_selected_degrees(&[
                IsogenyInteger::from(9u64),
                IsogenyInteger::from(4u64),
                IsogenyInteger::from(2u64),
            ])
            .is_none());
    }

    #[test]
    fn qlapoti_selected_degree_commitment_depends_on_grouping() {
        let plan = QlapotiEngine::plan_for_degree(360u64);
        let left = plan
            .selected_degree_commitment(&[IsogenyInteger::from(8u64), IsogenyInteger::from(5u64)])
            .unwrap();
        let right = plan
            .selected_degree_commitment(&[
                IsogenyInteger::from(4u64),
                IsogenyInteger::from(2u64),
                IsogenyInteger::from(5u64),
            ])
            .unwrap();
        assert_ne!(left, right);
    }
}
