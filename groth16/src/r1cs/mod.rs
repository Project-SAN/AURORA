use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg};
use ark_ff::Field;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VariableType {
    Input,
    Aux,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variable {
    pub index: usize,
    pub var_type: VariableType,
}

impl Variable {
    pub fn new(index: usize, var_type: VariableType) -> Self {
        Self { index, var_type }
    }

    pub fn is_input(&self) -> bool {
        matches!(self.var_type, VariableType::Input)
    }
}

#[derive(Clone, Debug)]
pub struct LinearCombination<F: Field> {
    pub terms: Vec<(Variable, F)>,
    pub constant: F,
}

impl<F: Field> LinearCombination<F> {
    pub fn zero() -> Self {
        Self {
            terms: Vec::new(),
            constant: F::zero(),
        }
    }

    pub fn with_constant(constant: F) -> Self {
        Self {
            terms: Vec::new(),
            constant,
        }
    }

    pub fn push_term(&mut self, var: Variable, coeff: F) {
        self.terms.push((var, coeff));
    }

    pub fn eval(&self, inputs: &[F], aux: &[F]) -> F {
        let mut acc = self.constant;
        for (var, coeff) in &self.terms {
            let value = match var.var_type {
                VariableType::Input => inputs[var.index],
                VariableType::Aux => aux[var.index],
            };
            acc += *coeff * value;
        }
        acc
    }
}

impl<F: Field> Default for LinearCombination<F> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<F: Field> From<Variable> for LinearCombination<F> {
    fn from(var: Variable) -> Self {
        let mut lc = LinearCombination::zero();
        lc.push_term(var, F::one());
        lc
    }
}

impl<F: Field> From<F> for LinearCombination<F> {
    fn from(value: F) -> Self {
        LinearCombination::with_constant(value)
    }
}

impl<F: Field> Add for LinearCombination<F> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.constant += rhs.constant;
        self.terms.extend(rhs.terms);
        self
    }
}

impl<F: Field> AddAssign for LinearCombination<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.constant += rhs.constant;
        self.terms.extend(rhs.terms.iter().cloned());
    }
}

impl<F: Field> Neg for LinearCombination<F> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.constant = -self.constant;
        for (_, coeff) in &mut self.terms {
            *coeff = -*coeff;
        }
        self
    }
}

impl<F: Field> Mul<F> for LinearCombination<F> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self::Output {
        self.constant *= rhs;
        for (_, coeff) in &mut self.terms {
            *coeff *= rhs;
        }
        self
    }
}

impl<F: Field> MulAssign<F> for LinearCombination<F> {
    fn mul_assign(&mut self, rhs: F) {
        self.constant *= rhs;
        for (_, coeff) in &mut self.terms {
            *coeff *= rhs;
        }
    }
}

#[derive(Clone, Debug)]
pub struct Constraint<F: Field> {
    pub a: LinearCombination<F>,
    pub b: LinearCombination<F>,
    pub c: LinearCombination<F>,
}

impl<F: Field> Constraint<F> {
    pub fn new(a: LinearCombination<F>, b: LinearCombination<F>, c: LinearCombination<F>) -> Self {
        Self { a, b, c }
    }
}

pub struct ConstraintSystem<F: Field> {
    pub inputs: Vec<F>,
    pub aux: Vec<F>,
    pub constraints: Vec<Constraint<F>>,
}

impl<F: Field> ConstraintSystem<F> {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            aux: Vec::new(),
            constraints: Vec::new(),
        }
    }

    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    pub fn num_aux(&self) -> usize {
        self.aux.len()
    }

    pub fn alloc_input(&mut self, value: F) -> Variable {
        let index = self.inputs.len();
        self.inputs.push(value);
        Variable::new(index, VariableType::Input)
    }

    pub fn alloc_aux(&mut self, value: F) -> Variable {
        let index = self.aux.len();
        self.aux.push(value);
        Variable::new(index, VariableType::Aux)
    }

    pub fn enforce(&mut self, a: LinearCombination<F>, b: LinearCombination<F>, c: LinearCombination<F>) {
        self.constraints.push(Constraint::new(a, b, c));
    }

    pub fn is_satisfied(&self) -> bool {
        self.constraints.iter().all(|constraint| {
            let a = constraint.a.eval(&self.inputs, &self.aux);
            let b = constraint.b.eval(&self.inputs, &self.aux);
            let c = constraint.c.eval(&self.inputs, &self.aux);
            a * b == c
        })
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn simple_mul_constraint() {
        let mut cs = ConstraintSystem::<Fr>::new();
        let x = cs.alloc_input(Fr::from(3u64));
        let y = cs.alloc_aux(Fr::from(11u64));
        let product = Fr::from(33u64);

        let a = LinearCombination::from(x);
        let b = LinearCombination::from(y);
        let c = LinearCombination::from(product);

        cs.enforce(a, b, c);
        assert!(cs.is_satisfied());
    }
}
