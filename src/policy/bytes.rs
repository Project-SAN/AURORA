use dusk_plonk::prelude::{BlsScalar, Composer, Witness};

#[derive(Clone, Copy, Debug)]
pub struct Byte {
    pub value: u8,
    pub witness: Witness,
}

impl Byte {
    pub fn witness<C: Composer>(composer: &mut C, value: u8) -> Self {
        let witness = composer.append_witness(BlsScalar::from(value as u64));
        composer.component_range(witness, 8);
        Self { value, witness }
    }

    pub fn constant<C: Composer>(composer: &mut C, value: u8) -> Self {
        let witness = composer.append_witness(BlsScalar::from(value as u64));
        composer.assert_equal_constant(witness, BlsScalar::from(value as u64), None);
        composer.component_range(witness, 8);
        Self { value, witness }
    }
}
