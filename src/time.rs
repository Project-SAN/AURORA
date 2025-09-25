pub trait TimeProvider {
    // Returns coarse-grained epoch seconds used for EXP checks.
    fn now_coarse(&self) -> u32;
}
