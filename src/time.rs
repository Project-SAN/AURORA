pub trait TimeProvider {
    // Returns coarse-grained epoch seconds used for EXP checks.
    fn now_coarse(&self) -> u32;
}

pub struct EpochSecondsProvider<F> {
    now: F,
}

impl<F> EpochSecondsProvider<F>
where
    F: Fn() -> u64,
{
    pub const fn new(now: F) -> Self {
        Self { now }
    }
}

impl<F> TimeProvider for EpochSecondsProvider<F>
where
    F: Fn() -> u64,
{
    fn now_coarse(&self) -> u32 {
        let secs = (self.now)();
        secs.min(u32::MAX as u64) as u32
    }
}
