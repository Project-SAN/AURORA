pub trait TimeProvider {
    // Returns coarse-grained epoch seconds used for EXP checks.
    fn now_coarse(&self) -> u32;
}

#[cfg(feature = "std")]
pub struct SystemTimeProvider;

#[cfg(feature = "std")]
impl TimeProvider for SystemTimeProvider {
    fn now_coarse(&self) -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0));
        now.as_secs() as u32
    }
}
