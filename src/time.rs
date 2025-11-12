pub trait TimeProvider {
    // Returns coarse-grained epoch seconds used for EXP checks.
    fn now_coarse(&self) -> u32;
}

#[cfg(feature = "std")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "std")]
pub struct SystemTimeProvider;

#[cfg(feature = "std")]
impl TimeProvider for SystemTimeProvider {
    fn now_coarse(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));
        now.as_secs() as u32
    }
}
