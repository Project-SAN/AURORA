#[cfg(feature = "hornet-time")]
use hornet::time::TimeProvider;

#[cfg(feature = "hornet-time")]
#[allow(dead_code)]
pub struct SysTimeProvider;

#[cfg(feature = "hornet-time")]
impl TimeProvider for SysTimeProvider {
    fn now_coarse(&self) -> u32 {
        let secs = crate::sys::time_epoch().unwrap_or(0);
        secs.min(u32::MAX as u64) as u32
    }
}
