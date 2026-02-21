use aurora::time::TimeProvider;

pub struct SysTimeProvider;

impl TimeProvider for SysTimeProvider {
    fn now_coarse(&self) -> u32 {
        let secs = crate::sys::time_epoch().unwrap_or(0);
        secs.min(u32::MAX as u64) as u32
    }
}
