pub unsafe fn syscall0(_num: u64) -> u64 {
    u64::MAX
}

pub unsafe fn syscall1(_num: u64, _a1: u64) -> u64 {
    u64::MAX
}

#[allow(dead_code)]
pub unsafe fn syscall2(_num: u64, _a1: u64, _a2: u64) -> u64 {
    u64::MAX
}

pub unsafe fn syscall3(_num: u64, _a1: u64, _a2: u64, _a3: u64) -> u64 {
    u64::MAX
}
