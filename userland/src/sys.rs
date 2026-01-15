use core::arch::asm;

pub const SYS_WRITE: u64 = 1;
pub const SYS_SLEEP: u64 = 4;
pub const SYS_NET_RECV: u64 = 12;
pub const SYS_NET_SEND: u64 = 13;
pub const SYS_NET_CLOSE: u64 = 14;
pub const SYS_NET_CONNECT: u64 = 15;
pub const SYS_TIME_EPOCH: u64 = 16;

pub fn write(fd: u64, buf: &[u8]) -> u64 {
    unsafe { syscall3(SYS_WRITE, fd, buf.as_ptr() as u64, buf.len() as u64) }
}

pub fn sleep(ms: u64) {
    unsafe {
        let _ = syscall1(SYS_SLEEP, ms);
    }
}

pub fn time_epoch() -> Option<u64> {
    let ret = unsafe { syscall0(SYS_TIME_EPOCH) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret)
    }
}

pub unsafe fn syscall0(num: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        inlateout("rax") num => ret,
        in("rdi") 0u64,
        in("rsi") 0u64,
        in("rdx") 0u64,
        in("r10") 0u64,
        in("r8") 0u64,
        in("r9") 0u64,
        lateout("rcx") _,
        lateout("r11") _,
    );
    ret
}

pub unsafe fn syscall1(num: u64, a1: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        inlateout("rax") num => ret,
        in("rdi") a1,
        in("rsi") 0u64,
        in("rdx") 0u64,
        in("r10") 0u64,
        in("r8") 0u64,
        in("r9") 0u64,
        lateout("rcx") _,
        lateout("r11") _,
    );
    ret
}

pub unsafe fn syscall2(num: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        inlateout("rax") num => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") 0u64,
        in("r10") 0u64,
        in("r8") 0u64,
        in("r9") 0u64,
        lateout("rcx") _,
        lateout("r11") _,
    );
    ret
}

pub unsafe fn syscall3(num: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        inlateout("rax") num => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") 0u64,
        in("r8") 0u64,
        in("r9") 0u64,
        lateout("rcx") _,
        lateout("r11") _,
    );
    ret
}
