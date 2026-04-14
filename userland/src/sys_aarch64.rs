#![cfg(target_arch = "aarch64")]

use core::arch::asm;

pub unsafe fn syscall0(num: u64) -> u64 {
    let ret: u64;
    asm!(
        "svc #0",
        inlateout("x0") 0u64 => ret,
        in("x1") 0u64,
        in("x2") 0u64,
        in("x8") num,
        lateout("x3") _,
        lateout("x4") _,
        lateout("x5") _,
        lateout("x6") _,
        lateout("x7") _,
        lateout("x9") _,
        lateout("x10") _,
        lateout("x11") _,
        lateout("x12") _,
        lateout("x13") _,
        lateout("x14") _,
        lateout("x15") _,
        lateout("x16") _,
        lateout("x17") _,
        options(nostack)
    );
    ret
}

pub unsafe fn syscall3(num: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    asm!(
        "svc #0",
        inlateout("x0") a1 => ret,
        in("x1") a2,
        in("x2") a3,
        in("x8") num,
        lateout("x3") _,
        lateout("x4") _,
        lateout("x5") _,
        lateout("x6") _,
        lateout("x7") _,
        lateout("x9") _,
        lateout("x10") _,
        lateout("x11") _,
        lateout("x12") _,
        lateout("x13") _,
        lateout("x14") _,
        lateout("x15") _,
        lateout("x16") _,
        lateout("x17") _,
        options(nostack)
    );
    ret
}
