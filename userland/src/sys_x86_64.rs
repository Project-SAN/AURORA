#![cfg(target_arch = "x86_64")]

use core::arch::asm;

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

#[allow(dead_code)]
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
