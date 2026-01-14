#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 2;
const SYS_YIELD: u64 = 3;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let msg = b"Hello from userland\n";
    unsafe {
        syscall3(SYS_WRITE, 1, msg.as_ptr() as u64, msg.len() as u64);
        syscall1(SYS_EXIT, 0);
    }
    loop {
        unsafe {
            syscall0(SYS_YIELD);
            asm!("pause");
        }
    }
}

unsafe fn syscall3(num: u64, a1: u64, a2: u64, a3: u64) -> u64 {
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

unsafe fn syscall1(num: u64, a1: u64) -> u64 {
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

unsafe fn syscall0(num: u64) -> u64 {
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { asm!("pause"); }
    }
}
