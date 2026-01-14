#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 2;
const SYS_SLEEP: u64 = 4;
const SYS_NET_LISTEN: u64 = 10;
const SYS_NET_ACCEPT: u64 = 11;
const SYS_NET_RECV: u64 = 12;
const SYS_NET_SEND: u64 = 13;
const SYS_NET_CLOSE: u64 = 14;
const LISTEN_PORT: u64 = 1234;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let msg = b"Hello from userland\n";
    unsafe {
        syscall3(SYS_WRITE, 1, msg.as_ptr() as u64, msg.len() as u64);
        syscall1(SYS_EXIT, 0);
    }
    let mut listened = false;
    loop {
        unsafe {
            if !listened {
                listened = syscall1(SYS_NET_LISTEN, LISTEN_PORT) == 0;
            }
            if syscall0(SYS_NET_ACCEPT) == 1 {
                let mut buf = [0u8; 512];
                let n = syscall2(SYS_NET_RECV, buf.as_mut_ptr() as u64, buf.len() as u64);
                if n != u64::MAX && n > 0 {
                    let _ = syscall2(SYS_NET_SEND, buf.as_ptr() as u64, n);
                } else if n == u64::MAX {
                    let _ = syscall0(SYS_NET_CLOSE);
                }
            } else {
                syscall1(SYS_SLEEP, 10);
            }
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

unsafe fn syscall2(num: u64, a1: u64, a2: u64) -> u64 {
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
