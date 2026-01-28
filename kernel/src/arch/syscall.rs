#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use core::arch::{asm, naked_asm};

#[cfg(target_arch = "x86_64")]
use crate::arch::gdt;

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

#[repr(C)]
struct KernelGsBase {
    kernel_rsp: u64,
    user_rsp: u64,
}

static mut KERNEL_GS_BASE: KernelGsBase = KernelGsBase {
    kernel_rsp: 0,
    user_rsp: 0,
};

#[repr(C)]
pub struct SyscallFrame {
    pub rax: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

#[cfg(target_arch = "x86_64")]
pub fn init(kernel_stack_top: u64) {
    unsafe {
        KERNEL_GS_BASE.kernel_rsp = kernel_stack_top;
        KERNEL_GS_BASE.user_rsp = 0;
        wrmsr(
            IA32_KERNEL_GS_BASE,
            &raw const KERNEL_GS_BASE as *const _ as u64,
        );
        wrmsr(IA32_GS_BASE, 0);

        let user_base = (gdt::USER_CODE as u64).saturating_sub(0x10);
        let star = (user_base << 48) | ((gdt::KERNEL_CODE as u64) << 32);
        wrmsr(IA32_STAR, star);
        wrmsr(IA32_LSTAR, syscall_entry as *const () as u64);
        wrmsr(IA32_FMASK, 1 << 9); // clear IF on entry
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | 1);
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn init(_kernel_stack_top: u64) {}

#[cfg(target_arch = "x86_64")]
pub fn read_efer() -> u64 {
    unsafe { rdmsr(IA32_EFER) }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn read_efer() -> u64 {
    0
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
extern "C" fn syscall_entry() -> ! {
    naked_asm!(
        "swapgs",
        "mov qword ptr gs:[8], rsp",
        "mov rsp, qword ptr gs:[0]",
        "sub rsp, 8",
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rbp",
        "push rax",
        "mov rcx, rsp",
        "sub rsp, 32",
        "call {dispatch}",
        "add rsp, 32",
        "pop rax",
        "pop rbp",
        "pop rbx",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "add rsp, 8",
        "mov rsp, qword ptr gs:[8]",
        "swapgs",
        "sysretq",
        dispatch = sym crate::syscall::dispatch,
    );
}

#[cfg(target_arch = "x86_64")]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn rdmsr(_msr: u32) -> u64 {
    0
}

#[cfg(target_arch = "x86_64")]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nostack, preserves_flags)
    );
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn wrmsr(_msr: u32, _value: u64) {}
