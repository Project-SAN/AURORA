#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
use core::arch::{asm, global_asm, naked_asm};
#[cfg(target_arch = "x86_64")]
use core::arch::{asm, naked_asm};

#[cfg(target_arch = "x86_64")]
use crate::arch::gdt;

#[cfg(target_arch = "x86_64")]
const IA32_EFER: u32 = 0xC000_0080;
#[cfg(target_arch = "x86_64")]
const IA32_STAR: u32 = 0xC000_0081;
#[cfg(target_arch = "x86_64")]
const IA32_LSTAR: u32 = 0xC000_0082;
#[cfg(target_arch = "x86_64")]
const IA32_FMASK: u32 = 0xC000_0084;
#[cfg(target_arch = "x86_64")]
const IA32_GS_BASE: u32 = 0xC000_0101;
#[cfg(target_arch = "x86_64")]
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct KernelGsBase {
    kernel_rsp: u64,
    user_rsp: u64,
}

#[cfg(target_arch = "x86_64")]
static mut KERNEL_GS_BASE: KernelGsBase = KernelGsBase {
    kernel_rsp: 0,
    user_rsp: 0,
};

#[cfg(target_arch = "x86_64")]
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
impl SyscallFrame {
    pub fn number(&self) -> u64 {
        self.rax
    }

    pub fn arg0(&self) -> u64 {
        self.rdi
    }

    pub fn arg1(&self) -> u64 {
        self.rsi
    }

    pub fn arg2(&self) -> u64 {
        self.rdx
    }

    pub fn set_ret(&mut self, value: u64) {
        self.rax = value;
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
#[repr(C)]
pub struct SyscallFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub pad0: u64,
    pub spsr_el1: u64,
    pub elr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
impl SyscallFrame {
    pub fn number(&self) -> u64 {
        self.x8
    }

    pub fn arg0(&self) -> u64 {
        self.x0
    }

    pub fn arg1(&self) -> u64 {
        self.x1
    }

    pub fn arg2(&self) -> u64 {
        self.x2
    }

    pub fn set_ret(&mut self, value: u64) {
        self.x0 = value;
    }

    fn exception_class(&self) -> u64 {
        (self.esr_el1 >> 26) & 0x3f
    }

    fn svc_imm(&self) -> u64 {
        self.esr_el1 & 0xffff
    }
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
        wrmsr(IA32_FMASK, 1 << 9);
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | 1);
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub fn init(_kernel_stack_top: u64) {
    let vectors = &raw const aurora_aarch64_vectors as *const u8 as u64;
    unsafe {
        asm!(
            "msr SPSel, #1",
            "msr VBAR_EL1, {vectors}",
            "isb",
            vectors = in(reg) vectors,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
)))]
pub fn init(_kernel_stack_top: u64) {}

#[cfg(target_arch = "x86_64")]
pub fn read_efer() -> u64 {
    unsafe { rdmsr(IA32_EFER) }
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub fn current_el() -> u64 {
    let current_el: u64;
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) current_el, options(nomem, nostack, preserves_flags));
    }
    (current_el >> 2) & 0x3
}

#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn current_el() -> u64 {
    0
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub fn vector_base() -> u64 {
    let vbar: u64;
    unsafe {
        asm!("mrs {}, VBAR_EL1", out(reg) vbar, options(nomem, nostack, preserves_flags));
    }
    vbar
}

#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn vector_base() -> u64 {
    0
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub fn self_test() -> bool {
    const TEST_MSG: &[u8] = b"AArch64 SVC dispatch path\n";
    let ret: u64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") 1u64 => ret,
            in("x1") TEST_MSG.as_ptr() as u64,
            in("x2") TEST_MSG.len() as u64,
            in("x8") 1u64,
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
    }
    ret == TEST_MSG.len() as u64
}

#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn self_test() -> bool {
    false
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

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
const ESR_EC_SVC64: u64 = 0x15;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
const AARCH64_FRAME_SIZE: usize = core::mem::size_of::<SyscallFrame>();

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
global_asm!(
    r#"
    .section .text.aurora_aarch64_vectors,"ax"
    .align 11
    .global aurora_aarch64_vectors
aurora_aarch64_vectors:
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    b {sync}
    .balign 128
    b {irq}
    .balign 128
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    b {sync}
    .balign 128
    b {irq}
    .balign 128
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    b {unhandled}
    .balign 128
    "#,
    sync = sym aarch64_sync_entry,
    irq = sym aarch64_irq_entry,
    unhandled = sym aarch64_unhandled_vector,
);

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
unsafe extern "C" {
    static aurora_aarch64_vectors: u8;
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
#[unsafe(naked)]
extern "C" fn aarch64_sync_entry() -> ! {
    naked_asm!(
        "sub sp, sp, #{frame_size}",
        "stp x0, x1, [sp, #0x00]",
        "stp x2, x3, [sp, #0x10]",
        "stp x4, x5, [sp, #0x20]",
        "stp x6, x7, [sp, #0x30]",
        "stp x8, x9, [sp, #0x40]",
        "stp x10, x11, [sp, #0x50]",
        "stp x12, x13, [sp, #0x60]",
        "stp x14, x15, [sp, #0x70]",
        "stp x16, x17, [sp, #0x80]",
        "stp x18, x19, [sp, #0x90]",
        "stp x20, x21, [sp, #0xa0]",
        "stp x22, x23, [sp, #0xb0]",
        "stp x24, x25, [sp, #0xc0]",
        "stp x26, x27, [sp, #0xd0]",
        "stp x28, x29, [sp, #0xe0]",
        "str x30, [sp, #0xf0]",
        "str xzr, [sp, #0xf8]",
        "mrs x9, SPSR_EL1",
        "mrs x10, ELR_EL1",
        "mrs x11, ESR_EL1",
        "mrs x12, FAR_EL1",
        "str x9, [sp, #0x100]",
        "str x10, [sp, #0x108]",
        "str x11, [sp, #0x110]",
        "str x12, [sp, #0x118]",
        "mov x0, sp",
        "bl {dispatch}",
        "ldr x9, [sp, #0x100]",
        "ldr x10, [sp, #0x108]",
        "msr SPSR_EL1, x9",
        "msr ELR_EL1, x10",
        "ldp x0, x1, [sp, #0x00]",
        "ldp x2, x3, [sp, #0x10]",
        "ldp x4, x5, [sp, #0x20]",
        "ldp x6, x7, [sp, #0x30]",
        "ldp x8, x9, [sp, #0x40]",
        "ldp x10, x11, [sp, #0x50]",
        "ldp x12, x13, [sp, #0x60]",
        "ldp x14, x15, [sp, #0x70]",
        "ldp x16, x17, [sp, #0x80]",
        "ldp x18, x19, [sp, #0x90]",
        "ldp x20, x21, [sp, #0xa0]",
        "ldp x22, x23, [sp, #0xb0]",
        "ldp x24, x25, [sp, #0xc0]",
        "ldp x26, x27, [sp, #0xd0]",
        "ldp x28, x29, [sp, #0xe0]",
        "ldr x30, [sp, #0xf0]",
        "add sp, sp, #{frame_size}",
        "eret",
        frame_size = const AARCH64_FRAME_SIZE,
        dispatch = sym aarch64_sync_dispatch,
    );
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
#[unsafe(naked)]
extern "C" fn aarch64_irq_entry() -> ! {
    naked_asm!(
        "sub sp, sp, #{frame_size}",
        "stp x0, x1, [sp, #0x00]",
        "stp x2, x3, [sp, #0x10]",
        "stp x4, x5, [sp, #0x20]",
        "stp x6, x7, [sp, #0x30]",
        "stp x8, x9, [sp, #0x40]",
        "stp x10, x11, [sp, #0x50]",
        "stp x12, x13, [sp, #0x60]",
        "stp x14, x15, [sp, #0x70]",
        "stp x16, x17, [sp, #0x80]",
        "stp x18, x19, [sp, #0x90]",
        "stp x20, x21, [sp, #0xa0]",
        "stp x22, x23, [sp, #0xb0]",
        "stp x24, x25, [sp, #0xc0]",
        "stp x26, x27, [sp, #0xd0]",
        "stp x28, x29, [sp, #0xe0]",
        "str x30, [sp, #0xf0]",
        "str xzr, [sp, #0xf8]",
        "mrs x9, SPSR_EL1",
        "mrs x10, ELR_EL1",
        "mrs x11, ESR_EL1",
        "mrs x12, FAR_EL1",
        "str x9, [sp, #0x100]",
        "str x10, [sp, #0x108]",
        "str x11, [sp, #0x110]",
        "str x12, [sp, #0x118]",
        "mov x0, sp",
        "bl {dispatch}",
        "ldr x9, [sp, #0x100]",
        "ldr x10, [sp, #0x108]",
        "msr SPSR_EL1, x9",
        "msr ELR_EL1, x10",
        "ldp x0, x1, [sp, #0x00]",
        "ldp x2, x3, [sp, #0x10]",
        "ldp x4, x5, [sp, #0x20]",
        "ldp x6, x7, [sp, #0x30]",
        "ldp x8, x9, [sp, #0x40]",
        "ldp x10, x11, [sp, #0x50]",
        "ldp x12, x13, [sp, #0x60]",
        "ldp x14, x15, [sp, #0x70]",
        "ldp x16, x17, [sp, #0x80]",
        "ldp x18, x19, [sp, #0x90]",
        "ldp x20, x21, [sp, #0xa0]",
        "ldp x22, x23, [sp, #0xb0]",
        "ldp x24, x25, [sp, #0xc0]",
        "ldp x26, x27, [sp, #0xd0]",
        "ldp x28, x29, [sp, #0xe0]",
        "ldr x30, [sp, #0xf0]",
        "add sp, sp, #{frame_size}",
        "eret",
        frame_size = const AARCH64_FRAME_SIZE,
        dispatch = sym aarch64_irq_dispatch,
    );
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
#[unsafe(naked)]
extern "C" fn aarch64_unhandled_vector() -> ! {
    naked_asm!(
        "mrs x0, CurrentEL",
        "mrs x1, ESR_EL1",
        "mrs x2, ELR_EL1",
        "mrs x3, FAR_EL1",
        "b {handler}",
        handler = sym aarch64_unhandled_exception,
    );
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
extern "C" fn aarch64_sync_dispatch(frame: &mut SyscallFrame) {
    if frame.exception_class() == ESR_EC_SVC64 {
        crate::syscall::dispatch(frame);
        return;
    }

    crate::serial::write(format_args!(
        "AArch64 sync fault: ec={:#x} imm={:#x} esr={:#x} elr={:#x} far={:#x}\n",
        frame.exception_class(),
        frame.svc_imm(),
        frame.esr_el1,
        frame.elr_el1,
        frame.far_el1
    ));
    halt_forever();
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
extern "C" fn aarch64_irq_dispatch(_frame: &mut SyscallFrame) {
    crate::interrupts::handle_irq();
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
extern "C" fn aarch64_unhandled_exception(current_el: u64, esr: u64, elr: u64, far: u64) -> ! {
    crate::serial::write(format_args!(
        "AArch64 unhandled exception: el={} esr={:#x} elr={:#x} far={:#x}\n",
        (current_el >> 2) & 0x3,
        esr,
        elr,
        far
    ));
    halt_forever();
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
fn halt_forever() -> ! {
    loop {
        unsafe {
            asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
    ((hi as u64) << 32) | (lo as u64)
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
