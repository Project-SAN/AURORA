#[cfg(target_arch = "x86_64")]
pub mod gdt;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub mod mmu;
pub mod syscall;

#[cfg(target_arch = "x86_64")]
pub fn init(kernel_stack_top: u64) {
    gdt::init(kernel_stack_top);
    enable_fpu_sse();
    syscall::init(kernel_stack_top);
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub fn init(kernel_stack_top: u64) {
    let _ = kernel_stack_top;
    syscall::init(kernel_stack_top);
}

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
)))]
pub fn init(_kernel_stack_top: u64) {}

#[cfg(target_arch = "x86_64")]
fn enable_fpu_sse() {
    unsafe {
        let mut cr0: u64;
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        // Clear EM (bit 2) to enable FPU, set MP (bit 1) and NE (bit 5)
        cr0 &= !(1 << 2);
        cr0 |= 1 << 1;
        cr0 |= 1 << 5;
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));

        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        // OSFXSR (bit 9) and OSXMMEXCPT (bit 10)
        cr4 |= 1 << 9;
        cr4 |= 1 << 10;
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));

        core::arch::asm!("fninit", options(nomem, nostack, preserves_flags));
    }
}
