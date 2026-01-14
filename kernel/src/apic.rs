use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::hpet::Hpet;

const IA32_APIC_BASE: u32 = 0x1B;
const IA32_APIC_BASE_ENABLE: u64 = 1 << 11;
const IA32_APIC_BASE_X2: u64 = 1 << 10;

const APIC_REG_EOI: u32 = 0x0B0;
const APIC_REG_SVR: u32 = 0x0F0;
const APIC_REG_LVT_TIMER: u32 = 0x320;
const APIC_REG_INIT_COUNT: u32 = 0x380;
const APIC_REG_CUR_COUNT: u32 = 0x390;
const APIC_REG_DIVIDE: u32 = 0x3E0;

static X2APIC: AtomicBool = AtomicBool::new(false);
static APIC_BASE: AtomicU64 = AtomicU64::new(0);

pub fn init(local_apic_base: u64, timer_vector: u8, hpet: &Hpet) {
    let x2 = has_x2apic();
    X2APIC.store(x2, Ordering::Release);

    let mut apic_base = rdmsr(IA32_APIC_BASE);
    apic_base |= IA32_APIC_BASE_ENABLE;
    if x2 {
        apic_base |= IA32_APIC_BASE_X2;
    } else {
        apic_base &= !IA32_APIC_BASE_X2;
    }
    wrmsr(IA32_APIC_BASE, apic_base);

    let base = if x2 {
        0
    } else {
        local_apic_base
    };
    APIC_BASE.store(base, Ordering::Release);

    // Spurious interrupt vector register: enable APIC (bit 8) + vector.
    write_reg(APIC_REG_SVR, 0x100 | 0xFF);

    // Divide by 16.
    write_reg(APIC_REG_DIVIDE, 0x3);

    // Mask timer while calibrating.
    write_reg(APIC_REG_LVT_TIMER, (timer_vector as u32) | (1 << 16));

    calibrate_timer(timer_vector, hpet);
}

pub fn eoi() {
    write_reg(APIC_REG_EOI, 0);
}

fn calibrate_timer(timer_vector: u8, hpet: &Hpet) {
    // One-shot max count.
    write_reg(APIC_REG_INIT_COUNT, 0xFFFF_FFFF);

    let start = hpet.ticks();
    let target = start + hpet.ticks_per_ms() * 10;
    while hpet.ticks() < target {
        unsafe { asm!("pause"); }
    }

    let current = read_reg(APIC_REG_CUR_COUNT);
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(current);
    let ticks_per_ms = elapsed / 10;

    // 100Hz periodic.
    let initial = ticks_per_ms.saturating_mul(10).max(1);
    let lvt = (timer_vector as u32) | (1 << 17); // periodic
    write_reg(APIC_REG_LVT_TIMER, lvt);
    write_reg(APIC_REG_INIT_COUNT, initial);
}

fn write_reg(offset: u32, value: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(0x800 + (offset >> 4), value as u64);
    } else {
        let base = APIC_BASE.load(Ordering::Relaxed);
        unsafe {
            core::ptr::write_volatile((base + offset as u64) as *mut u32, value);
        }
    }
}

fn read_reg(offset: u32) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        rdmsr(0x800 + (offset >> 4)) as u32
    } else {
        let base = APIC_BASE.load(Ordering::Relaxed);
        unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
    }
}

fn has_x2apic() -> bool {
    let info = __cpuid(1);
    (info.ecx & (1 << 21)) != 0
}

fn rdmsr(msr: u32) -> u64 {
    let high: u32;
    let low: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("edx") high,
            out("eax") low,
            options(nomem, nostack)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

fn wrmsr(msr: u32, value: u64) {
    let high = (value >> 32) as u32;
    let low = value as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("edx") high,
            in("eax") low,
            options(nomem, nostack)
        );
    }
}
