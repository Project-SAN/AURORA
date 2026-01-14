use core::ptr::{write_bytes, write_volatile};

use crate::memory;

const PAGE_SIZE: u64 = 4096;
const ENTRIES: usize = 512;
const HUGE_PAGE: u64 = 1 << 7;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const FLAGS: u64 = PRESENT | WRITABLE;

pub const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
const KERNEL_PML4_INDEX: usize = ((KERNEL_BASE >> 39) & 0x1ff) as usize;

#[inline]
pub fn to_higher_half(phys: u64) -> u64 {
    KERNEL_BASE + phys
}

pub fn init_identity_4g() -> Option<u64> {
    let pml4_phys = memory::alloc_contiguous(1)?;
    let pdpt_phys = memory::alloc_contiguous(1)?;
    zero_page(pml4_phys);
    zero_page(pdpt_phys);

    let mut pd_phys = [0u64; 4];
    for slot in pd_phys.iter_mut() {
        let phys = memory::alloc_contiguous(1)?;
        zero_page(phys);
        *slot = phys;
    }

    // Link PML4[0] -> PDPT (identity)
    write_entry(pml4_phys, 0, pdpt_phys | FLAGS);
    // Link PML4[KERNEL_PML4_INDEX] -> same PDPT (higher-half alias)
    write_entry(pml4_phys, KERNEL_PML4_INDEX, pdpt_phys | FLAGS);

    // Link PDPT[0..4] -> PDs and populate 2MiB entries.
    for (i, pd) in pd_phys.iter().enumerate() {
        write_entry(pdpt_phys, i, *pd | FLAGS);
        populate_pd(*pd, i as u64);
    }

    Some(pml4_phys)
}

pub unsafe fn switch_to(pml4_phys: u64) {
    core::arch::asm!("mov cr3, {}", in(reg) pml4_phys, options(nostack, preserves_flags));
}

fn populate_pd(pd_phys: u64, pd_index: u64) {
    let base = pd_index * ENTRIES as u64 * 0x200000;
    for i in 0..ENTRIES {
        let addr = base + (i as u64) * 0x200000;
        let entry = addr | FLAGS | HUGE_PAGE;
        write_entry(pd_phys, i, entry);
    }
}

fn zero_page(phys: u64) {
    unsafe {
        let ptr = memory::phys_to_virt(phys);
        write_bytes(ptr, 0, PAGE_SIZE as usize);
    }
}

fn write_entry(table_phys: u64, index: usize, value: u64) {
    unsafe {
        let table = memory::phys_to_virt(table_phys) as *mut u64;
        write_volatile(table.add(index), value);
    }
}
