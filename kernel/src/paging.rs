use core::ptr::{write_bytes, write_volatile};

use crate::memory;

const PAGE_SIZE: u64 = 4096;
const ENTRIES: usize = 512;
const HUGE_PAGE: u64 = 1 << 7;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const FLAGS: u64 = PRESENT | WRITABLE;

pub const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
const KERNEL_PML4_INDEX: usize = ((KERNEL_BASE >> 39) & 0x1ff) as usize;
const HUGE_PAGE_SIZE: u64 = 0x20_0000;

#[inline]
pub fn to_higher_half(phys: u64) -> u64 {
    KERNEL_BASE + phys
}

pub fn init_identity_4g() -> Option<u64> {
    let pml4_phys = memory::alloc_contiguous(1)?;
    let pdpt_low_phys = memory::alloc_contiguous(1)?;
    let pdpt_high_phys = memory::alloc_contiguous(1)?;
    zero_page(pml4_phys);
    zero_page(pdpt_low_phys);
    zero_page(pdpt_high_phys);

    let mut pd_low_phys = [0u64; 4];
    let mut pd_high_phys = [0u64; 4];
    for slot in pd_low_phys.iter_mut() {
        let phys = memory::alloc_contiguous(1)?;
        zero_page(phys);
        *slot = phys;
    }
    for slot in pd_high_phys.iter_mut() {
        let phys = memory::alloc_contiguous(1)?;
        zero_page(phys);
        *slot = phys;
    }

    // Link PML4[0] -> PDPT (low identity, supervisor)
    write_entry(pml4_phys, 0, pdpt_low_phys | FLAGS);
    // Link PML4[KERNEL_PML4_INDEX] -> PDPT (higher-half alias)
    write_entry(pml4_phys, KERNEL_PML4_INDEX, pdpt_high_phys | FLAGS);

    // Link PDPT[0..4] -> PDs and populate 2MiB entries.
    for (i, pd) in pd_low_phys.iter().enumerate() {
        write_entry(pdpt_low_phys, i, *pd | FLAGS);
        populate_pd(*pd, i as u64);
    }
    for (i, pd) in pd_high_phys.iter().enumerate() {
        write_entry(pdpt_high_phys, i, *pd | FLAGS);
        populate_pd(*pd, i as u64);
    }

    Some(pml4_phys)
}

pub unsafe fn switch_to(pml4_phys: u64) {
    core::arch::asm!("mov cr3, {}", in(reg) pml4_phys, options(nostack, preserves_flags));
}

pub fn map_mmio(phys: u64) {
    let virt = to_higher_half(phys);
    let pml4_phys = current_pml4();
    if pml4_phys == 0 {
        return;
    }
    let pml4 = memory::phys_to_virt(pml4_phys) as *mut u64;
    let pml4_index = ((virt >> 39) & 0x1ff) as usize;
    let mut pml4e = unsafe { core::ptr::read_volatile(pml4.add(pml4_index)) };
    if (pml4e & PRESENT) == 0 {
        let pdpt_phys = match memory::alloc_contiguous(1) {
            Some(p) => p,
            None => return,
        };
        zero_page(pdpt_phys);
        pml4e = pdpt_phys | FLAGS;
        unsafe { write_volatile(pml4.add(pml4_index), pml4e) };
    }
    let pdpt_phys = pml4e & 0x000f_ffff_ffff_f000;
    let pdpt = memory::phys_to_virt(pdpt_phys) as *mut u64;
    let pdpt_index = ((virt >> 30) & 0x1ff) as usize;
    let mut pdpt_entry = unsafe { core::ptr::read_volatile(pdpt.add(pdpt_index)) };
    if (pdpt_entry & PRESENT) == 0 {
        let pd_phys = match memory::alloc_contiguous(1) {
            Some(p) => p,
            None => return,
        };
        zero_page(pd_phys);
        pdpt_entry = pd_phys | FLAGS;
        unsafe { write_volatile(pdpt.add(pdpt_index), pdpt_entry) };
    }
    let pd_phys = pdpt_entry & 0x000f_ffff_ffff_f000;
    let pd = memory::phys_to_virt(pd_phys) as *mut u64;
    let pd_index = ((virt >> 21) & 0x1ff) as usize;
    let phys_aligned = phys & !(HUGE_PAGE_SIZE - 1);
    let entry = phys_aligned | FLAGS | HUGE_PAGE;
    unsafe {
        write_volatile(pd.add(pd_index), entry);
        core::arch::asm!("invlpg [{}]", in(reg) virt as *const u8, options(nostack));
    }
}

fn current_pml4() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value & 0x000f_ffff_ffff_f000
}

pub fn map_user_page(virt: u64, phys: u64, writable: bool) -> bool {
    let pml4_phys = current_pml4();
    if pml4_phys == 0 {
        return false;
    }
    let mut flags = PRESENT | USER;
    if writable {
        flags |= WRITABLE;
    }

    unsafe {
        let pml4 = memory::phys_to_virt(pml4_phys) as *mut u64;
        let pml4_index = ((virt >> 39) & 0x1ff) as usize;
        let mut pml4e = core::ptr::read_volatile(pml4.add(pml4_index));
        if (pml4e & PRESENT) == 0 {
            let pdpt_phys = match memory::alloc_contiguous(1) {
                Some(p) => p,
                None => return false,
            };
            zero_page(pdpt_phys);
            pml4e = pdpt_phys | PRESENT | WRITABLE | USER;
            write_volatile(pml4.add(pml4_index), pml4e);
        } else if (pml4e & USER) == 0 {
            pml4e |= USER;
            write_volatile(pml4.add(pml4_index), pml4e);
        }

        let pdpt_phys = pml4e & 0x000f_ffff_ffff_f000;
        let pdpt = memory::phys_to_virt(pdpt_phys) as *mut u64;
        let pdpt_index = ((virt >> 30) & 0x1ff) as usize;
        let mut pdpte = core::ptr::read_volatile(pdpt.add(pdpt_index));
        if (pdpte & PRESENT) == 0 {
            let pd_phys = match memory::alloc_contiguous(1) {
                Some(p) => p,
                None => return false,
            };
            zero_page(pd_phys);
            pdpte = pd_phys | PRESENT | WRITABLE | USER;
            write_volatile(pdpt.add(pdpt_index), pdpte);
        } else if (pdpte & USER) == 0 {
            pdpte |= USER;
            write_volatile(pdpt.add(pdpt_index), pdpte);
        }

        let pd_phys = pdpte & 0x000f_ffff_ffff_f000;
        let pd = memory::phys_to_virt(pd_phys) as *mut u64;
        let pd_index = ((virt >> 21) & 0x1ff) as usize;
        let mut pde = core::ptr::read_volatile(pd.add(pd_index));
        if (pde & PRESENT) != 0 && (pde & HUGE_PAGE) != 0 {
            let base = pde & 0x000f_ffff_ffe0_0000;
            let pt_phys = match memory::alloc_contiguous(1) {
                Some(p) => p,
                None => return false,
            };
            zero_page(pt_phys);
            for i in 0..ENTRIES {
                let addr = base + (i as u64) * PAGE_SIZE;
                let entry = addr | PRESENT | WRITABLE | USER;
                write_entry(pt_phys, i, entry);
            }
            pde = pt_phys | PRESENT | WRITABLE | USER;
            write_volatile(pd.add(pd_index), pde);
        } else if (pde & PRESENT) == 0 {
            let pt_phys = match memory::alloc_contiguous(1) {
                Some(p) => p,
                None => return false,
            };
            zero_page(pt_phys);
            pde = pt_phys | PRESENT | WRITABLE | USER;
            write_volatile(pd.add(pd_index), pde);
        } else if (pde & USER) == 0 {
            pde |= USER;
            write_volatile(pd.add(pd_index), pde);
        }

        let pt_phys = pde & 0x000f_ffff_ffff_f000;
        let pt = memory::phys_to_virt(pt_phys) as *mut u64;
        let pt_index = ((virt >> 12) & 0x1ff) as usize;
        let entry = (phys & 0x000f_ffff_ffff_f000) | flags;
        write_volatile(pt.add(pt_index), entry);
        core::arch::asm!("invlpg [{}]", in(reg) virt as *const u8, options(nostack));
    }
    true
}

pub fn virt_to_phys(virt: u64) -> u64 {
    let pml4_phys = current_pml4();
    if pml4_phys == 0 {
        return 0;
    }
    unsafe {
        let pml4 = memory::phys_to_virt(pml4_phys) as *const u64;
        let pml4e = core::ptr::read_volatile(pml4.add(((virt >> 39) & 0x1ff) as usize));
        if (pml4e & PRESENT) == 0 {
            return 0;
        }
        let pdpt_phys = pml4e & 0x000f_ffff_ffff_f000;
        let pdpt = memory::phys_to_virt(pdpt_phys) as *const u64;
        let pdpte = core::ptr::read_volatile(pdpt.add(((virt >> 30) & 0x1ff) as usize));
        if (pdpte & PRESENT) == 0 {
            return 0;
        }
        if (pdpte & HUGE_PAGE) != 0 {
            let base = pdpte & 0x000f_ffff_c000_0000;
            return base + (virt & 0x3fff_ffff);
        }
        let pd_phys = pdpte & 0x000f_ffff_ffff_f000;
        let pd = memory::phys_to_virt(pd_phys) as *const u64;
        let pde = core::ptr::read_volatile(pd.add(((virt >> 21) & 0x1ff) as usize));
        if (pde & PRESENT) == 0 {
            return 0;
        }
        if (pde & HUGE_PAGE) != 0 {
            let base = pde & 0x000f_ffff_ffe0_0000;
            return base + (virt & 0x1f_ffff);
        }
        let pt_phys = pde & 0x000f_ffff_ffff_f000;
        let pt = memory::phys_to_virt(pt_phys) as *const u64;
        let pte = core::ptr::read_volatile(pt.add(((virt >> 12) & 0x1ff) as usize));
        if (pte & PRESENT) == 0 {
            return 0;
        }
        let base = pte & 0x000f_ffff_ffff_f000;
        base + (virt & 0xfff)
    }
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
