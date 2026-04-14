use crate::memory;
use crate::serial;
use core::arch::asm;
use uefi::table::boot::{MemoryMap, MemoryType};

const TABLE_ENTRIES: usize = 512;
const TABLE_DESC: u64 = 0b11;
const BLOCK_DESC: u64 = 0b01;
const PAGE_DESC: u64 = 0b11;

const ATTR_DEVICE_NGNRNE: u64 = 0;
const ATTR_NORMAL_WBWA: u64 = 1;
const MAIR_VALUE: u64 = 0x04 | (0xff << 8);

const AP_KERNEL_RW: u64 = 0b00 << 6;
const AP_USER_RW: u64 = 0b01 << 6;
const AP_USER_RO: u64 = 0b11 << 6;
const SH_INNER: u64 = 0b11 << 8;
const AF: u64 = 1 << 10;
const NG: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

const L1_BLOCK_SIZE: u64 = 1 << 30;
const L2_BLOCK_SIZE: u64 = 1 << 21;

const USER_WINDOW_START: u64 = 0x4000_0000;
const USER_WINDOW_END: u64 = 0x4200_0000;
const USER_WINDOW_BLOCKS: usize = ((USER_WINDOW_END - USER_WINDOW_START) / L2_BLOCK_SIZE) as usize;

pub fn activate_user_map(map: &MemoryMap) -> bool {
    let l0_phys = match alloc_table_page() {
        Some(phys) => phys,
        None => return false,
    };
    let l1_phys = match alloc_table_page() {
        Some(phys) => phys,
        None => return false,
    };

    let mut l2_phys = [0u64; 4];
    for slot in &mut l2_phys {
        *slot = match alloc_table_page() {
            Some(phys) => phys,
            None => return false,
        };
    }

    let mut l3_phys = [0u64; USER_WINDOW_BLOCKS];
    for slot in &mut l3_phys {
        *slot = match alloc_table_page() {
            Some(phys) => phys,
            None => return false,
        };
    }

    let l0 = table_ptr(l0_phys);
    let l1 = table_ptr(l1_phys);
    unsafe {
        *l0.add(0) = table_desc(l1_phys);
    }

    for (l1_index, &l2_table_phys) in l2_phys.iter().enumerate() {
        unsafe {
            *l1.add(l1_index) = table_desc(l2_table_phys);
        }

        let l2 = table_ptr(l2_table_phys);
        for l2_index in 0..TABLE_ENTRIES {
            let base = (l1_index as u64) * L1_BLOCK_SIZE + (l2_index as u64) * L2_BLOCK_SIZE;
            if let Some(window_index) = user_window_index(base) {
                let l3_table_phys = l3_phys[window_index];
                let l3 = table_ptr(l3_table_phys);
                fill_user_window_l3(l3, map, base);
                unsafe {
                    *l2.add(l2_index) = table_desc(l3_table_phys);
                }
            } else {
                let attrs = if base < USER_WINDOW_START {
                    device_attrs(AP_KERNEL_RW)
                } else {
                    normal_attrs(AP_KERNEL_RW, false, false)
                };
                unsafe {
                    *l2.add(l2_index) = block_desc(base, attrs);
                }
            }
        }
    }

    unsafe {
        switch_ttbr0(l0_phys);
    }

    serial::write(format_args!(
        "AArch64 user map active: ttbr0={:#x} user_window=[{:#x}..{:#x})\n",
        l0_phys, USER_WINDOW_START, USER_WINDOW_END
    ));
    true
}

fn fill_user_window_l3(table: *mut u64, map: &MemoryMap, block_base: u64) {
    for page_index in 0..TABLE_ENTRIES {
        let addr = block_base + (page_index as u64) * memory::PAGE_SIZE;
        let attrs = match user_page_kind(map, addr) {
            Some(UserPageKind::Code) => normal_attrs(AP_USER_RO, true, true) | NG,
            Some(UserPageKind::Data) => normal_attrs(AP_USER_RW, true, false) | NG,
            None => normal_attrs(AP_KERNEL_RW, false, false),
        };
        unsafe {
            *table.add(page_index) = page_desc(addr, attrs);
        }
    }
}

fn user_window_index(base: u64) -> Option<usize> {
    if !(USER_WINDOW_START..USER_WINDOW_END).contains(&base) {
        return None;
    }
    Some(((base - USER_WINDOW_START) / L2_BLOCK_SIZE) as usize)
}

fn user_page_kind(map: &MemoryMap, addr: u64) -> Option<UserPageKind> {
    for desc in map.entries() {
        if !matches!(desc.ty, MemoryType::LOADER_CODE | MemoryType::LOADER_DATA) {
            continue;
        }
        let start = desc.phys_start;
        let end = desc.phys_start + desc.page_count * memory::PAGE_SIZE;
        if start < USER_WINDOW_START || start >= USER_WINDOW_END {
            continue;
        }
        if addr >= start && addr < end {
            return Some(match desc.ty {
                MemoryType::LOADER_CODE => UserPageKind::Code,
                MemoryType::LOADER_DATA => UserPageKind::Data,
                _ => unreachable!(),
            });
        }
    }
    None
}

fn alloc_table_page() -> Option<u64> {
    let phys = memory::alloc_normal_pages(1)?;
    unsafe {
        core::ptr::write_bytes(memory::phys_to_virt(phys), 0, memory::PAGE_SIZE as usize);
    }
    Some(phys)
}

fn table_ptr(phys: u64) -> *mut u64 {
    memory::phys_to_virt(phys) as *mut u64
}

const fn table_desc(next_level_phys: u64) -> u64 {
    (next_level_phys & !0xfff) | TABLE_DESC
}

const fn block_desc(output_addr: u64, attrs: u64) -> u64 {
    (output_addr & !0x1f_ffff) | attrs | BLOCK_DESC
}

const fn page_desc(output_addr: u64, attrs: u64) -> u64 {
    (output_addr & !0xfff) | attrs | PAGE_DESC
}

const fn normal_attrs(ap: u64, user: bool, user_exec: bool) -> u64 {
    let mut attrs = (ATTR_NORMAL_WBWA << 2) | ap | SH_INNER | AF;
    if user {
        attrs |= PXN;
        if !user_exec {
            attrs |= UXN;
        }
    }
    attrs
}

const fn device_attrs(ap: u64) -> u64 {
    (ATTR_DEVICE_NGNRNE << 2) | ap | AF | PXN | UXN
}

unsafe fn switch_ttbr0(ttbr0_phys: u64) {
    asm!(
        "dsb ishst",
        "msr mair_el1, {mair}",
        "msr ttbr0_el1, {ttbr0}",
        "isb",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        mair = in(reg) MAIR_VALUE,
        ttbr0 = in(reg) ttbr0_phys,
        options(nostack)
    );
}

#[derive(Clone, Copy)]
enum UserPageKind {
    Code,
    Data,
}
