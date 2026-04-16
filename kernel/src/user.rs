mod elf;

use crate::memory;
#[cfg(target_arch = "x86_64")]
use crate::paging;
use crate::serial;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
use uefi::table::boot::{AllocateType, BootServices, MemoryType};

#[cfg(target_arch = "x86_64")]
pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub const USER_STACK_TOP: u64 = 0x4200_0000;
const USER_STACK_PAGES: usize = 1024;

#[cfg(all(feature = "userland", target_arch = "x86_64"))]
pub const USER_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/x86_64-unknown-none/debug/aurora-userland"
));

#[cfg(all(feature = "userland", target_arch = "aarch64", target_os = "uefi"))]
pub const USER_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/aarch64-unknown-none/debug/aurora-userland"
));

#[cfg(not(feature = "userland"))]
pub const USER_ELF: &[u8] = &[];

pub struct UserImage {
    pub entry: u64,
    pub stack_top: u64,
}

static mut ENTRY_PHYS: u64 = 0;

pub fn set_entry_phys(phys: u64) {
    unsafe {
        ENTRY_PHYS = phys;
    }
}

#[cfg(target_arch = "x86_64")]
pub fn entry_phys() -> u64 {
    unsafe { ENTRY_PHYS }
}

#[cfg(target_arch = "x86_64")]
pub fn load_user_image(elf_bytes: &[u8]) -> Option<UserImage> {
    let entry = elf::load_elf(elf_bytes)?;
    let stack_top = map_user_stack()?;
    Some(UserImage { entry, stack_top })
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub fn prepare_user_image(bs: &BootServices, elf_bytes: &[u8]) -> Option<UserImage> {
    let entry = elf::prepare_elf_image(bs, elf_bytes)?;
    let stack_top = reserve_user_stack(bs)?;
    Some(UserImage { entry, stack_top })
}

#[cfg(target_arch = "x86_64")]
fn map_user_stack() -> Option<u64> {
    for i in 0..USER_STACK_PAGES {
        let page = USER_STACK_TOP - (i as u64 + 1) * memory::PAGE_SIZE;
        let phys = memory::alloc_normal_pages(1)?;
        let entry_phys = entry_phys();
        if entry_phys != 0 && phys == entry_phys {
            serial::write(format_args!(
                "user stack page {} overlaps entry phys={:#x} virt={:#x}\n",
                i, phys, page
            ));
        }
        if i < 2 {
            serial::write(format_args!(
                "user stack page {} phys={:#x} virt={:#x}\n",
                i, phys, page
            ));
        }
        if !paging::map_user_page(page, phys, true) {
            return None;
        }
        unsafe {
            let ptr = memory::phys_to_virt(phys);
            core::ptr::write_bytes(ptr, 0, memory::PAGE_SIZE as usize);
        }
    }
    serial::write(format_args!("user stack mapped at {:#x}\n", USER_STACK_TOP));
    Some(USER_STACK_TOP)
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
fn reserve_user_stack(bs: &BootServices) -> Option<u64> {
    let stack_base = USER_STACK_TOP - USER_STACK_PAGES as u64 * memory::PAGE_SIZE;
    bs.allocate_pages(
        AllocateType::Address(stack_base),
        MemoryType::LOADER_DATA,
        USER_STACK_PAGES,
    )
    .ok()?;
    unsafe {
        core::ptr::write_bytes(
            stack_base as *mut u8,
            0,
            USER_STACK_PAGES * memory::PAGE_SIZE as usize,
        );
    }
    serial::write(format_args!(
        "user stack reserved at {:#x}..{:#x}\n",
        stack_base, USER_STACK_TOP
    ));
    Some(USER_STACK_TOP)
}
