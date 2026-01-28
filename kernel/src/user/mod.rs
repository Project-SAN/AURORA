mod elf;

use crate::memory;
use crate::paging;
use crate::serial;

pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
const USER_STACK_PAGES: usize = 1024;

#[cfg(feature = "userland")]
pub const USER_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/x86_64-unknown-none/debug/aurora-userland"
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

pub fn entry_phys() -> u64 {
    unsafe { ENTRY_PHYS }
}

pub fn load_user_image(elf_bytes: &[u8]) -> Option<UserImage> {
    let entry = elf::load_elf(elf_bytes)?;
    let stack_top = map_user_stack()?;
    Some(UserImage { entry, stack_top })
}

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
