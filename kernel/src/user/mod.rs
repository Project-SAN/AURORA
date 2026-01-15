mod elf;

use crate::memory;
use crate::paging;
use crate::serial;

pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
const USER_STACK_PAGES: usize = 8;

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

pub fn load_user_image(elf_bytes: &[u8]) -> Option<UserImage> {
    let entry = elf::load_elf(elf_bytes)?;
    let stack_top = map_user_stack()?;
    Some(UserImage { entry, stack_top })
}

fn map_user_stack() -> Option<u64> {
    for i in 0..USER_STACK_PAGES {
        let page = USER_STACK_TOP - (i as u64 + 1) * memory::PAGE_SIZE;
        let phys = memory::alloc_contiguous(1)?;
        if !paging::map_user_page(page, phys, true) {
            return None;
        }
        unsafe {
            core::ptr::write_bytes(page as *mut u8, 0, memory::PAGE_SIZE as usize);
        }
    }
    serial::write(format_args!(
        "user stack mapped at {:#x}\n",
        USER_STACK_TOP
    ));
    Some(USER_STACK_TOP)
}
