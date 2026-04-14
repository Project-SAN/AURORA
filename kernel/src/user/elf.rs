use crate::memory;
#[cfg(target_arch = "x86_64")]
use crate::paging;
use crate::serial;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
use uefi::table::boot::{AllocateType, BootServices, MemoryType};

const PT_LOAD: u32 = 1;
#[cfg(target_arch = "x86_64")]
const EM_X86_64: u16 = 62;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
const EM_AARCH64: u16 = 183;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
const PF_X: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[cfg(target_arch = "x86_64")]
pub fn load_elf(bytes: &[u8]) -> Option<u64> {
    let ehdr = parse_elf(bytes, EM_X86_64)?;
    let phdrs = program_headers(bytes, &ehdr)?;

    let mut mapped_pages: Vec<u64> = Vec::new();
    let mut entry_phys: Option<u64> = None;
    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let writable = true;
        let seg_start = align_down(ph.p_vaddr, memory::PAGE_SIZE);
        let seg_end = align_up(ph.p_vaddr + ph.p_memsz, memory::PAGE_SIZE);
        let mut addr = seg_start;
        while addr < seg_end {
            if !mapped_pages.iter().any(|&p| p == addr) {
                let phys = memory::alloc_normal_pages(1)?;
                if !paging::map_user_page(addr, phys, writable) {
                    return None;
                }
                if ehdr.e_entry >= addr && ehdr.e_entry < addr + memory::PAGE_SIZE {
                    entry_phys = Some(phys);
                }
                unsafe {
                    core::ptr::write_bytes(addr as *mut u8, 0, memory::PAGE_SIZE as usize);
                }
                mapped_pages.push(addr);
            }
            addr += memory::PAGE_SIZE;
        }

        if ph.p_filesz > 0 {
            let file_off = ph.p_offset as usize;
            let file_end = file_off + ph.p_filesz as usize;
            if file_end > bytes.len() {
                serial::write(format_args!("ELF: segment out of range\n"));
                return None;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(file_off),
                    ph.p_vaddr as *mut u8,
                    ph.p_filesz as usize,
                );
            }
        }
    }

    if let Some(phys) = entry_phys {
        serial::write(format_args!("ELF: entry phys={:#x}\n", phys));
        super::set_entry_phys(phys);
        crate::memory::set_watch_phys(phys);
    }
    log_entry_bytes(bytes, &ehdr);
    if let Some(phys) = memory::alloc_normal_pages(1) {
        if paging::map_user_page(0, phys, true) {
            unsafe {
                let ptr = memory::phys_to_virt(phys);
                core::ptr::write_bytes(ptr, 0, memory::PAGE_SIZE as usize);
            }
        }
    }
    Some(ehdr.e_entry)
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub fn prepare_elf_image(bs: &BootServices, bytes: &[u8]) -> Option<u64> {
    let ehdr = parse_elf(bytes, EM_AARCH64)?;
    let phdrs = program_headers(bytes, &ehdr)?;

    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let seg_start = align_down(ph.p_vaddr, memory::PAGE_SIZE);
        let seg_end = align_up(ph.p_vaddr + ph.p_memsz, memory::PAGE_SIZE);
        let pages = ((seg_end - seg_start) / memory::PAGE_SIZE) as usize;
        let mem_ty = if (ph.p_flags & PF_X) != 0 {
            MemoryType::LOADER_CODE
        } else {
            MemoryType::LOADER_DATA
        };
        bs.allocate_pages(AllocateType::Address(seg_start), mem_ty, pages)
            .ok()?;
        unsafe {
            core::ptr::write_bytes(
                seg_start as *mut u8,
                0,
                (pages as u64 * memory::PAGE_SIZE) as usize,
            );
        }

        if ph.p_filesz > 0 {
            let file_off = ph.p_offset as usize;
            let file_end = file_off + ph.p_filesz as usize;
            if file_end > bytes.len() {
                serial::write(format_args!("ELF: segment out of range\n"));
                return None;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(file_off),
                    ph.p_vaddr as *mut u8,
                    ph.p_filesz as usize,
                );
            }
        }
        serial::write(format_args!(
            "ELF: prepared seg ty={:?} range=[{:#x}..{:#x}) flags={:#x}\n",
            mem_ty, seg_start, seg_end, ph.p_flags
        ));
    }

    super::set_entry_phys(ehdr.e_entry);
    log_entry_bytes(bytes, &ehdr);
    Some(ehdr.e_entry)
}

fn parse_elf(bytes: &[u8], expected_machine: u16) -> Option<Elf64Ehdr> {
    if bytes.len() < core::mem::size_of::<Elf64Ehdr>() {
        return None;
    }
    let ehdr = unsafe { read_struct::<Elf64Ehdr>(bytes.as_ptr())? };
    if &ehdr.e_ident[0..4] != b"\x7FELF" {
        serial::write(format_args!("ELF: bad magic\n"));
        return None;
    }
    if ehdr.e_ident[4] != 2 || ehdr.e_ident[5] != 1 {
        serial::write(format_args!("ELF: unsupported class/data\n"));
        return None;
    }
    if ehdr.e_machine != expected_machine {
        serial::write(format_args!("ELF: wrong machine={}\n", ehdr.e_machine));
        return None;
    }
    Some(ehdr)
}

fn program_headers<'a>(
    bytes: &'a [u8],
    ehdr: &Elf64Ehdr,
) -> Option<impl Iterator<Item = Elf64Phdr> + 'a> {
    let phoff = ehdr.e_phoff as usize;
    let phentsize = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;
    if phoff + phentsize * phnum > bytes.len() {
        serial::write(format_args!("ELF: phdr out of range\n"));
        return None;
    }
    Some((0..phnum).filter_map(move |i| {
        let off = phoff + i * phentsize;
        unsafe { read_struct::<Elf64Phdr>(bytes.as_ptr().add(off)) }
    }))
}

fn log_entry_bytes(bytes: &[u8], ehdr: &Elf64Ehdr) {
    if let Some((file_off, avail)) = entry_file_offset(bytes, ehdr) {
        let len = core::cmp::min(16, avail);
        serial::write(format_args!("ELF: entry file bytes:"));
        for i in 0..len {
            let b = bytes[file_off + i];
            serial::write(format_args!(" {:02x}", b));
        }
        serial::write(format_args!("\n"));
    }
}

fn entry_file_offset(bytes: &[u8], ehdr: &Elf64Ehdr) -> Option<(usize, usize)> {
    let phoff = ehdr.e_phoff as usize;
    let phentsize = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;
    if phoff + phentsize * phnum > bytes.len() {
        return None;
    }
    let entry = ehdr.e_entry;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let ph = unsafe { read_struct::<Elf64Phdr>(bytes.as_ptr().add(off))? };
        if ph.p_type != PT_LOAD || ph.p_filesz == 0 {
            continue;
        }
        let start = ph.p_vaddr;
        let end = ph.p_vaddr.saturating_add(ph.p_filesz);
        if entry >= start && entry < end {
            let file_off = ph.p_offset as usize + (entry - start) as usize;
            if file_off < bytes.len() {
                let avail = bytes.len().saturating_sub(file_off);
                return Some((file_off, avail));
            }
        }
    }
    None
}

unsafe fn read_struct<T: Copy>(ptr: *const u8) -> Option<T> {
    if ptr.is_null() {
        return None;
    }
    Some(core::ptr::read_unaligned(ptr as *const T))
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}
