use alloc::vec::Vec;

use crate::memory;
use crate::paging;
use crate::serial;

const PT_LOAD: u32 = 1;

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

pub fn load_elf(bytes: &[u8]) -> Option<u64> {
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
    let phoff = ehdr.e_phoff as usize;
    let phentsize = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;
    if phoff + phentsize * phnum > bytes.len() {
        serial::write(format_args!("ELF: phdr out of range\n"));
        return None;
    }

    let mut mapped_pages: Vec<u64> = Vec::new();
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let ph = unsafe { read_struct::<Elf64Phdr>(bytes.as_ptr().add(off))? };
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_memsz == 0 {
            continue;
        }
        // Map writable during load; tighten permissions later when we have remap support.
        let writable = true;
        let seg_start = align_down(ph.p_vaddr, memory::PAGE_SIZE);
        let seg_end = align_up(ph.p_vaddr + ph.p_memsz, memory::PAGE_SIZE);
        let mut addr = seg_start;
        while addr < seg_end {
            if !mapped_pages.iter().any(|&p| p == addr) {
                let phys = match memory::alloc_contiguous(1) {
                    Some(p) => p,
                    None => return None,
                };
                if !paging::map_user_page(addr, phys, writable) {
                    return None;
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
    Some(ehdr.e_entry)
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
