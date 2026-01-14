#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod heap;
mod serial;

use core::panic::PanicInfo;
use uefi::prelude::*;
use uefi::table::boot::MemoryType;

#[entry]
fn main(_handle: Handle, system_table: SystemTable<Boot>) -> Status {
    serial::init();
    heap::init();
    serial::write(format_args!("Hello from AURORA UEFI kernel\n"));

    let (_rt, memory_map) = system_table.exit_boot_services(MemoryType::LOADER_DATA);
    let entries = memory_map.entries().count();
    serial::write(format_args!(
        "Exited boot services. Memory map entries: {}\n",
        entries
    ));

    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::write(format_args!("PANIC: {}\n", info));
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    serial::write(format_args!("OOM: {:?}\n", layout));
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
