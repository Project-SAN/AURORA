#![no_std]
#![no_main]

mod serial;

use core::panic::PanicInfo;
use uefi::prelude::*;

#[entry]
fn main(_handle: Handle, _system_table: SystemTable<Boot>) -> Status {
    serial::init();
    serial::write(format_args!("Hello from AURORA UEFI kernel\n"));
    Status::SUCCESS
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::write(format_args!("PANIC: {}\n", info));
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
