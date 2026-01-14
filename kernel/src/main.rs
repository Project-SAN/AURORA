#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod heap;
mod acpi;
mod apic;
mod hpet;
mod interrupts;
mod port;
mod serial;

use core::panic::PanicInfo;
use uefi::prelude::*;
use uefi::table::boot::MemoryType;
use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID};

#[entry]
fn main(_handle: Handle, system_table: SystemTable<Boot>) -> Status {
    serial::init();
    heap::init();
    serial::write(format_args!("Hello from AURORA UEFI kernel\n"));

    let rsdp_addr = find_rsdp(&system_table);
    if rsdp_addr == 0 {
        serial::write(format_args!("ACPI RSDP not found\n"));
    } else {
        serial::write(format_args!("ACPI RSDP at {:#x}\n", rsdp_addr));
    }

    let (_rt, memory_map) = system_table.exit_boot_services(MemoryType::LOADER_DATA);
    let entries = memory_map.entries().count();
    serial::write(format_args!(
        "Exited boot services. Memory map entries: {}\n",
        entries
    ));

    if rsdp_addr != 0 {
        if let Some(info) = acpi::init(rsdp_addr) {
            serial::write(format_args!(
                "ACPI: LAPIC={:#x} IOAPIC={:?} HPET={:?}\n",
                info.lapic_addr, info.ioapic_addr, info.hpet_addr
            ));
            if interrupts::init(&info) {
                serial::write(format_args!("APIC/HPET timer enabled\n"));
            } else {
                serial::write(format_args!("APIC/HPET timer not configured\n"));
            }
        } else {
            serial::write(format_args!("ACPI parse failed; timer not configured\n"));
        }
    }

    let mut last_tick = 0;
    loop {
        unsafe { core::arch::asm!("hlt"); }
        let now = interrupts::ticks();
        if now != last_tick && now % 100 == 0 {
            serial::write(format_args!("tick={}\n", now));
        }
        last_tick = now;
    }
}

fn find_rsdp(system_table: &SystemTable<Boot>) -> u64 {
    for entry in system_table.config_table() {
        if entry.guid == ACPI2_GUID || entry.guid == ACPI_GUID {
            return entry.address as u64;
        }
    }
    0
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
