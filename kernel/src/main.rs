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
mod memory;
mod paging;
mod pci;
mod port;
mod serial;
mod virtio;

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
    let (_rt, memory_map) = system_table.exit_boot_services(MemoryType::LOADER_DATA);
    let entries = memory_map.entries().count();
    serial::write(format_args!(
        "Exited boot services. Memory map entries: {}\n",
        entries
    ));
    let stats = memory::init(&memory_map);
    serial::write(format_args!(
        "Memory: usable={} KiB regions={}\n",
        stats.total_usable / 1024,
        stats.region_count
    ));
    if let Some(buf) = memory::alloc_dma_pages(2) {
        serial::write(format_args!(
            "DMA test: phys={:#x} size={} bytes\n",
            buf.phys, buf.size
        ));
    } else {
        serial::write(format_args!("DMA test: allocation failed\n"));
    }
    if let Some(norm) = memory::alloc_normal_pages(4) {
        serial::write(format_args!("Normal alloc: phys={:#x} pages=4\n", norm));
        memory::free_contiguous(norm, 4);
        serial::write(format_args!("Normal free: ok\n"));
    } else {
        serial::write(format_args!("Normal alloc: failed\n"));
    }

    if let Some(pml4) = paging::init_identity_4g() {
        unsafe { paging::switch_to(pml4) };
        serial::write(format_args!(
            "Paging: identity 4GiB + higher-half at {:#x}\n",
            paging::KERNEL_BASE
        ));
    } else {
        serial::write(format_args!("Paging: failed to build tables\n"));
    }
    let stack_pages = 8usize;
    let stack_phys = match memory::alloc_contiguous(stack_pages) {
        Some(addr) => addr,
        None => {
            serial::write(format_args!("Stack alloc failed; staying in low half\n"));
            loop {
                unsafe { core::arch::asm!("hlt"); }
            }
        }
    };

    if rsdp_addr == 0 {
        serial::write(format_args!("ACPI RSDP not found\n"));
    } else {
        serial::write(format_args!("ACPI RSDP at {:#x}\n", rsdp_addr));
    }

    unsafe { enter_higher_half(rsdp_addr, stack_phys, stack_pages) }
}

extern "C" fn higher_half_main(rsdp_addr: u64) -> ! {
    serial::write(format_args!("Entered higher-half\n"));

    let pci_count = pci::scan();
    serial::write(format_args!("PCI scan complete: {} devices\n", pci_count));
    if let Some(dev) = pci::find_virtio_net() {
        serial::write(format_args!(
            "virtio-net at {:02x}:{:02x}.{} io={:?} mmio={:?}\n",
            dev.bus, dev.device, dev.function, dev.io_base, dev.mmio_base
        ));
        pci::enable_bus_master(&dev);
        let _ = virtio::init_net_legacy(&dev);
    } else {
        serial::write(format_args!("virtio-net not found\n"));
    }

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

unsafe fn enter_higher_half(rsdp_addr: u64, stack_phys: u64, stack_pages: usize) -> ! {
    let stack_top = paging::to_higher_half(
        stack_phys + (stack_pages as u64) * memory::PAGE_SIZE,
    );
    let target = paging::to_higher_half(higher_half_main as *const () as u64);
    core::arch::asm!(
        "mov rsp, {0}",
        "mov rdi, {1}",
        "jmp {2}",
        in(reg) stack_top,
        in(reg) rsdp_addr,
        in(reg) target,
        options(noreturn)
    );
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
