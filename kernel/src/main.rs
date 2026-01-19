#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod heap;
mod arch;
mod acpi;
mod apic;
mod fs;
mod hpet;
mod interrupts;
mod memory;
mod net;
mod paging;
mod pci;
mod port;
mod serial;
mod syscall;
mod time;
mod user;
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

    match system_table.runtime_services().get_time() {
        Ok(time) => {
            if time::init_from_uefi(time, interrupts::ticks()) {
                serial::write(format_args!("UEFI time captured\n"));
            } else {
                serial::write(format_args!("UEFI time invalid\n"));
            }
        }
        Err(_) => {
            serial::write(format_args!("UEFI time unavailable\n"));
        }
    }

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
    let stack_pages = 32usize;
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

    const RUN_USERLAND: bool = cfg!(feature = "userland");

    let syscall_stack_pages = 64usize;
    let syscall_stack_phys = match memory::alloc_contiguous(syscall_stack_pages) {
        Some(addr) => addr,
        None => {
            serial::write(format_args!("Syscall stack alloc failed\n"));
            loop {
                unsafe { core::arch::asm!("hlt"); }
            }
        }
    };
    let syscall_stack_top = paging::to_higher_half(
        syscall_stack_phys + (syscall_stack_pages as u64) * memory::PAGE_SIZE,
    );
    arch::init(syscall_stack_top);
    serial::write(format_args!(
        "arch: tr={:#x} tss_rsp0={:#x} efer={:#x}\n",
        arch::gdt::read_tr(),
        arch::gdt::tss_rsp0(),
        arch::syscall::read_efer()
    ));

    if rsdp_addr != 0 {
        if let Some(info) = acpi::init(rsdp_addr) {
            serial::write(format_args!(
                "ACPI: LAPIC={:#x} IOAPIC={:?} HPET={:?}\n",
                info.lapic_addr, info.ioapic_addr, info.hpet_addr
            ));
            if interrupts::init(&info) {
                serial::write(format_args!("APIC/HPET timer enabled\n"));
                interrupts::enable_net_irqs();
            } else {
                serial::write(format_args!("APIC/HPET timer not configured\n"));
            }
        } else {
            serial::write(format_args!("ACPI parse failed; timer not configured\n"));
        }
    }

    let pci_count = pci::scan();
    serial::write(format_args!("PCI scan complete: {} devices\n", pci_count));
    let _ = fs::init();
    if let Some(dev) = pci::find_virtio_net() {
        serial::write(format_args!(
            "virtio-net at {:02x}:{:02x}.{} io={:?} mmio={:?}\n",
            dev.bus, dev.device, dev.function, dev.io_base, dev.mmio_base
        ));
        pci::enable_bus_master(&dev);
        let _ = virtio::init_net(&dev);
    } else {
        serial::write(format_args!("virtio-net not found\n"));
    }

    let mut net_device = net::VirtioDevice::new();
    let mut net_stack = match virtio::mac_address() {
        Some(mac) => Some(net::NetStack::new(mac, &mut net_device, net::now())),
        None => {
            serial::write(format_args!("smoltcp: mac not available\n"));
            None
        }
    };

    if let Some(stack) = net_stack.as_mut() {
        syscall::install_yield(stack as *mut _, &mut net_device as *mut _);
    }

    if RUN_USERLAND {
        if let Some(image) = user::load_user_image(user::USER_ELF) {
            serial::write(format_args!(
                "userland: entry={:#x} stack={:#x}\n",
                image.entry, image.stack_top
            ));
            serial::write(format_args!("userland: entry bytes:"));
            for i in 0..16u64 {
                let b = unsafe { core::ptr::read_volatile((image.entry + i) as *const u8) };
                serial::write(format_args!(" {:02x}", b));
            }
            serial::write(format_args!("\n"));
            let entry_phys = paging::virt_to_phys(image.entry);
            serial::write(format_args!(
                "userland: entry phys query={:#x}\n",
                entry_phys
            ));
            if entry_phys != 0 {
                let base = entry_phys & !0xfff;
                let off = (image.entry & 0xfff) as usize;
                let ptr = unsafe { memory::phys_to_virt(base) };
                serial::write(format_args!("userland: entry phys bytes:"));
                for i in 0..16usize {
                    let b = unsafe { core::ptr::read_volatile(ptr.add(off + i)) };
                    serial::write(format_args!(" {:02x}", b));
                }
                serial::write(format_args!("\n"));
            }
            unsafe { enter_user(image.entry, image.stack_top) };
        } else {
            serial::write(format_args!("userland: load failed\n"));
        }
    }

    let mut next_poll_tick = None;
    if let Some(stack) = net_stack.as_mut() {
        next_poll_tick =
            schedule_next_poll(interrupts::ticks(), stack.poll(&mut net_device, net::now()));
    }

    let mut last_tick = 0;
    loop {
        unsafe { core::arch::asm!("hlt"); }
        let now = interrupts::ticks();
        if let Some(stack) = net_stack.as_mut() {
            let (rx_irq, tx_irq) = interrupts::net_pending();
            let irq = rx_irq || tx_irq;
            let due = next_poll_tick.map_or(false, |t| now >= t);
            if irq || due {
                next_poll_tick = schedule_next_poll(now, stack.poll(&mut net_device, net::now()));
            }
        }
        virtio::reclaim_tx();
        if now != last_tick && now % 100 == 0 {
            serial::write(format_args!("tick={}\n", now));
            if now % 1000 == 0 {
                let stats = virtio::stats_snapshot();
                if stats.rx_drops != 0
                    || stats.rx_overflow != 0
                    || stats.tx_drops != 0
                    || stats.tx_overflow != 0
                {
                    serial::write(format_args!(
                        "net stats: rx={} bytes={} drop={} ovf={} tx={} bytes={} drop={} ovf={}\n",
                        stats.rx_packets,
                        stats.rx_bytes,
                        stats.rx_drops,
                        stats.rx_overflow,
                        stats.tx_packets,
                        stats.tx_bytes,
                        stats.tx_drops,
                        stats.tx_overflow
                    ));
                }
            }
        }
        last_tick = now;
    }
}

unsafe fn enter_user(entry: u64, stack_top: u64) -> ! {
    let user_cs = (arch::gdt::USER_CODE | 3) as u64;
    let user_ss = (arch::gdt::USER_DATA | 3) as u64;
    let rflags = read_rflags() | (1 << 9);
    serial::write(format_args!(
        "enter_user: rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}\n",
        entry, user_cs, rflags, stack_top, user_ss
    ));
    core::arch::asm!(
        "cli",
        "sub rsp, 40",
        "mov [rsp + 0], {rip}",
        "mov [rsp + 8], {cs}",
        "mov [rsp + 16], {rflags}",
        "mov [rsp + 24], {rsp_user}",
        "mov [rsp + 32], {ss}",
        "iretq",
        rip = in(reg) entry,
        cs = in(reg) user_cs,
        rflags = in(reg) rflags,
        rsp_user = in(reg) stack_top,
        ss = in(reg) user_ss,
        options(noreturn)
    );
}

fn read_rflags() -> u64 {
    let rflags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }
    rflags
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

fn schedule_next_poll(now_ticks: u64, delay_ms: Option<u64>) -> Option<u64> {
    delay_ms.map(|ms| {
        let mut ticks = (ms + 9) / 10;
        if ticks == 0 {
            ticks = 1;
        }
        now_ticks.saturating_add(ticks)
    })
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
