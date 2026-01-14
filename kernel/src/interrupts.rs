use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::acpi::AcpiInfo;
use crate::apic;
use crate::hpet::Hpet;

macro_rules! handler_addr {
    ($handler:path) => {
        $handler as *const () as u64
    };
}

static TICKS: AtomicU64 = AtomicU64::new(0);
const TIMER_VECTOR: u8 = 32;
pub const NET_RX_VECTOR: u8 = 0x40;
pub const NET_TX_VECTOR: u8 = 0x41;
static NET_RX_IRQ: AtomicU64 = AtomicU64::new(0);
static NET_TX_IRQ: AtomicU64 = AtomicU64::new(0);

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    options: u16,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            options: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn new(handler_addr: u64, selector: u16) -> Self {
        let offset_low = handler_addr as u16;
        let offset_mid = (handler_addr >> 16) as u16;
        let offset_high = (handler_addr >> 32) as u32;
        let options = 0x8E00u16; // present, DPL=0, type=interrupt gate
        Self {
            offset_low,
            selector,
            options,
            offset_mid,
            offset_high,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

struct Idt {
    entries: UnsafeCell<[IdtEntry; 256]>,
}

unsafe impl Sync for Idt {}

impl Idt {
    const fn new() -> Self {
        Self {
            entries: UnsafeCell::new([IdtEntry::missing(); 256]),
        }
    }

    #[inline]
    fn entries_ptr(&self) -> *mut IdtEntry {
        self.entries.get().cast::<IdtEntry>()
    }
}

static IDT: Idt = Idt::new();

pub fn init(info: &AcpiInfo) -> bool {
    let mut ok = false;
    unsafe {
        disable();
        init_idt();
        load_idt();
        if let Some(hpet_addr) = info.hpet_addr {
            if let Some(hpet) = Hpet::init(hpet_addr) {
                apic::init(info.lapic_addr, TIMER_VECTOR, &hpet);
                ok = true;
            }
        }
        enable();
    }
    ok
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn enable_net_irqs() {
    unsafe {
        disable();
        let cs = code_segment();
        set_handler(NET_RX_VECTOR as usize, handler_addr!(net_rx_interrupt), cs);
        set_handler(NET_TX_VECTOR as usize, handler_addr!(net_tx_interrupt), cs);
        enable();
    }
}

pub fn net_pending() -> (bool, bool) {
    (
        NET_RX_IRQ.swap(0, Ordering::AcqRel) != 0,
        NET_TX_IRQ.swap(0, Ordering::AcqRel) != 0,
    )
}

unsafe fn init_idt() {
    let cs = code_segment();
    let idt_ptr = IDT.entries_ptr();
    for i in 0..256 {
        idt_ptr.add(i).write(IdtEntry::missing());
    }

    set_handler(0, handler_addr!(divide_by_zero), cs);
    set_handler(1, handler_addr!(debug_exception), cs);
    set_handler(2, handler_addr!(non_maskable_interrupt), cs);
    set_handler(3, handler_addr!(breakpoint), cs);
    set_handler(4, handler_addr!(overflow), cs);
    set_handler(5, handler_addr!(bound_range), cs);
    set_handler(6, handler_addr!(invalid_opcode), cs);
    set_handler(7, handler_addr!(device_not_available), cs);
    set_handler(8, handler_addr!(double_fault), cs);
    set_handler(9, handler_addr!(coprocessor_segment_overrun), cs);
    set_handler(10, handler_addr!(invalid_tss), cs);
    set_handler(11, handler_addr!(segment_not_present), cs);
    set_handler(12, handler_addr!(stack_segment_fault), cs);
    set_handler(13, handler_addr!(general_protection_fault), cs);
    set_handler(14, handler_addr!(page_fault), cs);
    set_handler(15, handler_addr!(reserved), cs);
    set_handler(16, handler_addr!(floating_point), cs);
    set_handler(17, handler_addr!(alignment_check), cs);
    set_handler(18, handler_addr!(machine_check), cs);
    set_handler(19, handler_addr!(simd_floating_point), cs);
    set_handler(20, handler_addr!(virtualization_exception), cs);
    set_handler(21, handler_addr!(control_protection), cs);
    set_handler(22, handler_addr!(reserved), cs);
    set_handler(23, handler_addr!(reserved), cs);
    set_handler(24, handler_addr!(reserved), cs);
    set_handler(25, handler_addr!(reserved), cs);
    set_handler(26, handler_addr!(reserved), cs);
    set_handler(27, handler_addr!(reserved), cs);
    set_handler(28, handler_addr!(reserved), cs);
    set_handler(29, handler_addr!(vmm_communication), cs);
    set_handler(30, handler_addr!(security_exception), cs);
    set_handler(31, handler_addr!(reserved), cs);

    set_handler(TIMER_VECTOR as usize, handler_addr!(timer_interrupt), cs);
    set_handler(0xFF, handler_addr!(spurious_interrupt), cs);
}

unsafe fn set_handler(vector: usize, handler: u64, selector: u16) {
    IDT.entries_ptr()
        .add(vector)
        .write(IdtEntry::new(handler, selector));
}

unsafe fn load_idt() {
    let ptr = IdtPointer {
        limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
        base: IDT.entries_ptr() as u64,
    };
    asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags));
}


unsafe fn disable() {
    asm!("cli", options(nomem, nostack, preserves_flags));
}

unsafe fn enable() {
    asm!("sti", options(nomem, nostack, preserves_flags));
}

fn code_segment() -> u16 {
    let cs: u16;
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    cs
}

fn fault(vector: u8, error: Option<u64>) -> ! {
    if let Some(code) = error {
        crate::serial::write(format_args!("EXCEPTION {} err={:#x}\n", vector, code));
    } else {
        crate::serial::write(format_args!("EXCEPTION {}\n", vector));
    }
    loop {
        unsafe { asm!("hlt"); }
    }
}

extern "x86-interrupt" fn timer_interrupt(_frame: &mut InterruptStackFrame) {
    TICKS.fetch_add(1, Ordering::Relaxed);
    apic::eoi();
}

extern "x86-interrupt" fn spurious_interrupt(_frame: &mut InterruptStackFrame) {
    apic::eoi();
}

extern "x86-interrupt" fn net_rx_interrupt(_frame: &mut InterruptStackFrame) {
    NET_RX_IRQ.fetch_add(1, Ordering::Relaxed);
    apic::eoi();
}

extern "x86-interrupt" fn net_tx_interrupt(_frame: &mut InterruptStackFrame) {
    NET_TX_IRQ.fetch_add(1, Ordering::Relaxed);
    apic::eoi();
}

macro_rules! exception_no_error {
    ($name:ident, $vec:expr) => {
        extern "x86-interrupt" fn $name(_frame: &mut InterruptStackFrame) {
            fault($vec, None);
        }
    };
}

macro_rules! exception_with_error {
    ($name:ident, $vec:expr) => {
        extern "x86-interrupt" fn $name(_frame: &mut InterruptStackFrame, code: u64) {
            fault($vec, Some(code));
        }
    };
}

exception_no_error!(divide_by_zero, 0);
exception_no_error!(debug_exception, 1);
exception_no_error!(non_maskable_interrupt, 2);
exception_no_error!(breakpoint, 3);
exception_no_error!(overflow, 4);
exception_no_error!(bound_range, 5);
extern "x86-interrupt" fn invalid_opcode(frame: &mut InterruptStackFrame) {
    let rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    crate::serial::write(format_args!(
        "INVALID OPCODE rip={:#x} cs={:#x} rflags={:#x} frame_ptr={:#x} rsp={:#x}\n",
        frame.instruction_pointer,
        frame.code_segment,
        frame.cpu_flags,
        frame as *const _ as u64,
        rsp
    ));
    loop {
        unsafe { asm!("hlt"); }
    }
}
exception_no_error!(device_not_available, 7);
exception_with_error!(double_fault, 8);
exception_no_error!(coprocessor_segment_overrun, 9);
exception_with_error!(invalid_tss, 10);
exception_with_error!(segment_not_present, 11);
exception_with_error!(stack_segment_fault, 12);
exception_with_error!(general_protection_fault, 13);
extern "x86-interrupt" fn page_fault(frame: &mut InterruptStackFrame, code: u64) {
    let cr2: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    crate::serial::write(format_args!(
        "PAGE FAULT err={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x} cr2={:#x}\n",
        code,
        frame.instruction_pointer,
        frame.code_segment,
        frame.cpu_flags,
        frame.stack_pointer,
        frame.stack_segment,
        cr2
    ));
    loop {
        unsafe { asm!("hlt"); }
    }
}
exception_no_error!(reserved, 15);
exception_no_error!(floating_point, 16);
exception_with_error!(alignment_check, 17);
exception_no_error!(machine_check, 18);
exception_no_error!(simd_floating_point, 19);
exception_no_error!(virtualization_exception, 20);
exception_with_error!(control_protection, 21);
exception_with_error!(vmm_communication, 29);
exception_with_error!(security_exception, 30);

#[repr(C)]
pub struct InterruptStackFrame {
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub cpu_flags: u64,
    pub stack_pointer: u64,
    pub stack_segment: u64,
}
