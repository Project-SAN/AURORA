use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::acpi::AcpiInfo;

static TICKS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
pub const NET_RX_VECTOR: u8 = 0x40;
#[cfg(target_arch = "x86_64")]
pub const NET_TX_VECTOR: u8 = 0x41;
static NET_RX_IRQ: AtomicU64 = AtomicU64::new(0);
static NET_TX_IRQ: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::*;
    use core::arch::asm;
    use core::cell::UnsafeCell;

    use crate::apic;
    use crate::hpet::Hpet;

    macro_rules! handler_addr {
        ($handler:path) => {
            $handler as *const () as u64
        };
    }

    const TIMER_VECTOR: u8 = 32;

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
            unsafe {
                asm!("hlt");
            }
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
    #[unsafe(naked)]
    extern "C" fn invalid_opcode() -> ! {
        core::arch::naked_asm!(
            "mov rdi, rsp",
            "jmp {handler}",
            handler = sym invalid_opcode_handler,
        );
    }

    extern "C" fn invalid_opcode_handler(frame_ptr: *const u64) -> ! {
        let mut v = [0u64; 5];
        unsafe {
            for i in 0..5 {
                v[i] = core::ptr::read_unaligned(frame_ptr.add(i));
            }
        }
        crate::serial::write(format_args!(
            "INVALID OPCODE frame={:#x} [rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}]\n",
            frame_ptr as u64, v[0], v[1], v[2], v[3], v[4]
        ));
        loop {
            unsafe {
                asm!("hlt");
            }
        }
    }
    exception_no_error!(device_not_available, 7);
    exception_with_error!(double_fault, 8);
    exception_no_error!(coprocessor_segment_overrun, 9);
    exception_with_error!(invalid_tss, 10);
    exception_with_error!(segment_not_present, 11);
    exception_with_error!(stack_segment_fault, 12);
    extern "x86-interrupt" fn general_protection_fault(frame: &mut InterruptStackFrame, code: u64) {
        crate::serial::write(format_args!(
            "EXCEPTION 13 err={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}\n",
            code,
            frame.instruction_pointer,
            frame.code_segment,
            frame.cpu_flags,
            frame.stack_pointer,
            frame.stack_segment
        ));
        loop {
            unsafe {
                asm!("hlt");
            }
        }
    }
    #[unsafe(naked)]
    extern "C" fn page_fault() -> ! {
        core::arch::naked_asm!(
            "mov rdi, rsp",
            "jmp {handler}",
            handler = sym page_fault_handler,
        );
    }

    extern "C" fn page_fault_handler(err_ptr: *const u64) -> ! {
        let mut v = [0u64; 6];
        unsafe {
            for i in 0..6 {
                v[i] = core::ptr::read_volatile(err_ptr.add(i));
            }
        }
        let err = v[0];
        let rip = v[1];
        let cs = v[2];
        let rflags = v[3];
        let mut rsp = 0u64;
        let mut ss = 0u64;
        if (cs & 3) == 3 {
            rsp = v[4];
            ss = v[5];
        }
        let cr2: u64;
        unsafe {
            asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        }
        crate::serial::write(format_args!(
            "PAGE FAULT err={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x} cr2={:#x} frame={:#x} tss_rsp0={:#x}\n",
            err,
            rip,
            cs,
            rflags,
            rsp,
            ss,
            cr2,
            err_ptr as u64,
            crate::arch::gdt::tss_rsp0()
        ));
        loop {
            unsafe {
                asm!("hlt");
            }
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
}

#[cfg(target_arch = "x86_64")]
pub use imp::{enable_net_irqs, init, net_pending, ticks};

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
mod imp {
    use super::*;
    use core::arch::asm;
    use core::ptr::{read_volatile, write_volatile};

    const GICD_BASE: u64 = 0x0800_0000;
    const GICR_BASE: u64 = 0x080A_0000;
    const GICR_SGI_BASE_OFFSET: u64 = 0x0001_0000;

    const GICD_CTLR: u64 = 0x0000;
    const GICD_IGROUPR: u64 = 0x0080;
    const GICD_ISENABLER: u64 = 0x0100;
    const GICD_IPRIORITYR: u64 = 0x0400;
    const GICD_ICFGR: u64 = 0x0c00;

    const GICR_WAKER: u64 = 0x0014;
    const GICR_IGROUPR0: u64 = GICR_SGI_BASE_OFFSET + 0x0080;
    const GICR_ISENABLER0: u64 = GICR_SGI_BASE_OFFSET + 0x0100;
    const GICR_IPRIORITYR0: u64 = GICR_SGI_BASE_OFFSET + 0x0400;
    const GICR_ICFGR1: u64 = GICR_SGI_BASE_OFFSET + 0x0c04;

    const GICD_CTLR_ENABLE_GRP1NS: u32 = 1 << 1;
    const GICD_CTLR_ARE_NS: u32 = 1 << 5;
    const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
    const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

    const TIMER_INTID: u32 = 30;
    const VIRTIO_MMIO_SPI_BASE: u32 = 16;
    const GIC_SPI_INTID_BASE: u32 = 32;
    const SPURIOUS_INTID: u32 = 1023;
    const TICK_MS: u64 = 10;
    const DEFAULT_PRIORITY: u8 = 0x80;

    static NET_INTID: AtomicU64 = AtomicU64::new(u64::MAX);
    static TICK_CYCLES: AtomicU64 = AtomicU64::new(0);
    static TIMER_IRQ_LOG: AtomicU64 = AtomicU64::new(0);
    static NET_IRQ_LOG: AtomicU64 = AtomicU64::new(0);

    pub fn init() -> bool {
        let cntfrq = counter_frequency();
        let tick_cycles = (cntfrq / (1000 / TICK_MS)).max(1);
        if cntfrq == 0 {
            crate::serial::write(format_args!("AArch64 timer frequency unavailable\n"));
            return false;
        }

        TICKS.store(0, Ordering::Relaxed);
        TICK_CYCLES.store(tick_cycles, Ordering::Relaxed);
        NET_RX_IRQ.store(0, Ordering::Relaxed);
        NET_TX_IRQ.store(0, Ordering::Relaxed);

        wake_redistributor();
        enable_system_register_interface();
        configure_distributor();
        configure_timer_ppi();
        rearm_timer();
        enable_timer();
        enable_cpu_interface();
        unmask_irqs();

        crate::serial::write(format_args!(
            "AArch64 timer: cntfrq={} tick_cycles={} intid={}\n",
            cntfrq, tick_cycles, TIMER_INTID
        ));
        true
    }

    pub fn ticks() -> u64 {
        TICKS.load(Ordering::Relaxed)
    }

    pub fn register_virtio_mmio_irq(base: u64, is_net: bool) {
        let intid = mmio_intid(base);
        configure_spi(intid, true);
        if is_net {
            NET_INTID.store(intid as u64, Ordering::Release);
            crate::serial::write(format_args!(
                "AArch64 net IRQ enabled: base={:#x} intid={}\n",
                base, intid
            ));
        }
    }

    pub fn handle_irq() {
        let intid = read_iar1();
        if intid == SPURIOUS_INTID {
            return;
        }

        match intid {
            TIMER_INTID => {
                if TIMER_IRQ_LOG.fetch_add(1, Ordering::Relaxed) == 0 {
                    crate::serial::write(format_args!("AArch64 timer IRQ active\n"));
                }
                TICKS.fetch_add(1, Ordering::Relaxed);
                rearm_timer();
            }
            id if NET_INTID.load(Ordering::Acquire) == id as u64 => {
                if NET_IRQ_LOG.fetch_add(1, Ordering::Relaxed) == 0 {
                    crate::serial::write(format_args!("AArch64 net IRQ active intid={}\n", id));
                }
                NET_RX_IRQ.fetch_add(1, Ordering::Relaxed);
                NET_TX_IRQ.fetch_add(1, Ordering::Relaxed);
            }
            other => {
                crate::serial::write(format_args!("AArch64 IRQ intid={}\n", other));
            }
        }

        write_eoir1(intid);
    }

    fn mmio_intid(base: u64) -> u32 {
        let slot = ((base - crate::virtio_mmio::base()) / crate::virtio_mmio::stride()) as u32;
        GIC_SPI_INTID_BASE + VIRTIO_MMIO_SPI_BASE + slot
    }

    fn counter_frequency() -> u64 {
        let cntfrq: u64;
        unsafe {
            asm!(
                "mrs {cntfrq}, CNTFRQ_EL0",
                cntfrq = out(reg) cntfrq,
                options(nomem, nostack, preserves_flags)
            );
        }
        cntfrq
    }

    fn enable_system_register_interface() {
        unsafe {
            let mut sre: u64;
            asm!("mrs {sre}, ICC_SRE_EL1", sre = out(reg) sre, options(nomem, nostack));
            sre |= 1;
            asm!("msr ICC_SRE_EL1, {sre}", sre = in(reg) sre, options(nomem, nostack));
            asm!("isb", options(nomem, nostack));
        }
    }

    fn enable_cpu_interface() {
        unsafe {
            asm!("msr ICC_PMR_EL1, {}", in(reg) 0xffu64, options(nomem, nostack));
            asm!("msr ICC_BPR1_EL1, {}", in(reg) 0u64, options(nomem, nostack));
            asm!("msr ICC_IGRPEN1_EL1, {}", in(reg) 1u64, options(nomem, nostack));
            asm!("isb", options(nomem, nostack));
        }
    }

    fn unmask_irqs() {
        unsafe {
            asm!("msr DAIFClr, #2", options(nomem, nostack, preserves_flags));
        }
    }

    fn configure_distributor() {
        write32(
            GICD_BASE + GICD_CTLR,
            GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1NS,
        );
    }

    fn wake_redistributor() {
        let waker = read32(GICR_BASE + GICR_WAKER) & !GICR_WAKER_PROCESSOR_SLEEP;
        write32(GICR_BASE + GICR_WAKER, waker);
        for _ in 0..1_000_000 {
            if (read32(GICR_BASE + GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP) == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }

    fn configure_timer_ppi() {
        set_group1_ppi(TIMER_INTID);
        set_priority_ppi(TIMER_INTID, DEFAULT_PRIORITY);
        set_level_ppi(TIMER_INTID);
        enable_ppi(TIMER_INTID);
    }

    fn configure_spi(intid: u32, edge_triggered: bool) {
        set_group1_spi(intid);
        set_priority_spi(intid, DEFAULT_PRIORITY);
        if edge_triggered {
            set_edge_spi(intid);
        }
        enable_spi(intid);
    }

    fn rearm_timer() {
        let cycles = TICK_CYCLES.load(Ordering::Relaxed).max(1);
        unsafe {
            asm!("msr CNTP_TVAL_EL0, {}", in(reg) cycles, options(nomem, nostack));
            asm!("isb", options(nomem, nostack));
        }
    }

    fn enable_timer() {
        unsafe {
            asm!("msr CNTP_CTL_EL0, {}", in(reg) 1u64, options(nomem, nostack));
            asm!("isb", options(nomem, nostack));
        }
    }

    fn set_group1_ppi(intid: u32) {
        let val = read32(GICR_BASE + GICR_IGROUPR0) | (1u32 << intid);
        write32(GICR_BASE + GICR_IGROUPR0, val);
    }

    fn set_priority_ppi(intid: u32, priority: u8) {
        write8(GICR_BASE + GICR_IPRIORITYR0 + intid as u64, priority);
    }

    fn set_level_ppi(intid: u32) {
        let offset = GICR_BASE + GICR_ICFGR1 + ((intid as u64 - 16) / 16) * 4;
        let shift = ((intid % 16) * 2 + 1) as u32;
        let val = read32(offset) & !(1u32 << shift);
        write32(offset, val);
    }

    fn enable_ppi(intid: u32) {
        write32(GICR_BASE + GICR_ISENABLER0, 1u32 << intid);
    }

    fn set_group1_spi(intid: u32) {
        let offset = GICD_BASE + GICD_IGROUPR + ((intid / 32) as u64) * 4;
        let val = read32(offset) | (1u32 << (intid % 32));
        write32(offset, val);
    }

    fn set_priority_spi(intid: u32, priority: u8) {
        write8(GICD_BASE + GICD_IPRIORITYR + intid as u64, priority);
    }

    fn set_edge_spi(intid: u32) {
        let offset = GICD_BASE + GICD_ICFGR + ((intid / 16) as u64) * 4;
        let shift = ((intid % 16) * 2 + 1) as u32;
        let val = read32(offset) | (1u32 << shift);
        write32(offset, val);
    }

    fn enable_spi(intid: u32) {
        let offset = GICD_BASE + GICD_ISENABLER + ((intid / 32) as u64) * 4;
        write32(offset, 1u32 << (intid % 32));
    }

    fn read_iar1() -> u32 {
        let intid: u64;
        unsafe {
            asm!("mrs {intid}, ICC_IAR1_EL1", intid = out(reg) intid, options(nomem, nostack));
        }
        intid as u32
    }

    fn write_eoir1(intid: u32) {
        unsafe {
            asm!("msr ICC_EOIR1_EL1, {}", in(reg) intid as u64, options(nomem, nostack));
            asm!("isb", options(nomem, nostack));
        }
    }

    fn read32(addr: u64) -> u32 {
        unsafe { read_volatile(addr as *const u32) }
    }

    fn write32(addr: u64, value: u32) {
        unsafe {
            write_volatile(addr as *mut u32, value);
        }
    }

    fn write8(addr: u64, value: u8) {
        unsafe {
            write_volatile(addr as *mut u8, value);
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub use imp::{handle_irq, init, register_virtio_mmio_irq, ticks};

#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn init() -> bool {
    false
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn enable_net_irqs() {}

#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn net_pending() -> (bool, bool) {
    (false, false)
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn register_virtio_mmio_irq(_base: u64, _is_net: bool) {}

#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(all(target_arch = "aarch64", target_os = "uefi")))]
pub fn handle_irq() {}
