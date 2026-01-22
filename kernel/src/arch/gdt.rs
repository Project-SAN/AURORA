use core::arch::asm;
use core::mem::size_of;

pub const KERNEL_CODE: u16 = 0x08;
pub const KERNEL_DATA: u16 = 0x10;
pub const USER_CODE: u16 = 0x20;
pub const TSS_SELECTOR: u16 = 0x28;

#[repr(C, packed)]
struct GdtDescriptor {
    limit: u16,
    base: u64,
}

#[repr(C, packed)]
pub struct Tss {
    _reserved1: u32,
    rsp: [u64; 3],
    _reserved2: u64,
    ist: [u64; 7],
    _reserved3: u64,
    _reserved4: u16,
    iopb_offset: u16,
}

impl Tss {
    const fn new() -> Self {
        Self {
            _reserved1: 0,
            rsp: [0; 3],
            _reserved2: 0,
            ist: [0; 7],
            _reserved3: 0,
            _reserved4: 0,
            iopb_offset: core::mem::size_of::<Tss>() as u16,
        }
    }
}

static mut TSS: Tss = Tss::new();
static mut GDT: [u64; 7] = [0; 7];

pub fn init(kernel_stack_top: u64) {
    unsafe {
        TSS.rsp[0] = kernel_stack_top;
        let (tss_low, tss_high) =
            tss_descriptor(&raw const TSS as *const _ as u64, size_of::<Tss>() as u32 - 1);
        GDT[0] = 0;
        GDT[1] = 0x00AF9A000000FFFF; // kernel code
        GDT[2] = 0x00AF92000000FFFF; // kernel data
        GDT[3] = 0x00AFF2000000FFFF; // user data
        GDT[4] = 0x00AFFA000000FFFF; // user code
        GDT[5] = tss_low;
        GDT[6] = tss_high;

        let descriptor = GdtDescriptor {
            limit: (size_of::<[u64; 7]>() - 1) as u16,
            base: &raw const GDT as *const _ as u64,
        };
        asm!("lgdt [{}]", in(reg) &descriptor, options(readonly, nostack, preserves_flags));

        asm!(
            "mov ds, {0:x}",
            "mov es, {0:x}",
            "mov ss, {0:x}",
            in(reg) KERNEL_DATA,
            options(nostack, preserves_flags)
        );

        asm!(
            "push {0}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            in(reg) (KERNEL_CODE as u64),
            out("rax") _,
            options(nostack, preserves_flags)
        );

        asm!("ltr {0:x}", in(reg) TSS_SELECTOR, options(nostack, preserves_flags));
    }
}

pub fn tss_rsp0() -> u64 {
    unsafe { TSS.rsp[0] }
}

pub fn read_tr() -> u16 {
    let tr: u16;
    unsafe {
        asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    tr
}

fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let mut low = 0u64;
    low |= (limit as u64) & 0xFFFF;
    low |= (base & 0xFFFFFF) << 16;
    low |= 0x89u64 << 40; // present, type=available 64-bit TSS
    low |= ((limit as u64 >> 16) & 0xF) << 48;
    low |= ((base >> 24) & 0xFF) << 56;
    let high = base >> 32;
    (low, high)
}
pub const USER_DATA: u16 = 0x18;
