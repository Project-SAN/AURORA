#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct Gas {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct HpetTable {
    header: SdtHeader,
    event_timer_block_id: u32,
    base_address: Gas,
    hpet_number: u8,
    minimum_tick: u16,
    page_protection: u8,
}

#[repr(C, packed)]
struct Madt {
    header: SdtHeader,
    lapic_address: u32,
    flags: u32,
}

#[repr(C, packed)]
struct MadtEntryHeader {
    entry_type: u8,
    length: u8,
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
#[repr(C, packed)]
struct MadtGenericInterruptGicr {
    header: MadtEntryHeader,
    reserved: u16,
    cpu_interface_number: u32,
    uid: u32,
    flags: u32,
    parking_version: u32,
    performance_interrupt: u32,
    parked_address: u64,
    base_address: u64,
    gicv_base_address: u64,
    gich_base_address: u64,
    vgic_interrupt: u32,
    gicr_base_address: u64,
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
#[repr(C, packed)]
struct MadtGenericDistributor {
    header: MadtEntryHeader,
    reserved: u16,
    gic_id: u32,
    base_address: u64,
    global_irq_base: u32,
    version: u8,
    reserved2: [u8; 3],
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
#[repr(C, packed)]
struct MadtGenericRedistributor {
    header: MadtEntryHeader,
    flags: u8,
    reserved: u8,
    base_address: u64,
    length: u32,
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
#[repr(C, packed)]
struct Gtdt {
    header: SdtHeader,
    counter_block_address: u64,
    reserved: u32,
    secure_el1_interrupt: u32,
    secure_el1_flags: u32,
    non_secure_el1_interrupt: u32,
    non_secure_el1_flags: u32,
    virtual_timer_interrupt: u32,
    virtual_timer_flags: u32,
    non_secure_el2_interrupt: u32,
    non_secure_el2_flags: u32,
    counter_read_block_address: u64,
    platform_timer_count: u32,
    platform_timer_offset: u32,
}

struct TableAddrs {
    madt: u64,
    #[cfg(target_arch = "x86_64")]
    hpet: u64,
    #[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
    gtdt: u64,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug)]
pub struct AcpiInfo {
    pub lapic_addr: u64,
    pub ioapic_addr: Option<u64>,
    pub hpet_addr: Option<u64>,
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
struct ArmGicInfo {
    gicd_base: u64,
    gicr_base: u64,
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
struct ArmTimerInfo {
    intid: u32,
    edge_triggered: bool,
}

#[cfg(target_arch = "x86_64")]
pub fn init(rsdp_addr: u64) -> Option<AcpiInfo> {
    let (root_addr, is_xsdt) = rsdp_root(rsdp_addr)?;
    let tables = unsafe { find_tables(root_addr, is_xsdt) }?;
    let madt = unsafe { &*(tables.madt as *const Madt) };
    let lapic_addr = madt.lapic_address as u64;
    let ioapic_addr = unsafe { find_ioapic(tables.madt) };
    let hpet_addr = if tables.hpet != 0 {
        let table = unsafe { &*(tables.hpet as *const HpetTable) };
        if table.base_address.address_space_id == 0 {
            Some(table.base_address.address)
        } else {
            None
        }
    } else {
        None
    };

    Some(AcpiInfo {
        lapic_addr,
        ioapic_addr,
        hpet_addr,
    })
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
pub fn arm_interrupt_model(rsdp_addr: u64) -> Option<crate::interrupts::Aarch64InterruptConfig> {
    let (root_addr, is_xsdt) = rsdp_root(rsdp_addr)?;
    let tables = unsafe { find_tables(root_addr, is_xsdt) }?;
    if tables.gtdt == 0 {
        return None;
    }

    let gic = unsafe { find_arm_gic(tables.madt) }?;
    let timer = unsafe { find_arm_timer(tables.gtdt) }?;
    Some(crate::interrupts::Aarch64InterruptConfig {
        gic_model: crate::interrupts::Aarch64GicModel::V3,
        gicd_base: gic.gicd_base,
        gicr_base: gic.gicr_base,
        gicc_base: 0,
        timer_intid: timer.intid,
        timer_edge_triggered: timer.edge_triggered,
        counter_frequency_hz: None,
    })
}

fn rsdp_root(rsdp_addr: u64) -> Option<(u64, bool)> {
    if rsdp_addr == 0 {
        return None;
    }

    let rsdp = unsafe { &*(rsdp_addr as *const Rsdp) };
    if &rsdp.signature != b"RSD PTR " {
        return None;
    }

    let use_xsdt = rsdp.revision >= 2 && rsdp.xsdt_address != 0;
    let root_addr = if use_xsdt {
        rsdp.xsdt_address as u64
    } else {
        rsdp.rsdt_address as u64
    };
    if root_addr == 0 {
        None
    } else {
        Some((root_addr, use_xsdt))
    }
}

unsafe fn find_tables(root_addr: u64, is_xsdt: bool) -> Option<TableAddrs> {
    let header = &*(root_addr as *const SdtHeader);
    let entries_len = header.length as usize - core::mem::size_of::<SdtHeader>();
    let entry_size = if is_xsdt { 8 } else { 4 };
    let count = entries_len / entry_size;
    let entries_base = (root_addr + core::mem::size_of::<SdtHeader>() as u64) as *const u8;

    let mut madt = 0u64;
    #[cfg(target_arch = "x86_64")]
    let mut hpet = 0u64;
    #[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
    let mut gtdt = 0u64;

    for i in 0..count {
        let addr = if is_xsdt {
            let ptr = entries_base.add(i * 8) as *const u64;
            core::ptr::read_unaligned(ptr)
        } else {
            let ptr = entries_base.add(i * 4) as *const u32;
            core::ptr::read_unaligned(ptr) as u64
        };
        if addr == 0 {
            continue;
        }

        let sig = &(*(addr as *const SdtHeader)).signature;
        if sig == b"APIC" {
            madt = addr;
        }
        #[cfg(target_arch = "x86_64")]
        if sig == b"HPET" {
            hpet = addr;
        }
        #[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
        if sig == b"GTDT" {
            gtdt = addr;
        }
    }

    if madt == 0 {
        None
    } else {
        Some(TableAddrs {
            madt,
            #[cfg(target_arch = "x86_64")]
            hpet,
            #[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
            gtdt,
        })
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn find_ioapic(madt_addr: u64) -> Option<u64> {
    let madt = &*(madt_addr as *const Madt);
    let base = madt_addr + core::mem::size_of::<Madt>() as u64;
    let end = madt_addr + madt.header.length as u64;
    let mut ptr = base;
    while ptr + 2 <= end {
        let entry_ptr = ptr as *const u8;
        let entry_type = *entry_ptr;
        let length = *(entry_ptr.add(1)) as u64;
        if length < 2 || ptr + length > end {
            break;
        }
        if entry_type == 1 && length >= 12 {
            let ioapic_addr = *(entry_ptr.add(4) as *const u32) as u64;
            return Some(ioapic_addr);
        }
        ptr += length;
    }
    None
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
unsafe fn find_arm_gic(madt_addr: u64) -> Option<ArmGicInfo> {
    const MADT_TYPE_GICC: u8 = 0x0b;
    const MADT_TYPE_GICD: u8 = 0x0c;
    const MADT_TYPE_GICR: u8 = 0x0e;

    let madt = &*(madt_addr as *const Madt);
    let base = madt_addr + core::mem::size_of::<Madt>() as u64;
    let end = madt_addr + madt.header.length as u64;
    let mut ptr = base;
    let mut gicd_base = 0u64;
    let mut gicd_version = 0u8;
    let mut gicr_base = 0u64;

    while ptr + 2 <= end {
        let entry = &*(ptr as *const MadtEntryHeader);
        let length = entry.length as u64;
        if length < 2 || ptr + length > end {
            break;
        }

        match entry.entry_type {
            MADT_TYPE_GICD if length >= core::mem::size_of::<MadtGenericDistributor>() as u64 => {
                let gicd = &*(ptr as *const MadtGenericDistributor);
                gicd_base = gicd.base_address;
                gicd_version = gicd.version;
            }
            MADT_TYPE_GICR if length >= core::mem::size_of::<MadtGenericRedistributor>() as u64 => {
                let gicr = &*(ptr as *const MadtGenericRedistributor);
                if gicr_base == 0 && gicr.base_address != 0 {
                    gicr_base = gicr.base_address;
                }
            }
            MADT_TYPE_GICC if length >= core::mem::size_of::<MadtGenericInterruptGicr>() as u64 => {
                let gicc = &*(ptr as *const MadtGenericInterruptGicr);
                if gicr_base == 0 && gicc.gicr_base_address != 0 {
                    gicr_base = gicc.gicr_base_address;
                }
            }
            _ => {}
        }

        ptr += length;
    }

    if gicd_base == 0 || gicr_base == 0 {
        return None;
    }
    if gicd_version != 0 && gicd_version < 3 {
        return None;
    }

    Some(ArmGicInfo {
        gicd_base,
        gicr_base,
    })
}

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
unsafe fn find_arm_timer(gtdt_addr: u64) -> Option<ArmTimerInfo> {
    const GTDT_INTERRUPT_MODE: u32 = 1;

    let gtdt = &*(gtdt_addr as *const Gtdt);
    if gtdt.non_secure_el1_interrupt == 0 {
        return None;
    }

    Some(ArmTimerInfo {
        intid: gtdt.non_secure_el1_interrupt,
        edge_triggered: (gtdt.non_secure_el1_flags & GTDT_INTERRUPT_MODE) != 0,
    })
}
