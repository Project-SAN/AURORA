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

#[repr(C, packed)]
struct Gas {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
}

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

#[derive(Clone, Copy, Debug)]
pub struct AcpiInfo {
    pub lapic_addr: u64,
    pub ioapic_addr: Option<u64>,
    pub hpet_addr: Option<u64>,
}

pub fn init(rsdp_addr: u64) -> Option<AcpiInfo> {
    let rsdp = unsafe { &*(rsdp_addr as *const Rsdp) };
    if &rsdp.signature != b"RSD PTR " {
        return None;
    }
    let use_xsdt = rsdp.revision >= 2 && rsdp.xsdt_address != 0;
    let xsdt_addr = if use_xsdt {
        rsdp.xsdt_address as u64
    } else {
        rsdp.rsdt_address as u64
    };

    let (madt_addr, hpet_addr) = unsafe { find_tables(xsdt_addr, use_xsdt) }?;
    let madt = unsafe { &*(madt_addr as *const Madt) };
    let lapic_addr = madt.lapic_address as u64;
    let ioapic_addr = unsafe { find_ioapic(madt_addr) };
    let hpet_addr = if hpet_addr != 0 {
        let table = unsafe { &*(hpet_addr as *const HpetTable) };
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

unsafe fn find_tables(xsdt_addr: u64, is_xsdt: bool) -> Option<(u64, u64)> {
    let header = &*(xsdt_addr as *const SdtHeader);
    let entries_len = header.length as usize - core::mem::size_of::<SdtHeader>();
    let entry_size = if is_xsdt { 8 } else { 4 };
    let count = entries_len / entry_size;
    let entries_base = (xsdt_addr + core::mem::size_of::<SdtHeader>() as u64) as *const u8;

    let mut madt_addr = 0u64;
    let mut hpet_addr = 0u64;

    for i in 0..count {
        let addr = if is_xsdt {
            let ptr = entries_base.add(i * 8) as *const u64;
            core::ptr::read_unaligned(ptr)
        } else {
            let ptr = entries_base.add(i * 4) as *const u32;
            core::ptr::read_unaligned(ptr) as u64
        };
        let sig = &(*(addr as *const SdtHeader)).signature;
        if sig == b"APIC" {
            madt_addr = addr;
        } else if sig == b"HPET" {
            hpet_addr = addr;
        }
    }

    if madt_addr == 0 {
        None
    } else {
        Some((madt_addr, hpet_addr))
    }
}

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
            // IOAPIC structure
            let ioapic_addr = *(entry_ptr.add(4) as *const u32) as u64;
            return Some(ioapic_addr);
        }
        ptr += length;
    }
    None
}
