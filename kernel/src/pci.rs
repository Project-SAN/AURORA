use crate::port;
use crate::serial;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

const VENDOR_VIRTIO: u16 = 0x1AF4;
const DEVICE_VIRTIO_NET_LEGACY: u16 = 0x1000;
const DEVICE_VIRTIO_NET_MODERN: u16 = 0x1041;
const PCI_STATUS_CAPABILITIES: u16 = 1 << 4;
const PCI_CAP_ID_VENDOR: u8 = 0x09;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

#[derive(Clone, Copy, Debug)]
pub struct VirtioPciDevice {
    pub bus: u16,
    pub device: u16,
    pub function: u16,
    pub io_base: Option<u16>,
    pub mmio_base: Option<u64>,
    pub common_cfg: Option<u64>,
    pub notify_cfg: Option<u64>,
    pub notify_off_multiplier: u32,
    pub isr_cfg: Option<u64>,
    pub device_cfg: Option<u64>,
}

pub fn scan() -> usize {
    let mut count = 0usize;
    for bus in 0u16..=255 {
        for device in 0u16..32 {
            let vendor = read_u16(bus, device, 0, 0x00);
            if vendor == 0xFFFF {
                continue;
            }
            let header = read_u8(bus, device, 0, 0x0E);
            let functions = if header & 0x80 != 0 { 8 } else { 1 };
            for function in 0u16..functions {
                let vendor = read_u16(bus, device, function, 0x00);
                if vendor == 0xFFFF {
                    continue;
                }
                count += 1;
                log_device(bus, device, function);
            }
        }
    }
    count
}

pub fn find_virtio_net() -> Option<VirtioPciDevice> {
    for bus in 0u16..=255 {
        for device in 0u16..32 {
            let vendor = read_u16(bus, device, 0, 0x00);
            if vendor == 0xFFFF {
                continue;
            }
            let header = read_u8(bus, device, 0, 0x0E);
            let functions = if header & 0x80 != 0 { 8 } else { 1 };
            for function in 0u16..functions {
                let vendor = read_u16(bus, device, function, 0x00);
                if vendor == 0xFFFF {
                    continue;
                }
                let device_id = read_u16(bus, device, function, 0x02);
                let class = read_u8(bus, device, function, 0x0B);
                if vendor == VENDOR_VIRTIO
                    && (device_id == DEVICE_VIRTIO_NET_LEGACY
                        || device_id == DEVICE_VIRTIO_NET_MODERN)
                    && class == 0x02
                {
                    let bars = read_bars(bus, device, function);
                    let mut io_base = None;
                    let mut mmio_base = None;
                    for bar in bars {
                        if bar == 0 {
                            continue;
                        }
                        if bar & 0x1 == 0x1 {
                            if io_base.is_none() {
                                io_base = Some((bar & 0xFFFC) as u16);
                            }
                        } else {
                            let addr = (bar & 0xFFFF_FFF0) as u64;
                            // Skip tiny MSI-X/PBA-style BARs; prefer the main MMIO window.
                            if addr >= 0x1000 && mmio_base.is_none() {
                                mmio_base = Some(addr);
                            }
                        }
                    }
                    let caps = read_virtio_caps(bus, device, function);
                    return Some(VirtioPciDevice {
                        bus,
                        device,
                        function,
                        io_base,
                        mmio_base,
                        common_cfg: caps.common_cfg,
                        notify_cfg: caps.notify_cfg,
                        notify_off_multiplier: caps.notify_off_multiplier,
                        isr_cfg: caps.isr_cfg,
                        device_cfg: caps.device_cfg,
                    });
                }
            }
        }
    }
    None
}

pub fn enable_bus_master(dev: &VirtioPciDevice) {
    let command = read_u16(dev.bus, dev.device, dev.function, 0x04);
    let new_command = command | 0x0004 | 0x0002 | 0x0001; // bus master + mem + io space
    write_u16(dev.bus, dev.device, dev.function, 0x04, new_command);
}

#[derive(Default)]
struct VirtioPciCaps {
    common_cfg: Option<u64>,
    notify_cfg: Option<u64>,
    notify_off_multiplier: u32,
    isr_cfg: Option<u64>,
    device_cfg: Option<u64>,
}

fn read_virtio_caps(bus: u16, device: u16, function: u16) -> VirtioPciCaps {
    let mut caps = VirtioPciCaps::default();
    let status = read_u16(bus, device, function, 0x06);
    if status & PCI_STATUS_CAPABILITIES == 0 {
        return caps;
    }
    let mut cap_ptr = read_u8(bus, device, function, 0x34) & 0xFC;
    let mut guard = 0;
    while cap_ptr != 0 && guard < 64 {
        let cap_off = cap_ptr as u16;
        let cap_id = read_u8(bus, device, function, cap_off);
        let next = read_u8(bus, device, function, cap_off + 1) & 0xFC;
        if cap_id == PCI_CAP_ID_VENDOR {
            let cfg_type = read_u8(bus, device, function, cap_off + 3);
            let bar = read_u8(bus, device, function, cap_off + 4);
            let offset = read_u32(bus, device, function, cap_off + 8);
            let length = read_u32(bus, device, function, cap_off + 12);
            if let Some(bar_base) = read_bar_base(bus, device, function, bar as usize) {
                let addr = bar_base + offset as u64;
                if length != 0 {
                    match cfg_type {
                        VIRTIO_PCI_CAP_COMMON_CFG => caps.common_cfg = Some(addr),
                        VIRTIO_PCI_CAP_NOTIFY_CFG => {
                            caps.notify_cfg = Some(addr);
                            caps.notify_off_multiplier =
                                read_u32(bus, device, function, cap_off + 16);
                        }
                        VIRTIO_PCI_CAP_ISR_CFG => caps.isr_cfg = Some(addr),
                        VIRTIO_PCI_CAP_DEVICE_CFG => caps.device_cfg = Some(addr),
                        _ => {}
                    }
                }
            }
        }
        cap_ptr = next;
        guard += 1;
    }
    caps
}

fn read_bar_base(bus: u16, device: u16, function: u16, index: usize) -> Option<u64> {
    if index >= 6 {
        return None;
    }
    let offset = 0x10 + (index * 4);
    let bar = read_u32(bus, device, function, offset as u16);
    if bar == 0 {
        return None;
    }
    if bar & 0x1 == 0x1 {
        // I/O space BAR
        return None;
    }
    let typ = (bar >> 1) & 0x3;
    let base_low = (bar & 0xFFFF_FFF0) as u64;
    if typ == 0x2 {
        // 64-bit BAR
        if index + 1 >= 6 {
            return None;
        }
        let bar_high = read_u32(bus, device, function, (offset + 4) as u16) as u64;
        Some((bar_high << 32) | base_low)
    } else {
        Some(base_low)
    }
}

fn log_device(bus: u16, device: u16, function: u16) {
    let vendor = read_u16(bus, device, function, 0x00);
    let device_id = read_u16(bus, device, function, 0x02);
    let class = read_u8(bus, device, function, 0x0B);
    let subclass = read_u8(bus, device, function, 0x0A);
    let prog_if = read_u8(bus, device, function, 0x09);
    let header = read_u8(bus, device, function, 0x0E);

    serial::write(format_args!(
        "PCI {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:02x}:{:02x}:{:02x} header={:02x}\n",
        bus, device, function, vendor, device_id, class, subclass, prog_if, header
    ));

    if vendor == VENDOR_VIRTIO {
        serial::write(format_args!(
            "  -> virtio device id={:04x}\n",
            device_id
        ));
        log_bars(bus, device, function);
    }
}

fn log_bars(bus: u16, device: u16, function: u16) {
    for i in 0..6 {
        let offset = 0x10 + (i * 4);
        let bar = read_u32(bus, device, function, offset);
        if bar == 0 {
            continue;
        }
        serial::write(format_args!("  BAR{} = {:#010x}\n", i, bar));
    }
}

fn read_bars(bus: u16, device: u16, function: u16) -> [u32; 6] {
    let mut bars = [0u32; 6];
    for i in 0..6 {
        let offset = (0x10 + (i * 4)) as u16;
        bars[i] = read_u32(bus, device, function, offset);
    }
    bars
}

fn read_u32(bus: u16, device: u16, function: u16, offset: u16) -> u32 {
    let address = config_address(bus, device, function, offset);
    unsafe {
        port::outl(CONFIG_ADDRESS, address);
        port::inl(CONFIG_DATA)
    }
}

fn write_u32(bus: u16, device: u16, function: u16, offset: u16, value: u32) {
    let address = config_address(bus, device, function, offset);
    unsafe {
        port::outl(CONFIG_ADDRESS, address);
        port::outl(CONFIG_DATA, value);
    }
}

fn read_u16(bus: u16, device: u16, function: u16, offset: u16) -> u16 {
    let value = read_u32(bus, device, function, offset & 0xFC);
    let shift = (offset & 2) * 8;
    ((value >> shift) & 0xFFFF) as u16
}

fn write_u16(bus: u16, device: u16, function: u16, offset: u16, value: u16) {
    let aligned = offset & 0xFC;
    let mut current = read_u32(bus, device, function, aligned);
    let shift = (offset & 2) * 8;
    current &= !(0xFFFFu32 << shift);
    current |= (value as u32) << shift;
    write_u32(bus, device, function, aligned, current);
}

fn read_u8(bus: u16, device: u16, function: u16, offset: u16) -> u8 {
    let value = read_u32(bus, device, function, offset & 0xFC);
    let shift = (offset & 3) * 8;
    ((value >> shift) & 0xFF) as u8
}

fn config_address(bus: u16, device: u16, function: u16, offset: u16) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}
