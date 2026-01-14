use crate::port;
use crate::serial;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

const VENDOR_VIRTIO: u16 = 0x1AF4;
const DEVICE_VIRTIO_NET: u16 = 0x1000;

#[derive(Clone, Copy, Debug)]
pub struct VirtioPciDevice {
    pub bus: u16,
    pub device: u16,
    pub function: u16,
    pub io_base: Option<u16>,
    pub mmio_base: Option<u64>,
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
                if vendor == VENDOR_VIRTIO && device_id == DEVICE_VIRTIO_NET && class == 0x02 {
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
                    return Some(VirtioPciDevice {
                        bus,
                        device,
                        function,
                        io_base,
                        mmio_base,
                    });
                }
            }
        }
    }
    None
}

pub fn enable_bus_master(dev: &VirtioPciDevice) {
    let command = read_u16(dev.bus, dev.device, dev.function, 0x04);
    let new_command = command | 0x0004 | 0x0001; // bus master + io space
    write_u16(dev.bus, dev.device, dev.function, 0x04, new_command);
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
