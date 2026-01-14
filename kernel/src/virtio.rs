use core::ptr::{read_volatile, write_bytes, write_volatile};

use crate::memory;
use crate::pci::VirtioPciDevice;
use crate::port;
use crate::serial;

const VIRTIO_NET_F_MAC: u32 = 5;

const REG_DEVICE_FEATURES: u16 = 0x00;
const REG_DRIVER_FEATURES: u16 = 0x04;
const REG_QUEUE_ADDR: u16 = 0x08;
const REG_QUEUE_SIZE: u16 = 0x0C;
const REG_QUEUE_SELECT: u16 = 0x0E;
const REG_QUEUE_NOTIFY: u16 = 0x10;
const REG_DEVICE_STATUS: u16 = 0x12;
const REG_ISR_STATUS: u16 = 0x13;
const REG_DEVICE_CONFIG: u16 = 0x14;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 0x80;

const QUEUE_NUM_RX: u16 = 0;
const QUEUE_NUM_TX: u16 = 1;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTIO_NET_HDR_LEN: usize = 10;

#[repr(C)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; 0],
}

#[repr(C)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; 0],
}

#[repr(C)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

pub fn init_net_legacy(dev: &VirtioPciDevice) -> bool {
    let io = match dev.io_base {
        Some(io) => io,
        None => {
            serial::write(format_args!("virtio: no io base\n"));
            return false;
        }
    };

    // Reset
    outb(io, REG_DEVICE_STATUS, 0);
    outb(io, REG_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
    outb(io, REG_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let device_features = inl(io, REG_DEVICE_FEATURES);
    let mut driver_features = 0u32;
    if (device_features & (1 << VIRTIO_NET_F_MAC)) != 0 {
        driver_features |= 1 << VIRTIO_NET_F_MAC;
    }
    outl(io, REG_DRIVER_FEATURES, driver_features);

    let mut mac = [0u8; 6];
    if (driver_features & (1 << VIRTIO_NET_F_MAC)) != 0 {
        for i in 0..6 {
            mac[i] = inb(io, REG_DEVICE_CONFIG + i as u16);
        }
        serial::write(format_args!(
            "virtio-net mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ));
    }

    let mut rxq = match setup_queue(io, QUEUE_NUM_RX) {
        Some(q) => q,
        None => {
            fail(io, "queue rx");
            return false;
        }
    };
    let mut txq = match setup_queue(io, QUEUE_NUM_TX) {
        Some(q) => q,
        None => {
            fail(io, "queue tx");
            return false;
        }
    };

    if !prime_rx_buffers(io, &mut rxq, 4) {
        fail(io, "queue rx");
        return false;
    }

    outb(
        io,
        REG_DEVICE_STATUS,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK,
    );
    serial::write(format_args!("virtio-net legacy init complete\n"));

    // Send a dummy Ethernet broadcast frame to validate TX.
    send_test_frame(io, &mut txq, &mac);
    true
}

fn setup_queue(io: u16, queue: u16) -> Option<VirtQueue> {
    outw(io, REG_QUEUE_SELECT, queue);
    let max = inw(io, REG_QUEUE_SIZE);
    if max == 0 {
        serial::write(format_args!("virtio: queue {} not available\n", queue));
        return None;
    }
    let qsize = max;
    let mem = allocate_queue(qsize)?;
    let pfn = (mem.phys >> 12) as u32;
    outl(io, REG_QUEUE_ADDR, pfn);
    serial::write(format_args!(
        "virtio: queue {} size {} pfn {:#x}\n",
        queue, qsize, pfn
    ));
    Some(mem.queue)
}

struct QueueMem {
    phys: u64,
    _size: usize,
    queue: VirtQueue,
}

struct VirtQueue {
    size: u16,
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    avail_idx: u16,
    last_used: u16,
}

fn allocate_queue(qsize: u16) -> Option<QueueMem> {
    let desc_size = core::mem::size_of::<VirtqDesc>() * (qsize as usize);
    let avail_size = 6 + 2 * (qsize as usize);
    let used_size = 6 + 8 * (qsize as usize);
    let used_offset = align_up(desc_size + avail_size, 4);
    let total = used_offset + used_size;
    let pages = (total + 4095) / 4096;
    let mem = memory::alloc_dma_pages(pages)?;
    unsafe {
        let ptr = memory::phys_to_virt(mem.phys);
        write_bytes(ptr, 0, pages * 4096);
    }
    let desc = memory::phys_to_virt(mem.phys) as *mut VirtqDesc;
    let avail = unsafe { (memory::phys_to_virt(mem.phys) as *mut u8).add(desc_size) }
        as *mut VirtqAvail;
    let used = unsafe { (memory::phys_to_virt(mem.phys) as *mut u8).add(used_offset) }
        as *mut VirtqUsed;

    Some(QueueMem {
        phys: mem.phys,
        _size: total,
        queue: VirtQueue {
            size: qsize,
            desc,
            avail,
            used,
            avail_idx: 0,
            last_used: 0,
        },
    })
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn fail(io: u16, msg: &str) {
    serial::write(format_args!("virtio init failed: {}\n", msg));
    outb(io, REG_DEVICE_STATUS, STATUS_FAILED);
}

fn prime_rx_buffers(io: u16, rxq: &mut VirtQueue, count: usize) -> bool {
    let count = count.min(rxq.size as usize);
    for i in 0..count {
        let buf = match memory::alloc_dma_pages(1) {
            Some(buf) => buf,
            None => return false,
        };
        let desc = VirtqDesc {
            addr: buf.phys,
            len: 2048,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        unsafe {
            write_volatile(rxq.desc.add(i), desc);
        }
        push_avail(rxq, i as u16);
    }
    outw(io, REG_QUEUE_NOTIFY, QUEUE_NUM_RX);
    true
}

fn send_test_frame(io: u16, txq: &mut VirtQueue, mac: &[u8; 6]) {
    let buf = match memory::alloc_dma_pages(1) {
        Some(buf) => buf,
        None => return,
    };
    let virt = memory::phys_to_virt(buf.phys);
    unsafe {
        write_bytes(virt, 0, 4096);
    }

    let frame_ptr = unsafe { virt.add(VIRTIO_NET_HDR_LEN) };
    let frame_len = 60usize;
    let mut frame = [0u8; 60];
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(mac);
    frame[12] = 0x08;
    frame[13] = 0x00;
    unsafe {
        core::ptr::copy_nonoverlapping(frame.as_ptr(), frame_ptr, frame_len);
    }

    let desc0 = VirtqDesc {
        addr: buf.phys,
        len: VIRTIO_NET_HDR_LEN as u32,
        flags: VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = VirtqDesc {
        addr: buf.phys + VIRTIO_NET_HDR_LEN as u64,
        len: frame_len as u32,
        flags: 0,
        next: 0,
    };
    unsafe {
        write_volatile(txq.desc.add(0), desc0);
        write_volatile(txq.desc.add(1), desc1);
    }
    push_avail(txq, 0);
    // notify queue 1
    outw(io, REG_QUEUE_NOTIFY, QUEUE_NUM_TX);

    // Wait briefly for used idx to advance.
    let start = used_idx(txq);
    for _ in 0..5_000_000 {
        if used_idx(txq) != start {
            serial::write(format_args!("virtio: tx complete\n"));
            return;
        }
    }
    serial::write(format_args!("virtio: tx pending\n"));
}

fn push_avail(queue: &mut VirtQueue, desc_idx: u16) {
    let ring = avail_ring(queue);
    let idx = queue.avail_idx;
    let slot = (idx % queue.size) as isize;
    unsafe {
        write_volatile(ring.offset(slot), desc_idx);
        write_volatile(&mut (*queue.avail).idx, idx.wrapping_add(1));
    }
    queue.avail_idx = queue.avail_idx.wrapping_add(1);
}

fn used_idx(queue: &VirtQueue) -> u16 {
    unsafe { read_volatile(&(*queue.used).idx) }
}

fn avail_ring(queue: &VirtQueue) -> *mut u16 {
    unsafe { (queue.avail as *mut u8).add(4) as *mut u16 }
}

#[inline]
fn outb(base: u16, offset: u16, value: u8) {
    unsafe { port::outb(base + offset, value) }
}

#[inline]
fn outw(base: u16, offset: u16, value: u16) {
    unsafe { port::outw(base + offset, value) }
}

#[inline]
fn outl(base: u16, offset: u16, value: u32) {
    unsafe { port::outl(base + offset, value) }
}

#[inline]
fn inb(base: u16, offset: u16) -> u8 {
    unsafe { port::inb(base + offset) }
}

#[inline]
fn inw(base: u16, offset: u16) -> u16 {
    unsafe { port::inw(base + offset) }
}

#[inline]
fn inl(base: u16, offset: u16) -> u32 {
    unsafe { port::inl(base + offset) }
}
