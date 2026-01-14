use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::cmp;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{fence, Ordering};

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
const REG_GUEST_PAGE_SIZE: u16 = 0x28;
const REG_QUEUE_ALIGN: u16 = 0x26;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 0x80;

const QUEUE_NUM_RX: u16 = 0;
const QUEUE_NUM_TX: u16 = 1;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTIO_NET_HDR_LEN: usize = 10;
const VIRTQ_ALIGN: usize = 4096;
const RX_BUFFER_LEN: usize = 2048;
const RX_QUEUE_ENTRIES: usize = 32;
const TX_BUFFER_LEN: usize = 4096 - VIRTIO_NET_HDR_LEN;
const TX_POOL_SIZE: usize = 32;

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
    outl(io, REG_GUEST_PAGE_SIZE, 4096);

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
    let txq = match setup_queue(io, QUEUE_NUM_TX) {
        Some(q) => q,
        None => {
            fail(io, "queue tx");
            return false;
        }
    };
    serial::write(format_args!(
        "virtio: rx phys={:#x} tx phys={:#x}\n",
        rxq.phys, txq.phys
    ));

    if !prime_rx_buffers(io, &mut rxq, RX_QUEUE_ENTRIES) {
        fail(io, "queue rx");
        return false;
    }

    let tx_state = match init_tx_state(&txq) {
        Some(state) => state,
        None => {
            fail(io, "tx buffers");
            return false;
        }
    };

    outb(
        io,
        REG_DEVICE_STATUS,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK,
    );
    serial::write(format_args!("virtio-net legacy init complete\n"));

    // Save queues for polling.
    set_net(VirtioNet {
        io,
        rx: rxq,
        tx: txq,
        tx_state,
        mac,
    });
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
    // Write back the queue size (legacy devices expect this).
    outw(io, REG_QUEUE_SIZE, qsize);
    // Queue alignment (legacy). Use 4K.
    outw(io, REG_QUEUE_ALIGN, VIRTQ_ALIGN as u16);
    let mem = allocate_queue(qsize)?;
    let pfn = (mem.phys >> 12) as u32;
    outl(io, REG_QUEUE_ADDR, pfn);
    serial::write(format_args!(
        "virtio: queue {} size {} pfn {:#x}\n",
        queue, qsize, pfn
    ));
    // Read back queue address for debugging.
    let readback = inl(io, REG_QUEUE_ADDR);
    if readback != pfn {
        serial::write(format_args!(
            "virtio: queue {} addr readback {:#x} (expected {:#x})\n",
            queue, readback, pfn
        ));
    }
    Some(mem.queue)
}

struct QueueMem {
    phys: u64,
    _size: usize,
    queue: VirtQueue,
}

struct VirtioNet {
    io: u16,
    rx: VirtQueue,
    tx: VirtQueue,
    tx_state: TxState,
    mac: [u8; 6],
}

struct TxBuffer {
    phys: u64,
}

struct TxState {
    bufs: Vec<TxBuffer>,
    free: Vec<u16>,
}

struct NetState {
    inner: UnsafeCell<Option<VirtioNet>>,
}

unsafe impl Sync for NetState {}

static NET: NetState = NetState {
    inner: UnsafeCell::new(None),
};

fn set_net(net: VirtioNet) {
    unsafe {
        *NET.inner.get() = Some(net);
    }
}

fn with_net<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut VirtioNet) -> R,
{
    unsafe {
        let slot = &mut *NET.inner.get();
        let net = slot.as_mut()?;
        Some(f(net))
    }
}

pub fn mac_address() -> Option<[u8; 6]> {
    with_net(|net| net.mac)
}

struct VirtQueue {
    size: u16,
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    phys: u64,
    avail_idx: u16,
    last_used: u16,
}

fn allocate_queue(qsize: u16) -> Option<QueueMem> {
    let desc_size = core::mem::size_of::<VirtqDesc>() * (qsize as usize);
    let avail_size = 6 + 2 * (qsize as usize);
    let used_size = 6 + 8 * (qsize as usize);
    let used_offset = align_up(desc_size + avail_size, VIRTQ_ALIGN);
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
            phys: mem.phys,
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
        let head = (i * 2) as u16;
        let desc = VirtqDesc {
            addr: buf.phys,
            len: VIRTIO_NET_HDR_LEN as u32,
            flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
            next: head + 1,
        };
        let desc2 = VirtqDesc {
            addr: buf.phys + VIRTIO_NET_HDR_LEN as u64,
            len: RX_BUFFER_LEN as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        unsafe {
            write_volatile(rxq.desc.add(head as usize), desc);
            write_volatile(rxq.desc.add((head + 1) as usize), desc2);
        }
        push_avail(rxq, head);
    }
    outw(io, REG_QUEUE_NOTIFY, QUEUE_NUM_RX);
    true
}

pub fn send_frame(frame: &[u8]) -> bool {
    match with_net(|net| send_frame_queue(net.io, &mut net.tx, &mut net.tx_state, frame)) {
        Some(ok) => ok,
        None => false,
    }
}

pub fn reclaim_tx() {
    let _ = with_net(|net| reclaim_tx_queue(&mut net.tx, &mut net.tx_state));
}

fn send_frame_queue(io: u16, txq: &mut VirtQueue, tx_state: &mut TxState, frame: &[u8]) -> bool {
    reclaim_tx_queue(txq, tx_state);
    if frame.len() > TX_BUFFER_LEN {
        serial::write(format_args!(
            "virtio: tx frame too large ({})\n",
            frame.len()
        ));
        return false;
    }
    let head = match tx_state.free.pop() {
        Some(head) => head,
        None => {
            serial::write(format_args!("virtio: tx no free buffers\n"));
            return false;
        }
    };
    let buf_index = (head as usize) / 2;
    if buf_index >= tx_state.bufs.len() {
        serial::write(format_args!("virtio: tx invalid head {}\n", head));
        return false;
    }
    let buf_phys = tx_state.bufs[buf_index].phys;
    let virt = memory::phys_to_virt(buf_phys);
    unsafe {
        write_bytes(virt, 0, 4096);
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            virt.add(VIRTIO_NET_HDR_LEN),
            frame.len(),
        );
    }

    let desc0 = VirtqDesc {
        addr: buf_phys,
        len: VIRTIO_NET_HDR_LEN as u32,
        flags: VIRTQ_DESC_F_NEXT,
        next: head + 1,
    };
    let desc1 = VirtqDesc {
        addr: buf_phys + VIRTIO_NET_HDR_LEN as u64,
        len: frame.len() as u32,
        flags: 0,
        next: 0,
    };
    unsafe {
        write_volatile(txq.desc.add(head as usize), desc0);
        write_volatile(txq.desc.add((head + 1) as usize), desc1);
    }

    fence(Ordering::SeqCst);
    push_avail(txq, head);
    fence(Ordering::SeqCst);
    outw(io, REG_QUEUE_NOTIFY, QUEUE_NUM_TX);
    true
}

fn push_avail(queue: &mut VirtQueue, desc_idx: u16) {
    let ring = avail_ring(queue);
    let idx = queue.avail_idx;
    let slot = (idx % queue.size) as isize;
    unsafe {
        write_volatile(ring.offset(slot), desc_idx);
        fence(Ordering::SeqCst);
        write_volatile(&mut (*queue.avail).idx, idx.wrapping_add(1));
    }
    queue.avail_idx = queue.avail_idx.wrapping_add(1);
}

fn used_idx(queue: &VirtQueue) -> u16 {
    unsafe { read_volatile(&(*queue.used).idx) }
}

pub fn recv_frame() -> Option<Vec<u8>> {
    with_net(|net| recv_frame_queue(net.io, &mut net.rx))?
}

fn recv_frame_queue(io: u16, rxq: &mut VirtQueue) -> Option<Vec<u8>> {
    let used = used_idx(rxq);
    if rxq.last_used == used {
        return None;
    }

    let idx = rxq.last_used % rxq.size;
    let elem = unsafe { read_volatile(used_ring(rxq).add(idx as usize)) };
    let head = elem.id as u16;
    let total_len = elem.len as usize;

    let desc1 = unsafe { read_volatile(rxq.desc.add((head + 1) as usize)) };
    let payload_len = total_len.saturating_sub(VIRTIO_NET_HDR_LEN);
    let copy_len = cmp::min(payload_len, desc1.len as usize);
    let src = memory::phys_to_virt(desc1.addr);
    let mut frame = Vec::with_capacity(copy_len);
    unsafe {
        frame.set_len(copy_len);
        core::ptr::copy_nonoverlapping(src, frame.as_mut_ptr(), copy_len);
    }

    push_avail(rxq, head);
    outw(io, REG_QUEUE_NOTIFY, QUEUE_NUM_RX);
    rxq.last_used = rxq.last_used.wrapping_add(1);
    Some(frame)
}

fn init_tx_state(txq: &VirtQueue) -> Option<TxState> {
    let max_pairs = (txq.size as usize) / 2;
    let count = cmp::min(TX_POOL_SIZE, max_pairs).max(1);
    let mut bufs: Vec<TxBuffer> = Vec::with_capacity(count);
    let mut free = Vec::with_capacity(count);

    for i in 0..count {
        let buf = match memory::alloc_dma_pages(1) {
            Some(buf) => buf,
            None => {
                for b in &bufs {
                    memory::free_contiguous(b.phys, 1);
                }
                return None;
            }
        };
        bufs.push(TxBuffer { phys: buf.phys });
        free.push((i * 2) as u16);
    }
    Some(TxState { bufs, free })
}

fn reclaim_tx_queue(txq: &mut VirtQueue, tx_state: &mut TxState) {
    let used = used_idx(txq);
    while txq.last_used != used {
        let idx = txq.last_used % txq.size;
        let elem = unsafe { read_volatile(used_ring(txq).add(idx as usize)) };
        let head = elem.id as u16;
        let buf_index = (head as usize) / 2;
        if buf_index < tx_state.bufs.len() {
            tx_state.free.push(head);
        } else {
            serial::write(format_args!("virtio: tx reclaim unknown head {}\n", head));
        }
        txq.last_used = txq.last_used.wrapping_add(1);
    }
}

fn avail_ring(queue: &VirtQueue) -> *mut u16 {
    unsafe { (queue.avail as *mut u8).add(4) as *mut u16 }
}

fn used_ring(queue: &VirtQueue) -> *mut VirtqUsedElem {
    unsafe { (queue.used as *mut u8).add(4) as *mut VirtqUsedElem }
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
