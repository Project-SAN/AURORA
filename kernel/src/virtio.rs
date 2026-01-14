use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::cmp;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{fence, AtomicU32, Ordering};

use crate::memory;
use crate::pci::VirtioPciDevice;
use crate::paging;
use crate::port;
use crate::serial;

const VIRTIO_NET_F_MAC: u32 = 5;
const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

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
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 0x80;

const QUEUE_NUM_RX: u16 = 0;
const QUEUE_NUM_TX: u16 = 1;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTIO_NET_HDR_LEN_LEGACY: usize = 10;
const VIRTIO_NET_HDR_LEN_MRG: usize = 12;
const VIRTQ_ALIGN: usize = 4096;
const RX_BUFFER_LEN: usize = 2048;
const RX_QUEUE_ENTRIES: usize = 32;
const TX_BUFFER_LEN: usize = 4096 - VIRTIO_NET_HDR_LEN_LEGACY;
const TX_POOL_SIZE: usize = 32;

static RX_LOG: AtomicU32 = AtomicU32::new(0);
static TX_LOG: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
struct VirtioPciCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc: u64,
    queue_driver: u64,
    queue_device: u64,
}

#[derive(Clone, Copy)]
enum Notify {
    Port(u16),
    Mmio(u64),
}

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

pub fn init_net(dev: &VirtioPciDevice) -> bool {
    if dev.common_cfg.is_some() && dev.notify_cfg.is_some() && dev.device_cfg.is_some() {
        if init_net_modern(dev) {
            return true;
        }
        serial::write(format_args!(
            "virtio: modern init failed, falling back to legacy\n"
        ));
    }
    init_net_legacy(dev)
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
        rxq.desc_phys, txq.desc_phys
    ));

    let hdr_len = VIRTIO_NET_HDR_LEN_LEGACY;
    if !prime_rx_buffers(&mut rxq, RX_QUEUE_ENTRIES, hdr_len) {
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
        rx: rxq,
        tx: txq,
        tx_state,
        hdr_len,
        mac,
    });
    true
}

fn init_net_modern(dev: &VirtioPciDevice) -> bool {
    let common_addr = match dev.common_cfg {
        Some(addr) => addr,
        None => return false,
    };
    let notify_base = match dev.notify_cfg {
        Some(addr) => addr,
        None => return false,
    };
    let device_cfg = match dev.device_cfg {
        Some(addr) => addr,
        None => return false,
    };
    let notify_mult = dev.notify_off_multiplier;
    if notify_mult == 0 {
        serial::write(format_args!("virtio: notify multiplier is zero\n"));
        return false;
    }

    let common_ptr = mmio_ptr(common_addr);
    let notify_base_ptr = mmio_ptr(notify_base);
    let device_cfg_ptr = mmio_ptr(device_cfg);
    serial::write(format_args!(
        "virtio: common={:#x} notify={:#x} mult={:#x} device={:#x}\n",
        common_ptr, notify_base_ptr, notify_mult, device_cfg_ptr
    ));
    let common = common_ptr as *mut VirtioPciCommonCfg;

    unsafe {
        write_volatile(&mut (*common).device_status, 0);
        write_volatile(&mut (*common).device_status, STATUS_ACKNOWLEDGE);
        write_volatile(&mut (*common).device_status, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    }

    let device_features = read_device_features(common);
    if (device_features & VIRTIO_F_VERSION_1) == 0 {
        serial::write(format_args!("virtio: device lacks version 1 feature\n"));
        write_status(common, STATUS_FAILED);
        return false;
    }
    let mut driver_features = VIRTIO_F_VERSION_1;
    if (device_features & (1u64 << VIRTIO_NET_F_MAC)) != 0 {
        driver_features |= 1u64 << VIRTIO_NET_F_MAC;
    }
    let mut hdr_len = VIRTIO_NET_HDR_LEN_LEGACY;
    if (device_features & (1u64 << VIRTIO_NET_F_MRG_RXBUF)) != 0 {
        driver_features |= 1u64 << VIRTIO_NET_F_MRG_RXBUF;
        hdr_len = VIRTIO_NET_HDR_LEN_MRG;
    }
    write_driver_features(common, driver_features);

    write_status(
        common,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
    );
    if (read_status(common) & STATUS_FEATURES_OK) == 0 {
        serial::write(format_args!("virtio: FEATURES_OK not accepted\n"));
        write_status(common, STATUS_FAILED);
        return false;
    }

    let mut mac = [0u8; 6];
    if (driver_features & (1u64 << VIRTIO_NET_F_MAC)) != 0 {
        for i in 0..6 {
            unsafe {
                mac[i] = read_volatile((device_cfg_ptr as *const u8).add(i));
            }
        }
        serial::write(format_args!(
            "virtio-net mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ));
    }

    let mut rxq = match setup_queue_modern(common, notify_base_ptr, notify_mult, QUEUE_NUM_RX) {
        Some(q) => q,
        None => {
            write_status(common, STATUS_FAILED);
            return false;
        }
    };
    let txq = match setup_queue_modern(common, notify_base_ptr, notify_mult, QUEUE_NUM_TX) {
        Some(q) => q,
        None => {
            write_status(common, STATUS_FAILED);
            return false;
        }
    };
    serial::write(format_args!(
        "virtio: rx phys={:#x} tx phys={:#x}\n",
        rxq.desc_phys, txq.desc_phys
    ));

    if !prime_rx_buffers(&mut rxq, RX_QUEUE_ENTRIES, hdr_len) {
        write_status(common, STATUS_FAILED);
        return false;
    }

    let tx_state = match init_tx_state(&txq) {
        Some(state) => state,
        None => {
            write_status(common, STATUS_FAILED);
            return false;
        }
    };

    write_status(
        common,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    );
    serial::write(format_args!("virtio-net modern init complete\n"));

    set_net(VirtioNet {
        rx: rxq,
        tx: txq,
        tx_state,
        hdr_len,
        mac,
    });
    true
}

fn setup_queue_modern(
    common: *mut VirtioPciCommonCfg,
    notify_base: u64,
    notify_mult: u32,
    queue: u16,
) -> Option<VirtQueue> {
    unsafe {
        write_volatile(&mut (*common).queue_select, queue);
    }
    let max = unsafe { read_volatile(&(*common).queue_size) };
    if max == 0 {
        serial::write(format_args!("virtio: queue {} not available\n", queue));
        return None;
    }
    let qsize = max.min(256);
    unsafe {
        write_volatile(&mut (*common).queue_size, qsize);
    }
    let mem = allocate_queue(qsize)?;
    unsafe {
        write_volatile(&mut (*common).queue_desc, mem.queue.desc_phys);
        write_volatile(&mut (*common).queue_driver, mem.queue.avail_phys);
        write_volatile(&mut (*common).queue_device, mem.queue.used_phys);
        write_volatile(&mut (*common).queue_msix_vector, 0xFFFF);
    }
    let notify_off = unsafe { read_volatile(&(*common).queue_notify_off) };
    let notify_addr = notify_base + (notify_off as u64) * (notify_mult as u64);
    serial::write(format_args!(
        "virtio: q{} size {} notify_off {} addr={:#x}\n",
        queue, qsize, notify_off, notify_addr
    ));
    unsafe {
        write_volatile(&mut (*common).queue_enable, 1);
    }
    let mut q = mem.queue;
    q.queue_index = queue;
    q.notify = Notify::Mmio(notify_addr);
    Some(q)
}

fn mmio_ptr(phys: u64) -> u64 {
    if phys >= 0x1_0000_0000 {
        paging::map_mmio(phys);
    }
    paging::to_higher_half(phys)
}

fn read_device_features(common: *mut VirtioPciCommonCfg) -> u64 {
    unsafe {
        write_volatile(&mut (*common).device_feature_select, 0);
        let lo = read_volatile(&(*common).device_feature) as u64;
        write_volatile(&mut (*common).device_feature_select, 1);
        let hi = read_volatile(&(*common).device_feature) as u64;
        (hi << 32) | lo
    }
}

fn write_driver_features(common: *mut VirtioPciCommonCfg, features: u64) {
    unsafe {
        write_volatile(&mut (*common).driver_feature_select, 0);
        write_volatile(&mut (*common).driver_feature, features as u32);
        write_volatile(&mut (*common).driver_feature_select, 1);
        write_volatile(&mut (*common).driver_feature, (features >> 32) as u32);
    }
}

fn write_status(common: *mut VirtioPciCommonCfg, status: u8) {
    unsafe {
        write_volatile(&mut (*common).device_status, status);
    }
}

fn read_status(common: *mut VirtioPciCommonCfg) -> u8 {
    unsafe { read_volatile(&(*common).device_status) }
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
    let mut q = mem.queue;
    q.queue_index = queue;
    q.notify = Notify::Port(io);
    Some(q)
}

struct QueueMem {
    phys: u64,
    _size: usize,
    queue: VirtQueue,
}

struct VirtioNet {
    rx: VirtQueue,
    tx: VirtQueue,
    tx_state: TxState,
    hdr_len: usize,
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
    desc_phys: u64,
    avail_phys: u64,
    used_phys: u64,
    queue_index: u16,
    notify: Notify,
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
    let desc_phys = mem.phys;
    let avail_phys = mem.phys + desc_size as u64;
    let used_phys = mem.phys + used_offset as u64;

    Some(QueueMem {
        phys: mem.phys,
        _size: total,
        queue: VirtQueue {
            size: qsize,
            desc,
            avail,
            used,
            desc_phys,
            avail_phys,
            used_phys,
            queue_index: 0,
            notify: Notify::Port(0),
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

fn prime_rx_buffers(rxq: &mut VirtQueue, count: usize, hdr_len: usize) -> bool {
    let count = count.min(rxq.size as usize);
    for i in 0..count {
        let buf = match memory::alloc_dma_pages(1) {
            Some(buf) => buf,
            None => return false,
        };
        let head = (i * 2) as u16;
        let desc = VirtqDesc {
            addr: buf.phys,
            len: hdr_len as u32,
            flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
            next: head + 1,
        };
        let desc2 = VirtqDesc {
            addr: buf.phys + hdr_len as u64,
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
    notify_queue(rxq);
    true
}

pub fn send_frame(frame: &[u8]) -> bool {
    match with_net(|net| send_frame_queue(&mut net.tx, &mut net.tx_state, net.hdr_len, frame)) {
        Some(ok) => ok,
        None => false,
    }
}

pub fn reclaim_tx() {
    let _ = with_net(|net| reclaim_tx_queue(&mut net.tx, &mut net.tx_state));
}

fn send_frame_queue(
    txq: &mut VirtQueue,
    tx_state: &mut TxState,
    hdr_len: usize,
    frame: &[u8],
) -> bool {
    reclaim_tx_queue(txq, tx_state);
    if frame.len() + hdr_len > 4096 {
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
        core::ptr::copy_nonoverlapping(frame.as_ptr(), virt.add(hdr_len), frame.len());
    }

    let desc0 = VirtqDesc {
        addr: buf_phys,
        len: hdr_len as u32,
        flags: VIRTQ_DESC_F_NEXT,
        next: head + 1,
    };
    let desc1 = VirtqDesc {
        addr: buf_phys + hdr_len as u64,
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
    notify_queue(txq);
    if TX_LOG.fetch_add(1, Ordering::Relaxed) < 8 {
        serial::write(format_args!(
            "virtio: tx len={} head={} free={}\n",
            frame.len(),
            head,
            tx_state.free.len()
        ));
        if frame.len() >= 14 {
            let eth_type = ((frame[12] as u16) << 8) | (frame[13] as u16);
            serial::write(format_args!("virtio: tx eth=0x{:04x}\n", eth_type));
        }
    }
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

fn notify_queue(queue: &VirtQueue) {
    match queue.notify {
        Notify::Port(io) => outw(io, REG_QUEUE_NOTIFY, queue.queue_index),
        Notify::Mmio(addr) => unsafe {
            write_volatile(addr as *mut u32, queue.queue_index as u32);
        },
    }
}

fn used_idx(queue: &VirtQueue) -> u16 {
    unsafe { read_volatile(&(*queue.used).idx) }
}

pub fn recv_frame() -> Option<Vec<u8>> {
    with_net(|net| recv_frame_queue(&mut net.rx, net.hdr_len))?
}

fn recv_frame_queue(rxq: &mut VirtQueue, hdr_len: usize) -> Option<Vec<u8>> {
    let used = used_idx(rxq);
    if rxq.last_used == used {
        return None;
    }

    let idx = rxq.last_used % rxq.size;
    let elem = unsafe { read_volatile(used_ring(rxq).add(idx as usize)) };
    let head = elem.id as u16;
    let total_len = elem.len as usize;

    let desc1 = unsafe { read_volatile(rxq.desc.add((head + 1) as usize)) };
    let payload_len = total_len.saturating_sub(hdr_len);
    let copy_len = cmp::min(payload_len, desc1.len as usize);
    let src = memory::phys_to_virt(desc1.addr);
    let mut frame = Vec::with_capacity(copy_len);
    unsafe {
        frame.set_len(copy_len);
        core::ptr::copy_nonoverlapping(src, frame.as_mut_ptr(), copy_len);
    }

    push_avail(rxq, head);
    notify_queue(rxq);
    rxq.last_used = rxq.last_used.wrapping_add(1);
    if RX_LOG.fetch_add(1, Ordering::Relaxed) < 8 {
        serial::write(format_args!(
            "virtio: rx len={} head={}\n",
            copy_len, head
        ));
        if copy_len >= 14 {
            let eth_type = ((frame[12] as u16) << 8) | (frame[13] as u16);
            if eth_type == 0x0806 && copy_len >= 42 {
                let op = ((frame[20] as u16) << 8) | (frame[21] as u16);
                let tip = [frame[38], frame[39], frame[40], frame[41]];
                serial::write(format_args!(
                    "virtio: rx arp op={} tip={}.{}.{}.{}\n",
                    op, tip[0], tip[1], tip[2], tip[3]
                ));
            } else {
                serial::write(format_args!("virtio: rx eth=0x{:04x}\n", eth_type));
            }
        }
    }
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
