use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::cmp;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use crate::memory;
use crate::pci;
use crate::pci::VirtioPciDevice;
use crate::paging;
use crate::serial;
use crate::interrupts;

const VIRTIO_NET_F_MAC: u32 = 5;
const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_STATUS_OK: u8 = 0;
const QUEUE_NUM_BLK: u16 = 0;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 0x80;

const QUEUE_NUM_RX: u16 = 0;
const QUEUE_NUM_TX: u16 = 1;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTIO_NET_HDR_LEN: usize = 12;
const VIRTQ_ALIGN: usize = 4096;
const RX_BUFFER_LEN: usize = 2048;
const RX_QUEUE_ENTRIES: usize = 32;
const TX_POOL_SIZE: usize = 32;
const RX_MSIX_VECTOR: u16 = 0;
const TX_MSIX_VECTOR: u16 = 1;

static RX_LOG: AtomicU32 = AtomicU32::new(0);
static TX_LOG: AtomicU32 = AtomicU32::new(0);

struct NetStats {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    rx_drops: AtomicU64,
    rx_overflow: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    tx_drops: AtomicU64,
    tx_overflow: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
pub struct NetStatsSnapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_drops: u64,
    pub rx_overflow: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_drops: u64,
    pub tx_overflow: u64,
}

impl NetStats {
    const fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            rx_drops: AtomicU64::new(0),
            rx_overflow: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_drops: AtomicU64::new(0),
            tx_overflow: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> NetStatsSnapshot {
        NetStatsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_drops: self.rx_drops.load(Ordering::Relaxed),
            rx_overflow: self.rx_overflow.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_drops: self.tx_drops.load(Ordering::Relaxed),
            tx_overflow: self.tx_overflow.load(Ordering::Relaxed),
        }
    }
}

static NET_STATS: NetStats = NetStats::new();

pub fn stats_snapshot() -> NetStatsSnapshot {
    NET_STATS.snapshot()
}

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

#[repr(C)]
struct MsixTableEntry {
    addr_low: u32,
    addr_high: u32,
    data: u32,
    ctrl: u32,
}

pub fn init_net(dev: &VirtioPciDevice) -> bool {
    init_net_modern(dev)
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

    if dev.msix_table.is_none() || dev.msix_table_size < 2 {
        serial::write(format_args!("virtio: MSI-X not available\n"));
        return false;
    }
    if !pci::enable_msix(dev) {
        serial::write(format_args!("virtio: MSI-X enable failed\n"));
        return false;
    }
    if !setup_msix(dev) {
        serial::write(format_args!("virtio: MSI-X setup failed\n"));
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
        write_volatile(&mut (*common).msix_config, 0xFFFF);
    }

    let device_features = read_device_features(common);
    let required =
        VIRTIO_F_VERSION_1 | (1u64 << VIRTIO_NET_F_MAC) | (1u64 << VIRTIO_NET_F_MRG_RXBUF);
    if (device_features & required) != required {
        serial::write(format_args!(
            "virtio: missing required features (device={:#x} required={:#x})\n",
            device_features, required
        ));
        write_status(common, STATUS_FAILED);
        return false;
    }
    let driver_features = required;
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
    for i in 0..6 {
        unsafe {
            mac[i] = read_volatile((device_cfg_ptr as *const u8).add(i));
        }
    }
    serial::write(format_args!(
        "virtio-net mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ));

    let mut rxq = match setup_queue_modern(
        common,
        notify_base_ptr,
        notify_mult,
        QUEUE_NUM_RX,
        RX_MSIX_VECTOR,
    ) {
        Some(q) => q,
        None => {
            write_status(common, STATUS_FAILED);
            return false;
        }
    };
    let txq = match setup_queue_modern(
        common,
        notify_base_ptr,
        notify_mult,
        QUEUE_NUM_TX,
        TX_MSIX_VECTOR,
    ) {
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

    if !prime_rx_buffers(&mut rxq, RX_QUEUE_ENTRIES) {
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
        mac,
    });
    true
}

fn setup_queue_modern(
    common: *mut VirtioPciCommonCfg,
    notify_base: u64,
    notify_mult: u32,
    queue: u16,
    vector: u16,
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
        write_volatile(&mut (*common).queue_msix_vector, vector);
    }
    let readback = unsafe { read_volatile(&(*common).queue_msix_vector) };
    if readback != vector {
        serial::write(format_args!(
            "virtio: queue {} MSI-X vector rejected ({:#x})\n",
            queue, readback
        ));
        return None;
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

fn setup_queue_modern_no_msix(
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
        serial::write(format_args!("virtio-blk: queue {} not available\n", queue));
        return None;
    }
    let qsize = max.min(128);
    if qsize < 3 {
        serial::write(format_args!("virtio-blk: queue {} too small\n", queue));
        return None;
    }
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
        "virtio-blk: q{} size {} notify_off {} addr={:#x}\n",
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

struct QueueMem {
    _size: usize,
    queue: VirtQueue,
}

struct VirtioNet {
    rx: VirtQueue,
    tx: VirtQueue,
    tx_state: TxState,
    mac: [u8; 6],
}

#[repr(C)]
struct VirtioBlkReq {
    type_: u32,
    reserved: u32,
    sector: u64,
}

struct VirtioBlk {
    queue: VirtQueue,
    capacity: u64,
    size_max: u32,
    req_phys: u64,
    req_virt: *mut VirtioBlkReq,
    status_phys: u64,
    status_virt: *mut u8,
}

struct BlkState {
    inner: UnsafeCell<Option<VirtioBlk>>,
}

unsafe impl Sync for BlkState {}

static BLK: BlkState = BlkState {
    inner: UnsafeCell::new(None),
};

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

fn set_blk(blk: VirtioBlk) {
    unsafe {
        *BLK.inner.get() = Some(blk);
    }
}

fn with_blk<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut VirtioBlk) -> R,
{
    unsafe {
        let slot = &mut *BLK.inner.get();
        let blk = slot.as_mut()?;
        Some(f(blk))
    }
}

pub fn blk_capacity_sectors() -> Option<u64> {
    with_blk(|blk| blk.capacity)
}

pub fn init_blk(dev: &VirtioPciDevice) -> bool {
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
        serial::write(format_args!("virtio-blk: notify multiplier is zero\n"));
        return false;
    }

    let common_ptr = mmio_ptr(common_addr);
    let notify_base_ptr = mmio_ptr(notify_base);
    let device_cfg_ptr = mmio_ptr(device_cfg);
    let common = common_ptr as *mut VirtioPciCommonCfg;

    unsafe {
        write_volatile(&mut (*common).device_status, 0);
        write_volatile(&mut (*common).device_status, STATUS_ACKNOWLEDGE);
        write_volatile(&mut (*common).device_status, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        write_volatile(&mut (*common).msix_config, 0xFFFF);
    }

    let device_features = read_device_features(common);
    if (device_features & VIRTIO_F_VERSION_1) == 0 {
        serial::write(format_args!("virtio-blk: missing VERSION_1\n"));
        write_status(common, STATUS_FAILED);
        return false;
    }
    write_driver_features(common, VIRTIO_F_VERSION_1);
    write_status(common, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if (read_status(common) & STATUS_FEATURES_OK) == 0 {
        serial::write(format_args!("virtio-blk: FEATURES_OK not accepted\n"));
        write_status(common, STATUS_FAILED);
        return false;
    }

    let mut queue = match setup_queue_modern_no_msix(common, notify_base_ptr, notify_mult, QUEUE_NUM_BLK) {
        Some(q) => q,
        None => {
            write_status(common, STATUS_FAILED);
            return false;
        }
    };

    let cfg_ptr = device_cfg_ptr as *const u8;
    let capacity = unsafe { read_volatile(cfg_ptr as *const u64) };
    let size_max = unsafe { read_volatile(cfg_ptr.add(8) as *const u32) };
    let req_buf = match memory::alloc_dma_pages(1) {
        Some(buf) => buf,
        None => {
            write_status(common, STATUS_FAILED);
            return false;
        }
    };
    let req_phys = req_buf.phys;
    let req_virt = memory::phys_to_virt(req_phys) as *mut VirtioBlkReq;
    let status_phys = req_phys + core::mem::size_of::<VirtioBlkReq>() as u64;
    let status_virt = memory::phys_to_virt(status_phys) as *mut u8;

    queue.queue_index = QUEUE_NUM_BLK;
    write_status(
        common,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    );
    serial::write(format_args!(
        "virtio-blk modern init complete capacity={} sectors size_max={}\n",
        capacity, size_max
    ));
    set_blk(VirtioBlk {
        queue,
        capacity,
        size_max,
        req_phys,
        req_virt,
        status_phys,
        status_virt,
    });
    true
}

pub fn blk_read(lba: u64, buf: &mut [u8]) -> bool {
    blk_rw_read(lba, buf)
}

pub fn blk_write(lba: u64, buf: &[u8]) -> bool {
    blk_rw_write(lba, buf)
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
            notify: Notify::Mmio(0),
            avail_idx: 0,
            last_used: 0,
        },
    })
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn prime_rx_buffers(rxq: &mut VirtQueue, count: usize) -> bool {
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
    notify_queue(rxq);
    true
}

pub fn send_frame(frame: &[u8]) -> bool {
    match with_net(|net| send_frame_queue(&mut net.tx, &mut net.tx_state, frame)) {
        Some(ok) => ok,
        None => false,
    }
}

pub fn reclaim_tx() {
    let _ = with_net(|net| reclaim_tx_queue(&mut net.tx, &mut net.tx_state));
}

fn send_frame_queue(txq: &mut VirtQueue, tx_state: &mut TxState, frame: &[u8]) -> bool {
    reclaim_tx_queue(txq, tx_state);
    if frame.len() + VIRTIO_NET_HDR_LEN > 4096 {
        NET_STATS.tx_overflow.fetch_add(1, Ordering::Relaxed);
        NET_STATS.tx_drops.fetch_add(1, Ordering::Relaxed);
        serial::write(format_args!(
            "virtio: tx frame too large ({})\n",
            frame.len()
        ));
        return false;
    }
    let head = match tx_state.free.pop() {
        Some(head) => head,
        None => {
            NET_STATS.tx_drops.fetch_add(1, Ordering::Relaxed);
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
        core::ptr::copy_nonoverlapping(frame.as_ptr(), virt.add(VIRTIO_NET_HDR_LEN), frame.len());
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
    notify_queue(txq);
    NET_STATS.tx_packets.fetch_add(1, Ordering::Relaxed);
    NET_STATS
        .tx_bytes
        .fetch_add(frame.len() as u64, Ordering::Relaxed);
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
    let Notify::Mmio(addr) = queue.notify;
    unsafe {
        write_volatile(addr as *mut u32, queue.queue_index as u32);
    }
}

fn used_idx(queue: &VirtQueue) -> u16 {
    unsafe { read_volatile(&(*queue.used).idx) }
}

pub fn recv_frame_into(buf: &mut [u8]) -> Option<usize> {
    with_net(|net| recv_frame_into_queue(&mut net.rx, buf))?
}

fn recv_frame_into_queue(rxq: &mut VirtQueue, buf: &mut [u8]) -> Option<usize> {
    let used = used_idx(rxq);
    if rxq.last_used == used {
        return None;
    }

    let idx = rxq.last_used % rxq.size;
    let elem = unsafe { read_volatile(used_ring(rxq).add(idx as usize)) };
    let head = elem.id as u16;
    let total_len = elem.len as usize;

    if total_len < VIRTIO_NET_HDR_LEN {
        NET_STATS.rx_drops.fetch_add(1, Ordering::Relaxed);
        rxq.last_used = rxq.last_used.wrapping_add(1);
        push_avail(rxq, head);
        notify_queue(rxq);
        return None;
    }

    let desc1 = unsafe { read_volatile(rxq.desc.add((head + 1) as usize)) };
    let payload_len = total_len.saturating_sub(VIRTIO_NET_HDR_LEN);
    let max_copy = cmp::min(desc1.len as usize, buf.len());
    if payload_len > max_copy {
        NET_STATS.rx_overflow.fetch_add(1, Ordering::Relaxed);
        NET_STATS.rx_drops.fetch_add(1, Ordering::Relaxed);
        rxq.last_used = rxq.last_used.wrapping_add(1);
        push_avail(rxq, head);
        notify_queue(rxq);
        return None;
    }
    let copy_len = payload_len;
    let src = memory::phys_to_virt(desc1.addr);
    unsafe {
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), copy_len);
    }

    push_avail(rxq, head);
    notify_queue(rxq);
    rxq.last_used = rxq.last_used.wrapping_add(1);
    NET_STATS.rx_packets.fetch_add(1, Ordering::Relaxed);
    NET_STATS
        .rx_bytes
        .fetch_add(copy_len as u64, Ordering::Relaxed);
    if RX_LOG.fetch_add(1, Ordering::Relaxed) < 8 {
        serial::write(format_args!(
            "virtio: rx len={} head={}\n",
            copy_len, head
        ));
        if copy_len >= 14 {
            let eth_type = ((buf[12] as u16) << 8) | (buf[13] as u16);
            if eth_type == 0x0806 && copy_len >= 42 {
                let op = ((buf[20] as u16) << 8) | (buf[21] as u16);
                let tip = [buf[38], buf[39], buf[40], buf[41]];
                serial::write(format_args!(
                    "virtio: rx arp op={} tip={}.{}.{}.{}\n",
                    op, tip[0], tip[1], tip[2], tip[3]
                ));
            } else {
                serial::write(format_args!("virtio: rx eth=0x{:04x}\n", eth_type));
            }
        }
    }
    Some(copy_len)
}

fn setup_msix(dev: &VirtioPciDevice) -> bool {
    let table_phys = match dev.msix_table {
        Some(addr) => addr,
        None => return false,
    };
    if dev.msix_table_size < 2 {
        return false;
    }
    let table_ptr = mmio_ptr(table_phys) as *mut MsixTableEntry;
    let apic_id = 0u64;
    let msi_addr = 0xFEE0_0000u64 | (apic_id << 12);

    let rx_data = (interrupts::NET_RX_VECTOR as u32) & 0xFF;
    let tx_data = (interrupts::NET_TX_VECTOR as u32) & 0xFF;
    unsafe {
        let entry = table_ptr.add(RX_MSIX_VECTOR as usize);
        write_volatile(&mut (*entry).addr_low, (msi_addr & 0xFFFF_FFFF) as u32);
        write_volatile(&mut (*entry).addr_high, (msi_addr >> 32) as u32);
        write_volatile(&mut (*entry).data, rx_data);
        write_volatile(&mut (*entry).ctrl, 0);

        let entry = table_ptr.add(TX_MSIX_VECTOR as usize);
        write_volatile(&mut (*entry).addr_low, (msi_addr & 0xFFFF_FFFF) as u32);
        write_volatile(&mut (*entry).addr_high, (msi_addr >> 32) as u32);
        write_volatile(&mut (*entry).data, tx_data);
        write_volatile(&mut (*entry).ctrl, 0);
    }
    true
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

fn blk_rw_read(lba: u64, buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    if buf.len() % 512 != 0 {
        return false;
    }
    let max_bytes = with_blk(|blk| blk.size_max).unwrap_or(0);
    let mut max_blocks = 32usize;
    if max_bytes != 0 {
        max_blocks = max_blocks.min((max_bytes as usize) / 512).max(1);
    }
    let mut offset = 0usize;
    let mut sector = lba;
    while offset < buf.len() {
        let remaining = buf.len() - offset;
        let blocks = (remaining / 512).min(max_blocks).max(1);
        let bytes = blocks * 512;
        let slice = &mut buf[offset..offset + bytes];
        let ok = with_blk(|blk| blk_submit_read(blk, sector, slice)).unwrap_or(false);
        if !ok {
            return false;
        }
        offset += bytes;
        sector += blocks as u64;
    }
    true
}

fn blk_rw_write(lba: u64, buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    if buf.len() % 512 != 0 {
        return false;
    }
    let max_bytes = with_blk(|blk| blk.size_max).unwrap_or(0);
    let mut max_blocks = 32usize;
    if max_bytes != 0 {
        max_blocks = max_blocks.min((max_bytes as usize) / 512).max(1);
    }
    let mut offset = 0usize;
    let mut sector = lba;
    while offset < buf.len() {
        let remaining = buf.len() - offset;
        let blocks = (remaining / 512).min(max_blocks).max(1);
        let bytes = blocks * 512;
        let slice = &buf[offset..offset + bytes];
        let ok = with_blk(|blk| blk_submit_write(blk, sector, slice)).unwrap_or(false);
        if !ok {
            return false;
        }
        offset += bytes;
        sector += blocks as u64;
    }
    true
}

fn blk_submit_read(blk: &mut VirtioBlk, sector: u64, buf: &mut [u8]) -> bool {
    let bytes = buf.len();
    if bytes == 0 {
        return true;
    }
    let pages = (bytes + 4095) / 4096;
    let dma = match memory::alloc_dma_pages(pages) {
        Some(buf) => buf,
        None => return false,
    };
    let data_phys = dma.phys;
    let data_virt = memory::phys_to_virt(data_phys);
    unsafe {
        write_bytes(data_virt, 0, bytes);
        // read: leave buffer zeroed
    }

    unsafe {
        (*blk.req_virt).type_ = VIRTIO_BLK_T_IN;
        (*blk.req_virt).reserved = 0;
        (*blk.req_virt).sector = sector;
        write_volatile(blk.status_virt, 0xFF);
    }

    let desc0 = VirtqDesc {
        addr: blk.req_phys,
        len: core::mem::size_of::<VirtioBlkReq>() as u32,
        flags: VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = VirtqDesc {
        addr: data_phys,
        len: bytes as u32,
        flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
        next: 2,
    };
    let desc2 = VirtqDesc {
        addr: blk.status_phys,
        len: 1,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    unsafe {
        write_volatile(blk.queue.desc.add(0), desc0);
        write_volatile(blk.queue.desc.add(1), desc1);
        write_volatile(blk.queue.desc.add(2), desc2);
    }

    fence(Ordering::SeqCst);
    push_avail(&mut blk.queue, 0);
    fence(Ordering::SeqCst);
    notify_queue(&blk.queue);

    let mut spins = 0u64;
    while used_idx(&blk.queue) == blk.queue.last_used {
        spins = spins.wrapping_add(1);
        if spins == 100_000_000 {
            serial::write(format_args!(
                "virtio-blk: read timeout lba={} avail={} used={}\n",
                sector,
                blk.queue.avail_idx,
                used_idx(&blk.queue)
            ));
            memory::free_contiguous(data_phys, pages);
            return false;
        }
        core::hint::spin_loop();
    }
    let idx = blk.queue.last_used % blk.queue.size;
    let _elem = unsafe { read_volatile(used_ring(&blk.queue).add(idx as usize)) };
    blk.queue.last_used = blk.queue.last_used.wrapping_add(1);

    let status = unsafe { read_volatile(blk.status_virt) };
    unsafe {
        core::ptr::copy_nonoverlapping(data_virt, buf.as_mut_ptr(), bytes);
    }
    memory::free_contiguous(data_phys, pages);
    status == VIRTIO_BLK_STATUS_OK
}

fn blk_submit_write(blk: &mut VirtioBlk, sector: u64, buf: &[u8]) -> bool {
    let bytes = buf.len();
    if bytes == 0 {
        return true;
    }
    let pages = (bytes + 4095) / 4096;
    let dma = match memory::alloc_dma_pages(pages) {
        Some(buf) => buf,
        None => return false,
    };
    let data_phys = dma.phys;
    let data_virt = memory::phys_to_virt(data_phys);
    unsafe {
        write_bytes(data_virt, 0, bytes);
        core::ptr::copy_nonoverlapping(buf.as_ptr(), data_virt, bytes);
    }

    unsafe {
        (*blk.req_virt).type_ = VIRTIO_BLK_T_OUT;
        (*blk.req_virt).reserved = 0;
        (*blk.req_virt).sector = sector;
        write_volatile(blk.status_virt, 0xFF);
    }

    let desc0 = VirtqDesc {
        addr: blk.req_phys,
        len: core::mem::size_of::<VirtioBlkReq>() as u32,
        flags: VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = VirtqDesc {
        addr: data_phys,
        len: bytes as u32,
        flags: VIRTQ_DESC_F_NEXT,
        next: 2,
    };
    let desc2 = VirtqDesc {
        addr: blk.status_phys,
        len: 1,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    unsafe {
        write_volatile(blk.queue.desc.add(0), desc0);
        write_volatile(blk.queue.desc.add(1), desc1);
        write_volatile(blk.queue.desc.add(2), desc2);
    }

    fence(Ordering::SeqCst);
    push_avail(&mut blk.queue, 0);
    fence(Ordering::SeqCst);
    notify_queue(&blk.queue);

    let mut spins = 0u64;
    while used_idx(&blk.queue) == blk.queue.last_used {
        spins = spins.wrapping_add(1);
        if spins == 100_000_000 {
            serial::write(format_args!(
                "virtio-blk: write timeout lba={} avail={} used={} status={}\n",
                sector,
                blk.queue.avail_idx,
                used_idx(&blk.queue),
                unsafe { read_volatile(blk.status_virt) }
            ));
            memory::free_contiguous(data_phys, pages);
            return false;
        }
        core::hint::spin_loop();
    }
    let idx = blk.queue.last_used % blk.queue.size;
    let _elem = unsafe { read_volatile(used_ring(&blk.queue).add(idx as usize)) };
    blk.queue.last_used = blk.queue.last_used.wrapping_add(1);

    let status = unsafe { read_volatile(blk.status_virt) };
    memory::free_contiguous(data_phys, pages);
    status == VIRTIO_BLK_STATUS_OK
}
