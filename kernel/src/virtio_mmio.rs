use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{fence, Ordering};

use crate::memory;
use crate::serial;

const VIRTIO_MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
const VIRTIO_MMIO_VERSION_MODERN: u32 = 2;
const VIRTIO_MMIO_DEVICE_ID_BLOCK: u32 = 2;
const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
const VIRTIO_MMIO_STRIDE: u64 = 0x200;
const VIRTIO_MMIO_SLOTS: usize = 32;

const REG_MAGIC_VALUE: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_VENDOR_ID: u64 = 0x00c;
const REG_DEVICE_FEATURES: u64 = 0x010;
const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
const REG_DRIVER_FEATURES: u64 = 0x020;
const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_READY: u64 = 0x044;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_INTERRUPT_ACK: u64 = 0x064;
const REG_STATUS: u64 = 0x070;
const REG_QUEUE_DESC_LOW: u64 = 0x080;
const REG_QUEUE_AVAIL_LOW: u64 = 0x090;
const REG_QUEUE_USED_LOW: u64 = 0x0a0;
const REG_CONFIG_GENERATION: u64 = 0x0fc;
const REG_CONFIG_SPACE: u64 = 0x100;

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_STATUS_OK: u8 = 0;
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 0x80;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTQ_ALIGN: usize = 4096;
const QUEUE_NUM_BLK: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
struct VirtioBlkReq {
    type_: u32,
    reserved: u32,
    sector: u64,
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
    notify_addr: u64,
    avail_idx: u16,
    last_used: u16,
}

struct QueueMem {
    _size: usize,
    queue: VirtQueue,
}

struct VirtioBlk {
    base: u64,
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

pub fn scan_blk_devices(out: &mut [u64]) -> usize {
    let mut found = 0usize;
    for slot in 0..VIRTIO_MMIO_SLOTS {
        let base = VIRTIO_MMIO_BASE + (slot as u64) * VIRTIO_MMIO_STRIDE;
        let magic = read_reg(base, REG_MAGIC_VALUE);
        let version = read_reg(base, REG_VERSION);
        let device_id = read_reg(base, REG_DEVICE_ID);
        if magic != VIRTIO_MMIO_MAGIC_VALUE {
            continue;
        }
        if version != VIRTIO_MMIO_VERSION_MODERN || device_id != VIRTIO_MMIO_DEVICE_ID_BLOCK {
            continue;
        }
        let vendor = read_reg(base, REG_VENDOR_ID);
        serial::write(format_args!(
            "virtio-mmio: blk slot={} base={:#x} vendor={:#x}\n",
            slot, base, vendor
        ));
        if found < out.len() {
            out[found] = base;
        }
        found += 1;
    }
    found.min(out.len())
}

pub fn init_blk(base: u64) -> bool {
    write_reg(base, REG_STATUS, 0);
    write_reg(base, REG_STATUS, STATUS_ACKNOWLEDGE as u32);
    write_reg(base, REG_STATUS, (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u32);

    let device_features = read_device_features(base);
    if (device_features & VIRTIO_F_VERSION_1) == 0 {
        serial::write(format_args!(
            "virtio-mmio: blk {:#x} missing VERSION_1\n",
            base
        ));
        write_reg(base, REG_STATUS, STATUS_FAILED as u32);
        return false;
    }
    write_driver_features(base, VIRTIO_F_VERSION_1);
    write_reg(
        base,
        REG_STATUS,
        (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK) as u32,
    );
    if (read_reg(base, REG_STATUS) & STATUS_FEATURES_OK as u32) == 0 {
        serial::write(format_args!(
            "virtio-mmio: blk {:#x} FEATURES_OK rejected\n",
            base
        ));
        write_reg(base, REG_STATUS, STATUS_FAILED as u32);
        return false;
    }

    let mut queue = match setup_queue(base, QUEUE_NUM_BLK) {
        Some(q) => q,
        None => {
            write_reg(base, REG_STATUS, STATUS_FAILED as u32);
            return false;
        }
    };

    let capacity = read_config_u64(base, 0);
    let size_max = read_config_u32(base, 8);
    let req_phys = match memory::alloc_contiguous(1) {
        Some(phys) => phys,
        None => {
            write_reg(base, REG_STATUS, STATUS_FAILED as u32);
            return false;
        }
    };
    let req_virt = memory::phys_to_virt(req_phys) as *mut VirtioBlkReq;
    let status_phys = req_phys + core::mem::size_of::<VirtioBlkReq>() as u64;
    let status_virt = memory::phys_to_virt(status_phys) as *mut u8;
    unsafe {
        write_bytes(memory::phys_to_virt(req_phys), 0, memory::PAGE_SIZE as usize);
    }

    queue.queue_index = QUEUE_NUM_BLK as u16;
    write_reg(
        base,
        REG_STATUS,
        (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK) as u32,
    );
    serial::write(format_args!(
        "virtio-mmio: blk init base={:#x} capacity={} sectors size_max={}\n",
        base, capacity, size_max
    ));
    unsafe {
        *BLK.inner.get() = Some(VirtioBlk {
            base,
            queue,
            capacity,
            size_max,
            req_phys,
            req_virt,
            status_phys,
            status_virt,
        });
    }
    true
}

pub fn blk_capacity_sectors() -> Option<u64> {
    with_blk(|blk| blk.capacity)
}

pub fn blk_read(lba: u64, buf: &mut [u8]) -> bool {
    blk_rw_read(lba, buf)
}

pub fn blk_write(lba: u64, buf: &[u8]) -> bool {
    blk_rw_write(lba, buf)
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

fn setup_queue(base: u64, queue_num: u32) -> Option<VirtQueue> {
    write_reg(base, REG_QUEUE_SEL, queue_num);
    let max = read_reg(base, REG_QUEUE_NUM_MAX) as u16;
    if max < 3 {
        serial::write(format_args!(
            "virtio-mmio: blk queue {} unavailable size={}\n",
            queue_num, max
        ));
        return None;
    }
    let qsize = max.min(128);
    write_reg(base, REG_QUEUE_NUM, qsize as u32);
    let mem = allocate_queue(qsize)?;
    write_reg64(base, REG_QUEUE_DESC_LOW, mem.queue.desc_phys);
    write_reg64(base, REG_QUEUE_AVAIL_LOW, mem.queue.avail_phys);
    write_reg64(base, REG_QUEUE_USED_LOW, mem.queue.used_phys);
    write_reg(base, REG_QUEUE_READY, 1);
    Some(VirtQueue {
        notify_addr: base + REG_QUEUE_NOTIFY,
        ..mem.queue
    })
}

fn allocate_queue(qsize: u16) -> Option<QueueMem> {
    let desc_size = core::mem::size_of::<VirtqDesc>() * (qsize as usize);
    let avail_size = 6 + 2 * (qsize as usize);
    let used_size = 6 + 8 * (qsize as usize);
    let used_offset = align_up(desc_size + avail_size, VIRTQ_ALIGN);
    let total = used_offset + used_size;
    let pages = (total + 4095) / 4096;
    let phys = memory::alloc_contiguous(pages)?;
    unsafe {
        write_bytes(memory::phys_to_virt(phys), 0, pages * 4096);
    }
    let desc = memory::phys_to_virt(phys) as *mut VirtqDesc;
    let avail = unsafe { (memory::phys_to_virt(phys) as *mut u8).add(desc_size) } as *mut VirtqAvail;
    let used = unsafe { (memory::phys_to_virt(phys) as *mut u8).add(used_offset) } as *mut VirtqUsed;
    Some(QueueMem {
        _size: total,
        queue: VirtQueue {
            size: qsize,
            desc,
            avail,
            used,
            desc_phys: phys,
            avail_phys: phys + desc_size as u64,
            used_phys: phys + used_offset as u64,
            queue_index: 0,
            notify_addr: 0,
            avail_idx: 0,
            last_used: 0,
        },
    })
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
    let data_phys = match memory::alloc_contiguous(pages) {
        Some(phys) => phys,
        None => return false,
    };
    let data_virt = memory::phys_to_virt(data_phys);
    unsafe {
        write_bytes(data_virt, 0, pages * 4096);
        (*blk.req_virt).type_ = VIRTIO_BLK_T_IN;
        (*blk.req_virt).reserved = 0;
        (*blk.req_virt).sector = sector;
        write_volatile(blk.status_virt, 0xff);
    }

    submit_request(blk, data_phys, bytes as u32, true);
    let ok = wait_for_completion(blk, sector, true);
    if ok {
        unsafe {
            core::ptr::copy_nonoverlapping(data_virt, buf.as_mut_ptr(), bytes);
        }
    }
    memory::free_contiguous(data_phys, pages);
    ok
}

fn blk_submit_write(blk: &mut VirtioBlk, sector: u64, buf: &[u8]) -> bool {
    let bytes = buf.len();
    if bytes == 0 {
        return true;
    }
    let pages = (bytes + 4095) / 4096;
    let data_phys = match memory::alloc_contiguous(pages) {
        Some(phys) => phys,
        None => return false,
    };
    let data_virt = memory::phys_to_virt(data_phys);
    unsafe {
        write_bytes(data_virt, 0, pages * 4096);
        core::ptr::copy_nonoverlapping(buf.as_ptr(), data_virt, bytes);
        (*blk.req_virt).type_ = VIRTIO_BLK_T_OUT;
        (*blk.req_virt).reserved = 0;
        (*blk.req_virt).sector = sector;
        write_volatile(blk.status_virt, 0xff);
    }

    submit_request(blk, data_phys, bytes as u32, false);
    let ok = wait_for_completion(blk, sector, false);
    memory::free_contiguous(data_phys, pages);
    ok
}

fn submit_request(blk: &mut VirtioBlk, data_phys: u64, data_len: u32, is_read: bool) {
    let desc0 = VirtqDesc {
        addr: blk.req_phys,
        len: core::mem::size_of::<VirtioBlkReq>() as u32,
        flags: VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = VirtqDesc {
        addr: data_phys,
        len: data_len,
        flags: if is_read {
            VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT
        } else {
            VIRTQ_DESC_F_NEXT
        },
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
}

fn wait_for_completion(blk: &mut VirtioBlk, sector: u64, is_read: bool) -> bool {
    let mut spins = 0u64;
    while used_idx(&blk.queue) == blk.queue.last_used {
        spins = spins.wrapping_add(1);
        if spins == 100_000_000 {
            serial::write(format_args!(
                "virtio-mmio: {} timeout base={:#x} lba={} avail={} used={}\n",
                if is_read { "read" } else { "write" },
                blk.base,
                sector,
                blk.queue.avail_idx,
                used_idx(&blk.queue)
            ));
            return false;
        }
        core::hint::spin_loop();
    }
    let idx = blk.queue.last_used % blk.queue.size;
    let _elem = unsafe { read_volatile(used_ring(&blk.queue).add(idx as usize)) };
    blk.queue.last_used = blk.queue.last_used.wrapping_add(1);
    write_reg(blk.base, REG_INTERRUPT_ACK, 0xffff_ffff);
    unsafe { read_volatile(blk.status_virt) == VIRTIO_BLK_STATUS_OK }
}

fn push_avail(queue: &mut VirtQueue, head: u16) {
    let idx = queue.avail_idx % queue.size;
    unsafe {
        write_volatile(avail_ring(queue).add(idx as usize), head);
        fence(Ordering::SeqCst);
        queue.avail_idx = queue.avail_idx.wrapping_add(1);
        write_volatile(&mut (*queue.avail).idx, queue.avail_idx);
    }
}

fn notify_queue(queue: &VirtQueue) {
    unsafe {
        write_volatile(queue.notify_addr as *mut u32, queue.queue_index as u32);
    }
}

fn used_idx(queue: &VirtQueue) -> u16 {
    unsafe { read_volatile(&(*queue.used).idx) }
}

fn avail_ring(queue: &VirtQueue) -> *mut u16 {
    unsafe { (queue.avail as *mut u8).add(4) as *mut u16 }
}

fn used_ring(queue: &VirtQueue) -> *mut VirtqUsedElem {
    unsafe { (queue.used as *mut u8).add(4) as *mut VirtqUsedElem }
}

fn read_device_features(base: u64) -> u64 {
    write_reg(base, REG_DEVICE_FEATURES_SEL, 0);
    let lo = read_reg(base, REG_DEVICE_FEATURES) as u64;
    write_reg(base, REG_DEVICE_FEATURES_SEL, 1);
    let hi = read_reg(base, REG_DEVICE_FEATURES) as u64;
    (hi << 32) | lo
}

fn write_driver_features(base: u64, features: u64) {
    write_reg(base, REG_DRIVER_FEATURES_SEL, 0);
    write_reg(base, REG_DRIVER_FEATURES, features as u32);
    write_reg(base, REG_DRIVER_FEATURES_SEL, 1);
    write_reg(base, REG_DRIVER_FEATURES, (features >> 32) as u32);
}

fn read_config_u32(base: u64, offset: u64) -> u32 {
    read_reg(base, REG_CONFIG_SPACE + offset)
}

fn read_config_u64(base: u64, offset: u64) -> u64 {
    let before = read_reg(base, REG_CONFIG_GENERATION);
    let lo = read_config_u32(base, offset) as u64;
    let hi = read_config_u32(base, offset + 4) as u64;
    let after = read_reg(base, REG_CONFIG_GENERATION);
    if before != after {
        let lo = read_config_u32(base, offset) as u64;
        let hi = read_config_u32(base, offset + 4) as u64;
        return (hi << 32) | lo;
    }
    (hi << 32) | lo
}

fn read_reg(base: u64, offset: u64) -> u32 {
    unsafe { read_volatile((base + offset) as *const u32) }
}

fn write_reg(base: u64, offset: u64, value: u32) {
    unsafe {
        write_volatile((base + offset) as *mut u32, value);
    }
}

fn write_reg64(base: u64, low_offset: u64, value: u64) {
    write_reg(base, low_offset, value as u32);
    write_reg(base, low_offset + 4, (value >> 32) as u32);
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}
