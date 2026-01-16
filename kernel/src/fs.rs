use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::size_of;
use core::str;

use hadris_fat::structures::boot_sector::{BootSectorInfo, BootSectorInfoFat32};
use hadris_fat::structures::directory::{Directory, FileAttributes, FileEntry};
use hadris_fat::structures::fat::{self, Fat32};
use hadris_fat::structures::fs_info::FsInfo;
use hadris_fat::structures::raw::boot_sector::RawBootSector;
use hadris_fat::structures::raw::directory::RawDirectoryEntry;
use hadris_fat::structures::time::{FatTime, FatTimeHighP};
use hadris_fat::structures::FatStr;

use crate::interrupts;
use crate::pci;
use crate::serial;
use crate::time;
use crate::virtio;

const BLOCK_SIZE: usize = 512;
const DIR_ENTRY_SIZE: usize = size_of::<RawDirectoryEntry>();
const MAX_HANDLES: usize = 64;

pub const O_READ: u32 = 1;
pub const O_WRITE: u32 = 2;
pub const O_CREATE: u32 = 4;
pub const O_TRUNC: u32 = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dirent {
    pub name_len: u8,
    pub attr: u8,
    pub _pad: [u8; 2],
    pub size: u32,
    pub name: [u8; 12],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    File,
    Dir,
}

#[derive(Clone, Copy)]
struct Handle {
    kind: HandleKind,
    cluster: u32,
    size: u32,
    pos: u32,
    entry_cluster: u32,
    entry_index: usize,
    flags: u32,
    dir_cluster: u32,
    dir_index: usize,
}

enum FsDevice {
    RamDisk,
    VirtioBlk { sectors: u64 },
}

struct FsState {
    storage: Vec<u8>,
    offset: usize,
    size: usize,
    bs: BootSectorInfoFat32,
    device: FsDevice,
    handles: [Option<Handle>; MAX_HANDLES],
    dirty: Option<DirtyRange>,
}

#[derive(Clone, Copy)]
struct DirtyRange {
    start: usize,
    end: usize,
}

struct FsStateCell(UnsafeCell<Option<FsState>>);

unsafe impl Sync for FsStateCell {}

static FS_STATE: FsStateCell = FsStateCell(UnsafeCell::new(None));

pub fn init() -> bool {
    let mounted = mount_virtio_blk().or_else(mount_ramdisk);
    if let Some(fs) = mounted {
        unsafe {
            *FS_STATE.0.get() = Some(fs);
        }
        serial::write(format_args!("fs: mounted\n"));
        true
    } else {
        serial::write(format_args!("fs: mount failed\n"));
        false
    }
}

pub fn open(path: &str, flags: u32) -> Option<u64> {
    with_fs(None, |fs| fs.open_file(path, flags))
}

pub fn opendir(path: &str) -> Option<u64> {
    with_fs(None, |fs| fs.open_dir(path))
}

pub fn read(handle: u64, buf: &mut [u8]) -> Option<usize> {
    with_fs(None, |fs| fs.read_file(handle, buf))
}

pub fn write(handle: u64, buf: &[u8]) -> Option<usize> {
    with_fs(None, |fs| fs.write_file(handle, buf))
}

pub fn close(handle: u64) -> bool {
    with_fs(false, |fs| fs.close_handle(handle))
}

pub fn mkdir(path: &str) -> bool {
    with_fs(false, |fs| fs.mkdir(path))
}

pub fn readdir(handle: u64, out: &mut Dirent) -> Option<bool> {
    with_fs(None, |fs| fs.read_dir(handle, out))
}

pub fn sync() -> bool {
    with_fs(false, |fs| fs.sync())
}

fn with_fs<F, R>(default: R, f: F) -> R
where
    F: FnOnce(&mut FsState) -> R,
{
    unsafe {
        let slot = &mut *FS_STATE.0.get();
        let fs = match slot.as_mut() {
            Some(fs) => fs,
            None => return default,
        };
        f(fs)
    }
}

fn mount_ramdisk() -> Option<FsState> {
    let image: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ramdisk.img"));
    let mut storage = Vec::with_capacity(image.len());
    storage.extend_from_slice(image);
    mount_from_storage(storage, FsDevice::RamDisk)
}

fn mount_virtio_blk() -> Option<FsState> {
    let dev = pci::find_virtio_blk()?;
    pci::enable_bus_master(&dev);
    if !virtio::init_blk(&dev) {
        return None;
    }
    let sectors = virtio::blk_capacity_sectors()?;
    if sectors == 0 {
        return None;
    }
    let total = sectors as usize * BLOCK_SIZE;
    let mut storage = Vec::with_capacity(total);
    storage.resize(total, 0);
    if !virtio::blk_read(0, &mut storage) {
        return None;
    }
    mount_from_storage(storage, FsDevice::VirtioBlk { sectors })
}

fn mount_from_storage(mut storage: Vec<u8>, device: FsDevice) -> Option<FsState> {
    let (offset, size) = find_fat32_partition(&storage).unwrap_or((0, storage.len()));
    if size < BLOCK_SIZE {
        return None;
    }
    let bs_bytes = &mut storage[offset..offset + BLOCK_SIZE];
    let raw = RawBootSector::from_bytes((&bs_bytes[..BLOCK_SIZE]).try_into().ok()?);
    let info = BootSectorInfo::try_from(raw).ok()?;
    let bs = match info {
        BootSectorInfo::Fat32(info) => info,
    };
    let fs_size = bs.total_sectors as usize * bs.bytes_per_sector as usize;
    if offset + fs_size > storage.len() {
        return None;
    }

    Some(FsState {
        storage,
        offset,
        size: fs_size,
        bs,
        device,
        handles: [None; MAX_HANDLES],
        dirty: None,
    })
}

fn find_fat32_partition(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 512 {
        return None;
    }
    if bytes[510] != 0x55 || bytes[511] != 0xAA {
        return None;
    }
    let table = 0x1BE;
    for idx in 0..4 {
        let off = table + idx * 16;
        let ptype = bytes[off + 4];
        if ptype == 0x0B || ptype == 0x0C {
            let lba = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().ok()?) as usize;
            let sectors =
                u32::from_le_bytes(bytes[off + 12..off + 16].try_into().ok()?) as usize;
            return Some((lba * BLOCK_SIZE, sectors * BLOCK_SIZE));
        }
    }
    None
}

impl FsState {
    fn bytes_per_sector(&self) -> usize {
        self.bs.bytes_per_sector as usize
    }

    fn cluster_size(&self) -> usize {
        self.bytes_per_sector() * self.bs.sectors_per_cluster as usize
    }

    fn reserved_len(&self) -> usize {
        self.bs.reserved_sector_count as usize * self.bytes_per_sector()
    }

    fn fat_len(&self) -> usize {
        self.bs.fat_count as usize * self.bs.sectors_per_fat as usize * self.bytes_per_sector()
    }

    fn fs_slice_mut(&mut self) -> &mut [u8] {
        let start = self.offset;
        let end = self.offset + self.size;
        &mut self.storage[start..end]
    }

    fn fs_slice(&self) -> &[u8] {
        let start = self.offset;
        let end = self.offset + self.size;
        &self.storage[start..end]
    }

    fn split_mut(&mut self) -> (&mut [u8], &mut [u8], &mut [u8]) {
        let reserved_len = self.reserved_len();
        let fat_len = self.fat_len();
        let fs = self.fs_slice_mut();
        let (reserved, rest) = fs.split_at_mut(reserved_len);
        let (fat, data) = rest.split_at_mut(fat_len);
        (reserved, fat, data)
    }

    fn split(&self) -> (&[u8], &[u8], &[u8]) {
        let reserved_len = self.reserved_len();
        let fat_len = self.fat_len();
        let fs = self.fs_slice();
        let (reserved, rest) = fs.split_at(reserved_len);
        let (fat, data) = rest.split_at(fat_len);
        (reserved, fat, data)
    }

    fn fs_info_range(&self) -> core::ops::Range<usize> {
        let start = self.bs.fs_info_sector as usize * self.bytes_per_sector();
        start..start + self.bytes_per_sector()
    }

    fn mark_dirty(&mut self, start: usize, len: usize) {
        if len == 0 {
            return;
        }
        let end = start.saturating_add(len);
        let range = DirtyRange { start, end };
        self.dirty = Some(match self.dirty {
            Some(existing) => DirtyRange {
                start: existing.start.min(range.start),
                end: existing.end.max(range.end),
            },
            None => range,
        });
    }

    fn mark_dirty_fat(&mut self) {
        let start = self.offset;
        let len = self.reserved_len() + self.fat_len();
        self.mark_dirty(start, len);
    }

    fn mark_cluster_range(&mut self, cluster: u32, offset: usize, len: usize) {
        if cluster < 2 || len == 0 {
            return;
        }
        let cluster_size = self.cluster_size();
        if offset >= cluster_size {
            return;
        }
        let data_base = self.offset + self.reserved_len() + self.fat_len();
        let cluster_off = (cluster as usize - 2) * cluster_size;
        let start = data_base + cluster_off + offset;
        let max_len = cluster_size - offset;
        self.mark_dirty(start, len.min(max_len));
    }

    fn mark_data_range(&mut self, start_cluster: u32, start_offset: usize, len: usize) {
        if len == 0 || start_cluster < 2 {
            return;
        }
        let cluster_size = self.cluster_size();
        let data_base = self.offset + self.reserved_len() + self.fat_len();
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        {
            let (_, fat_bytes, _) = self.split();
            let fat = Fat32::from_bytes(fat_bytes);
            let mut cluster = start_cluster;
            let mut skip = start_offset;
            let mut remaining = len;

            while skip >= cluster_size {
                let next = fat.entries[cluster as usize] & 0x0FFF_FFFF;
                if next >= fat::constants::FAT32_CLUSTER_RESERVED {
                    return;
                }
                cluster = next;
                skip -= cluster_size;
            }

            while remaining > 0 {
                let in_cluster = cluster_size - skip;
                let chunk = remaining.min(in_cluster);
                let cluster_off = (cluster as usize - 2) * cluster_size;
                let start = data_base + cluster_off + skip;
                ranges.push((start, chunk));
                remaining -= chunk;
                skip = 0;
                if remaining == 0 {
                    break;
                }
                let next = fat.entries[cluster as usize] & 0x0FFF_FFFF;
                if next >= fat::constants::FAT32_CLUSTER_RESERVED {
                    break;
                }
                cluster = next;
            }
        }
        for (start, len) in ranges {
            self.mark_dirty(start, len);
        }
    }

    fn allocate_clusters(&mut self, count: u32) -> u32 {
        let range = self.fs_info_range();
        let (reserved, fat, _) = self.split_mut();
        let (mut free_count, mut next_free) = ensure_fs_info(range.clone(), reserved, fat);
        if free_count == 0 {
            return 0;
        }
        let cluster =
            Fat32::from_bytes_mut(fat).allocate_clusters(&mut free_count, &mut next_free, count);
        if let Some(info) = fs_info_mut_range(range, reserved) {
            info.next_free = next_free;
            info.free_count = free_count;
        }
        self.mark_dirty_fat();
        cluster
    }

    fn retain_cluster_chain(&mut self, cluster: u32, length: u32) {
        let range = self.fs_info_range();
        let (reserved, fat, _) = self.split_mut();
        let (mut free_count, mut next_free) = ensure_fs_info(range.clone(), reserved, fat);
        Fat32::from_bytes_mut(fat).retain_cluster_chain(
            cluster as usize,
            length,
            &mut free_count,
            &mut next_free,
        );
        if let Some(info) = fs_info_mut_range(range, reserved) {
            info.next_free = next_free;
            info.free_count = free_count;
        }
        self.mark_dirty_fat();
    }

    fn free_cluster_chain(&mut self, cluster: u32) {
        if cluster < 2 {
            return;
        }
        let range = self.fs_info_range();
        let (reserved, fat_bytes, _) = self.split_mut();
        let (free_count, next_free) = ensure_fs_info(range.clone(), reserved, fat_bytes);
        let mut fs_info = fs_info_mut_range(range.clone(), reserved).map(|info| {
            let mut info = *info;
            info.free_count = free_count;
            info.next_free = next_free;
            info
        });
        let fat = Fat32::from_bytes_mut(fat_bytes);
        let fat_len = fat.entries.len() as u32;
        if cluster < 2 || cluster >= fat_len || cluster >= fat::constants::FAT32_CLUSTER_RESERVED {
            return;
        }
        let mut current = cluster;
        loop {
            if current >= fat_len {
                break;
            }
            let entry = fat.entries[current as usize] & 0x0FFF_FFFF;
            fat.mark_cluster_as(current as usize, fat::constants::FAT32_CLUSTER_FREE);
            if let Some(ref mut info) = fs_info {
                info.free_count = info.free_count.saturating_add(1);
                if info.next_free == 0 || current < info.next_free {
                    info.next_free = current;
                }
            }
            if entry >= fat::constants::FAT32_CLUSTER_RESERVED {
                break;
            }
            current = entry;
        }
        if let (Some(info), Some(updated)) = (fs_info_mut_range(range, reserved), fs_info) {
            *info = updated;
        }
        self.mark_dirty_fat();
    }

    fn next_cluster(&self, fat: &Fat32, cluster: u32) -> Option<u32> {
        if cluster < 2 || cluster as usize >= fat.entries.len() {
            return None;
        }
        let next = fat.entries[cluster as usize] & 0x0FFF_FFFF;
        if next >= fat::constants::FAT32_CLUSTER_RESERVED {
            None
        } else {
            Some(next)
        }
    }

    fn find_entry(
        &self,
        dir_cluster: u32,
        name: &FatStr<8>,
        ext: &FatStr<3>,
    ) -> Option<(u32, usize, FileEntry)> {
        let cluster_size = self.cluster_size();
        let (_, fat_bytes, data) = self.split();
        let fat = Fat32::from_bytes(fat_bytes);
        let mut cluster = dir_cluster;
        loop {
            let offset = (cluster as usize - 2) * cluster_size;
            let dir = Directory::from_bytes(&data[offset..offset + cluster_size]);
            for (idx, entry) in dir.entries.iter().enumerate() {
                let base = entry.base_name().raw;
                if base[0] == 0x00 {
                    return None;
                }
                if base[0] == 0xE5 {
                    continue;
                }
                if entry.base_name() == *name && entry.extension() == *ext {
                    return Some((cluster, idx, *entry));
                }
            }
            cluster = match self.next_cluster(fat, cluster) {
                Some(next) => next,
                None => return None,
            };
        }
    }

    fn find_free_entry(&mut self, dir_cluster: u32) -> Option<(u32, usize)> {
        let cluster_size = self.cluster_size();
        let (_, fat_bytes, data) = self.split();
        let fat = Fat32::from_bytes(fat_bytes);
        let mut cluster = dir_cluster;
        let mut last = dir_cluster;
        loop {
            let offset = (cluster as usize - 2) * cluster_size;
            let dir = Directory::from_bytes(&data[offset..offset + cluster_size]);
            for (idx, entry) in dir.entries.iter().enumerate() {
                let base = entry.base_name().raw;
                if base[0] == 0x00 || base[0] == 0xE5 {
                    return Some((cluster, idx));
                }
            }
            match self.next_cluster(fat, cluster) {
                Some(next) => {
                    last = next;
                    cluster = next;
                }
                None => break,
            }
        }

        let new_cluster = self.allocate_clusters(1);
        if new_cluster < 2 {
            return None;
        }
        {
            let (_, fat_bytes, _) = self.split_mut();
            let fat = Fat32::from_bytes_mut(fat_bytes);
            fat.link_cluster(last as usize, new_cluster as usize);
            fat.mark_cluster_as(new_cluster as usize, fat::constants::FAT32_CLUSTER_LAST);
        }
        {
            let (_, _, data) = self.split_mut();
            let offset = (new_cluster as usize - 2) * cluster_size;
            for b in &mut data[offset..offset + cluster_size] {
                *b = 0;
            }
        }
        self.mark_cluster_range(new_cluster, 0, cluster_size);
        Some((new_cluster, 0))
    }

    fn update_entry(&mut self, cluster: u32, index: usize, entry: FileEntry) {
        let cluster_size = self.cluster_size();
        let (_, _, data) = self.split_mut();
        let offset = (cluster as usize - 2) * cluster_size;
        let dir = Directory::from_bytes_mut(&mut data[offset..offset + cluster_size]);
        if index < dir.entries.len() {
            dir.entries[index] = entry;
            self.mark_cluster_range(cluster, 0, cluster_size);
        }
    }

    fn open_file(&mut self, path: &str, flags: u32) -> Option<u64> {
        let (parent, name, ext) = self.resolve_parent(path)?;
        if let Some((cluster, index, entry)) = self.find_entry(parent, &name, &ext) {
            if entry
                .info()
                .attributes
                .contains(FileAttributes::DIRECTORY)
            {
                return None;
            }
            let mut entry = entry;
            if flags & O_TRUNC != 0 {
                let cl = entry.cluster();
                if cl >= 2 {
                    self.free_cluster_chain(cl);
                }
                entry.write_cluster(0);
                entry.write_size(0);
                self.update_entry(cluster, index, entry);
            }
            return self.alloc_handle(Handle {
                kind: HandleKind::File,
                cluster: entry.cluster(),
                size: entry.size(),
                pos: 0,
                entry_cluster: cluster,
                entry_index: index,
                flags,
                dir_cluster: 0,
                dir_index: 0,
            });
        }

        if flags & O_CREATE == 0 {
            return None;
        }
        let (time_hp, _) = fat_time_now();
        let entry = FileEntry::new(
            fat_name_to_str(&name),
            fat_ext_to_str(&ext),
            FileAttributes::ARCHIVE,
            0,
            0,
            time_hp,
        );
        let (cluster, index) = self.find_free_entry(parent)?;
        self.update_entry(cluster, index, entry);
        self.alloc_handle(Handle {
            kind: HandleKind::File,
            cluster: 0,
            size: 0,
            pos: 0,
            entry_cluster: cluster,
            entry_index: index,
            flags,
            dir_cluster: 0,
            dir_index: 0,
        })
    }

    fn open_dir(&mut self, path: &str) -> Option<u64> {
        let cluster = self.resolve_dir(path)?;
        self.alloc_handle(Handle {
            kind: HandleKind::Dir,
            cluster: 0,
            size: 0,
            pos: 0,
            entry_cluster: 0,
            entry_index: 0,
            flags: O_READ,
            dir_cluster: cluster,
            dir_index: 0,
        })
    }

    fn read_file(&mut self, handle: u64, buf: &mut [u8]) -> Option<usize> {
        let handle_idx = usize::try_from(handle).ok()?;
        let mut h = self.handles.get(handle_idx)?.clone()?;
        if h.kind != HandleKind::File {
            return None;
        }
        if h.cluster < 2 || h.pos >= h.size {
            return Some(0);
        }
        let remaining = (h.size - h.pos) as usize;
        let to_read = buf.len().min(remaining);
        let cluster_size = self.cluster_size();
        let (_, fat_bytes, data) = self.split();
        let fat = Fat32::from_bytes(fat_bytes);
        let read = fat.read_data(
            data,
            cluster_size,
            h.cluster,
            h.pos as usize,
            &mut buf[..to_read],
        );
        h.pos = h.pos.saturating_add(read as u32);
        self.handles[handle_idx] = Some(h);
        Some(read)
    }

    fn write_file(&mut self, handle: u64, buf: &[u8]) -> Option<usize> {
        let handle_idx = usize::try_from(handle).ok()?;
        let mut h = self.handles.get(handle_idx)?.clone()?;
        if h.kind != HandleKind::File {
            return None;
        }
        if h.flags & O_WRITE == 0 {
            return None;
        }
        if buf.is_empty() {
            return Some(0);
        }
        let cluster_size = self.cluster_size();
        let new_size = h.pos.saturating_add(buf.len() as u32);
        let needed_clusters =
            ((new_size as usize) + cluster_size - 1) / cluster_size;
        if h.cluster < 2 {
            if needed_clusters > 0 {
                h.cluster = self.allocate_clusters(needed_clusters as u32);
            }
        } else {
            self.retain_cluster_chain(h.cluster, needed_clusters as u32);
        }
        let (_, fat_bytes, data) = self.split_mut();
        let fat = Fat32::from_bytes_mut(fat_bytes);
        let written = fat.write_data(
            data,
            cluster_size,
            h.cluster,
            h.pos as usize,
            buf,
        );
        self.mark_data_range(h.cluster, h.pos as usize, written);
        h.pos = h.pos.saturating_add(written as u32);
        if h.pos > h.size {
            h.size = h.pos;
        }
        let mut entry = {
            let (_, _, data) = self.split();
            let offset = (h.entry_cluster as usize - 2) * cluster_size;
            let dir = Directory::from_bytes(&data[offset..offset + cluster_size]);
            dir.entries[h.entry_index]
        };
        entry.write_size(h.size);
        entry.write_cluster(h.cluster);
        let (_, time) = fat_time_now();
        entry.write_access_time(time);
        entry.write_modification_time(time);
        self.update_entry(h.entry_cluster, h.entry_index, entry);
        self.handles[handle_idx] = Some(h);
        Some(written)
    }

    fn close_handle(&mut self, handle: u64) -> bool {
        let idx = match usize::try_from(handle) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if idx >= self.handles.len() {
            return false;
        }
        self.handles[idx] = None;
        true
    }

    fn mkdir(&mut self, path: &str) -> bool {
        let (parent, name, ext) = match self.resolve_parent(path) {
            Some(val) => val,
            None => return false,
        };
        if let Some((_, _, entry)) = self.find_entry(parent, &name, &ext) {
            if entry
                .info()
                .attributes
                .contains(FileAttributes::DIRECTORY)
            {
                return true;
            }
            return false;
        }
        let cluster = self.allocate_clusters(1);
        if cluster < 2 {
            return false;
        }
        let (time_hp, _) = fat_time_now();
        let dir_entry = FileEntry::new(
            fat_name_to_str(&name),
            fat_ext_to_str(&ext),
            FileAttributes::DIRECTORY,
            0,
            cluster,
            time_hp,
        );
        let (dir_cluster, dir_index) = match self.find_free_entry(parent) {
            Some(v) => v,
            None => return false,
        };
        self.update_entry(dir_cluster, dir_index, dir_entry);

        let cluster_size = self.cluster_size();
        {
            let (_, _, data) = self.split_mut();
            let offset = (cluster as usize - 2) * cluster_size;
            for b in &mut data[offset..offset + cluster_size] {
                *b = 0;
            }
            let dir = Directory::from_bytes_mut(&mut data[offset..offset + cluster_size]);
            let (dot_time, _) = fat_time_now();
            dir.entries[0] = FileEntry::new(
                ".",
                "",
                FileAttributes::DIRECTORY,
                0,
                cluster,
                dot_time,
            );
            let (dotdot_time, _) = fat_time_now();
            dir.entries[1] = FileEntry::new(
                "..",
                "",
                FileAttributes::DIRECTORY,
                0,
                parent,
                dotdot_time,
            );
        }
        self.mark_cluster_range(cluster, 0, cluster_size);
        true
    }

    fn read_dir(&mut self, handle: u64, out: &mut Dirent) -> Option<bool> {
        let handle_idx = usize::try_from(handle).ok()?;
        let mut h = self.handles.get(handle_idx)?.clone()?;
        if h.kind != HandleKind::Dir {
            return None;
        }

        let cluster_size = self.cluster_size();
        let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
        let (_, fat_bytes, data) = self.split();
        let fat = Fat32::from_bytes(fat_bytes);
        let mut cluster = h.dir_cluster;
        let mut index = h.dir_index;
        loop {
            let offset = (cluster as usize - 2) * cluster_size;
            let dir = Directory::from_bytes(&data[offset..offset + cluster_size]);
            while index < entries_per_cluster {
                let entry = dir.entries[index];
                index += 1;
                let base = entry.base_name().raw;
                if base[0] == 0x00 {
                    h.dir_cluster = cluster;
                    h.dir_index = index;
                    self.handles[handle_idx] = Some(h);
                    return Some(false);
                }
                if base[0] == 0xE5 {
                    continue;
                }
                let info = entry.info();
                if info.attributes.contains(FileAttributes::VOLUME_LABEL) {
                    continue;
                }
                fill_dirent(out, &entry, &info);
                h.dir_cluster = cluster;
                h.dir_index = index;
                self.handles[handle_idx] = Some(h);
                return Some(true);
            }
            match self.next_cluster(fat, cluster) {
                Some(next) => {
                    cluster = next;
                    index = 0;
                }
                None => {
                    h.dir_cluster = cluster;
                    h.dir_index = index;
                    self.handles[handle_idx] = Some(h);
                    return Some(false);
                }
            }
        }
    }

    fn sync(&mut self) -> bool {
        match self.device {
            FsDevice::RamDisk => {
                self.dirty = None;
                true
            }
            FsDevice::VirtioBlk { sectors } => {
                if sectors == 0 {
                    return false;
                }
                let range = match self.dirty.take() {
                    Some(r) => r,
                    None => return true,
                };
                let start = range.start.min(self.storage.len());
                let end = range.end.min(self.storage.len());
                if end <= start {
                    return true;
                }
                let start_sector = start / BLOCK_SIZE;
                let end_sector = (end + BLOCK_SIZE - 1) / BLOCK_SIZE;
                let total_sectors = end_sector.saturating_sub(start_sector);
                if total_sectors == 0 {
                    return true;
                }
                serial::write(format_args!(
                    "fs: sync {} sectors (lba {}..{})\n",
                    total_sectors,
                    start_sector,
                    end_sector
                ));
                let mut done = 0u64;
                let mut lba = start_sector as u64;
                while done < total_sectors as u64 {
                    let chunk_sectors = (total_sectors as u64 - done).min(128);
                    let bytes = (chunk_sectors as usize) * BLOCK_SIZE;
                    let start_byte = (lba as usize) * BLOCK_SIZE;
                    let end_byte = start_byte + bytes;
                    if end_byte > self.storage.len() {
                        return false;
                    }
                    let slice = &self.storage[start_byte..end_byte];
                    if !virtio::blk_write(lba, slice) {
                        return false;
                    }
                    done += chunk_sectors;
                    lba += chunk_sectors;
                    if done % (128 * 16) == 0 || done == total_sectors as u64 {
                        serial::write(format_args!("fs: sync {}/{}\n", done, total_sectors));
                    }
                }
                serial::write(format_args!("fs: sync done\n"));
                true
            }
        }
    }

    fn alloc_handle(&mut self, handle: Handle) -> Option<u64> {
        for (idx, slot) in self.handles.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(handle);
                return Some(idx as u64);
            }
        }
        None
    }

    fn resolve_dir(&self, path: &str) -> Option<u32> {
        if path == "/" || path.is_empty() {
            return Some(self.bs.root_cluster);
        }
        let mut cluster = self.bs.root_cluster;
        for comp in path.split('/').filter(|s| !s.is_empty()) {
            if comp == "." {
                continue;
            }
            if comp == ".." {
                let name = FatStr::<8>::new_truncate("..");
                let ext = FatStr::<3>::new_truncate("");
                if let Some((_, _, entry)) = self.find_entry(cluster, &name, &ext) {
                    cluster = entry.cluster();
                }
                continue;
            }
            let (name, ext) = split_name(comp);
            let (_, _, entry) = self.find_entry(cluster, &name, &ext)?;
            if !entry
                .info()
                .attributes
                .contains(FileAttributes::DIRECTORY)
            {
                return None;
            }
            cluster = entry.cluster();
        }
        Some(cluster)
    }

    fn resolve_parent(&self, path: &str) -> Option<(u32, FatStr<8>, FatStr<3>)> {
        let mut comps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if comps.is_empty() {
            return None;
        }
        let last = comps.pop()?;
        let parent = if comps.is_empty() {
            self.bs.root_cluster
        } else {
            let mut cluster = self.bs.root_cluster;
            for comp in comps {
                let (name, ext) = split_name(comp);
                let (_, _, entry) = self.find_entry(cluster, &name, &ext)?;
                if !entry
                    .info()
                    .attributes
                    .contains(FileAttributes::DIRECTORY)
                {
                    return None;
                }
                cluster = entry.cluster();
            }
            cluster
        };
        let (name, ext) = split_name(last);
        Some((parent, name, ext))
    }
}

fn fs_info_mut_range<'a>(
    range: core::ops::Range<usize>,
    reserved: &'a mut [u8],
) -> Option<&'a mut FsInfo> {
    if range.end <= reserved.len() {
        Some(FsInfo::from_bytes_mut(&mut reserved[range]))
    } else {
        None
    }
}

fn recompute_free(fat_bytes: &[u8]) -> (u32, u32) {
    let fat = Fat32::from_bytes(fat_bytes);
    let mut free = 0u32;
    let mut next_free = 0xFFFF_FFFFu32;
    for (idx, entry) in fat.entries.iter().enumerate().skip(2) {
        if *entry == fat::constants::FAT32_CLUSTER_FREE {
            free = free.saturating_add(1);
            if next_free == 0xFFFF_FFFF {
                next_free = idx as u32;
            }
        }
    }
    if free == 0 {
        next_free = 0xFFFF_FFFF;
    }
    (free, next_free)
}

fn ensure_fs_info(
    range: core::ops::Range<usize>,
    reserved: &mut [u8],
    fat_bytes: &[u8],
) -> (u32, u32) {
    let (mut free_count, mut next_free) = if let Some(info) = fs_info_mut_range(range.clone(), reserved) {
        (info.free_count, info.next_free)
    } else {
        (0xFFFF_FFFF, 0xFFFF_FFFF)
    };

    if free_count == 0 || free_count == 0xFFFF_FFFF || next_free == 0xFFFF_FFFF {
        let (free, next) = recompute_free(fat_bytes);
        free_count = free;
        next_free = next;
        if let Some(info) = fs_info_mut_range(range, reserved) {
            info.free_count = free_count;
            info.next_free = next_free;
        }
    }

    (free_count, next_free)
}

fn split_name(name: &str) -> (FatStr<8>, FatStr<3>) {
    let mut parts = name.splitn(2, '.');
    let base = parts.next().unwrap_or("");
    let ext = parts.next().unwrap_or("");
    let base = uppercase_ascii(base);
    let ext = uppercase_ascii(ext);
    (FatStr::new_truncate(&base), FatStr::new_truncate(&ext))
}

fn uppercase_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        out.push((b as char).to_ascii_uppercase());
    }
    out
}

fn fat_name_to_str(name: &FatStr<8>) -> &str {
    let len = name.len();
    str::from_utf8(&name.as_slice()[..len]).unwrap_or("")
}

fn fat_ext_to_str(ext: &FatStr<3>) -> &str {
    let len = ext.len();
    str::from_utf8(&ext.as_slice()[..len]).unwrap_or("")
}

fn fill_dirent(out: &mut Dirent, entry: &FileEntry, info: &hadris_fat::structures::directory::FileEntryInfo) {
    let base = entry.base_name();
    let ext = entry.extension();
    let base_len = base.len();
    let ext_len = ext.len();
    let mut name_len = 0usize;
    out.name = [0; 12];
    if base_len > 0 {
        let slice = &base.as_slice()[..base_len];
        out.name[..slice.len()].copy_from_slice(slice);
        name_len += slice.len();
    }
    if ext_len > 0 {
        out.name[name_len] = b'.';
        name_len += 1;
        let slice = &ext.as_slice()[..ext_len];
        out.name[name_len..name_len + slice.len()].copy_from_slice(slice);
        name_len += slice.len();
    }
    out.name_len = name_len as u8;
    out.attr = info.attributes.bits();
    out._pad = [0; 2];
    out.size = info.size;
}

fn fat_time_now() -> (FatTimeHighP, FatTime) {
    let epoch = time::epoch_seconds_now(interrupts::ticks()).unwrap_or(0);
    let (year, month, day, hour, minute, second) = epoch_to_ymdhms(epoch);
    let year = year.clamp(1980, 2107);
    let date = (((year - 1980) as u16) << 9) | ((month as u16) << 5) | (day as u16);
    let time_val = ((hour as u16) << 11) | ((minute as u16) << 5) | ((second as u16) / 2);
    let fat = FatTime::new(time_val, date);
    (FatTimeHighP::new(0, time_val, date), fat)
}

fn epoch_to_ymdhms(epoch: u64) -> (u16, u8, u8, u8, u8, u8) {
    const SECS_PER_DAY: u64 = 86_400;
    const SECS_PER_HOUR: u64 = 3_600;
    const SECS_PER_MIN: u64 = 60;
    let mut days = epoch / SECS_PER_DAY;
    let mut secs = epoch % SECS_PER_DAY;
    let hour = (secs / SECS_PER_HOUR) as u8;
    secs %= SECS_PER_HOUR;
    let minute = (secs / SECS_PER_MIN) as u8;
    let second = (secs % SECS_PER_MIN) as u8;

    let mut year: u16 = 1970;
    loop {
        let year_days = if is_leap(year) { 366 } else { 365 };
        if days >= year_days {
            days -= year_days;
            year += 1;
        } else {
            break;
        }
    }

    let mut month: u8 = 1;
    loop {
        let dim = days_in_month(year, month) as u64;
        if days >= dim {
            days -= dim;
            month += 1;
        } else {
            break;
        }
    }
    let day = (days + 1) as u8;
    (year, month, day, hour, minute, second)
}

fn is_leap(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 => 31,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        _ => 31,
    }
}
