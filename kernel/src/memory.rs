use alloc::vec::Vec;
use core::cell::UnsafeCell;
use uefi::table::boot::{MemoryMap, MemoryType};

pub const PAGE_SIZE: u64 = 4096;
const MIN_USABLE_ADDR: u64 = PAGE_SIZE; // avoid returning phys 0
const MAX_PHYS_ADDR: u64 = 0x1_0000_0000; // 4 GiB limit for current paging
const DMA_LIMIT: u64 = 0x1000_0000 - 1; // 256 MiB for DMA-safe allocations

#[derive(Clone, Copy, Debug)]
struct Region {
    start: u64,
    end: u64,
}

pub struct MemoryManager {
    free: Vec<Region>,
    total_usable: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct MemoryStats {
    pub total_usable: u64,
    pub region_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct DmaBuffer {
    pub phys: u64,
    pub size: usize,
}

struct MemoryState {
    manager: UnsafeCell<Option<MemoryManager>>,
}

unsafe impl Sync for MemoryState {}

impl MemoryState {
    const fn new() -> Self {
        Self {
            manager: UnsafeCell::new(None),
        }
    }
}

static MEMORY: MemoryState = MemoryState::new();

pub fn init(map: &MemoryMap) -> MemoryStats {
    let manager = MemoryManager::new(map);
    let stats = manager.stats();
    unsafe { *MEMORY.manager.get() = Some(manager) };
    stats
}

pub fn alloc_frame() -> Option<u64> {
    with_manager(|mgr| mgr.alloc_contiguous_range(1, MIN_USABLE_ADDR, MAX_PHYS_ADDR - 1))?
}

pub fn alloc_contiguous(pages: usize) -> Option<u64> {
    with_manager(|mgr| mgr.alloc_contiguous_range(pages, MIN_USABLE_ADDR, MAX_PHYS_ADDR - 1))?
}

pub fn alloc_dma_pages(pages: usize) -> Option<DmaBuffer> {
    let phys = with_manager(|mgr| mgr.alloc_contiguous_range(pages, MIN_USABLE_ADDR, DMA_LIMIT))??;
    Some(DmaBuffer {
        phys,
        size: pages * PAGE_SIZE as usize,
    })
}

pub fn alloc_normal_pages(pages: usize) -> Option<u64> {
    with_manager(|mgr| mgr.alloc_contiguous_range(pages, DMA_LIMIT + 1, MAX_PHYS_ADDR - 1))?
}

pub fn free_frame(addr: u64) {
    free_contiguous(addr, 1);
}

pub fn free_contiguous(addr: u64, pages: usize) {
    let _ = with_manager(|mgr| {
        mgr.free_range(addr, pages);
    });
}

/// Temporary: assumes an identity mapping between physical and virtual memory.
pub fn phys_to_virt(phys: u64) -> *mut u8 {
    phys as *mut u8
}

fn with_manager<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut MemoryManager) -> R,
{
    unsafe {
        let slot = &mut *MEMORY.manager.get();
        let manager = slot.as_mut()?;
        Some(f(manager))
    }
}

impl MemoryManager {
    fn new(map: &MemoryMap) -> Self {
        let mut regions = Vec::new();
        let mut total = 0u64;
        for desc in map.entries() {
            if is_usable(desc.ty) {
                let start = align_up(desc.phys_start, PAGE_SIZE).max(MIN_USABLE_ADDR);
                let end = desc
                    .phys_start
                    .saturating_add(desc.page_count.saturating_mul(PAGE_SIZE))
                    .min(MAX_PHYS_ADDR);
                if start < end {
                    regions.push(Region { start, end });
                    total = total.saturating_add(end - start);
                }
            }
        }
        regions.sort_by_key(|r| r.start);
        let regions = coalesce(regions);

        Self {
            free: regions,
            total_usable: total,
        }
    }

    fn stats(&self) -> MemoryStats {
        MemoryStats {
            total_usable: self.total_usable,
            region_count: self.free.len(),
        }
    }

    fn alloc_contiguous_range(&mut self, pages: usize, min: u64, max: u64) -> Option<u64> {
        if pages == 0 {
            return None;
        }
        let size = (pages as u64).saturating_mul(PAGE_SIZE);
        if min > max || size == 0 {
            return None;
        }
        for idx in 0..self.free.len() {
            let region = self.free[idx];
            let usable_start = align_up(region.start.max(min), PAGE_SIZE);
            let usable_end = region.end.min(max.saturating_add(1));
            if usable_start.saturating_add(size) <= usable_end {
                let alloc_start = usable_start;
                let alloc_end = alloc_start + size;

                if alloc_start == region.start && alloc_end == region.end {
                    self.free.remove(idx);
                } else if alloc_start == region.start {
                    self.free[idx].start = alloc_end;
                } else if alloc_end == region.end {
                    self.free[idx].end = alloc_start;
                } else {
                    let tail = Region {
                        start: alloc_end,
                        end: region.end,
                    };
                    self.free[idx].end = alloc_start;
                    self.free.insert(idx + 1, tail);
                }
                return Some(alloc_start);
            }
        }
        None
    }

    fn free_range(&mut self, addr: u64, pages: usize) {
        if pages == 0 {
            return;
        }
        let start = align_up(addr, PAGE_SIZE);
        let end = start.saturating_add((pages as u64).saturating_mul(PAGE_SIZE));
        if start >= end {
            return;
        }
        self.free.push(Region { start, end });
        self.free = coalesce(self.free.clone());
    }
}

fn is_usable(ty: MemoryType) -> bool {
    matches!(
        ty,
        MemoryType::CONVENTIONAL
            | MemoryType::BOOT_SERVICES_CODE
            | MemoryType::BOOT_SERVICES_DATA
    )
}

fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

fn coalesce(mut regions: Vec<Region>) -> Vec<Region> {
    if regions.is_empty() {
        return regions;
    }
    regions.sort_by_key(|r| r.start);
    let mut merged = Vec::new();
    let mut current = regions[0];
    for region in regions.into_iter().skip(1) {
        if region.start <= current.end {
            current.end = current.end.max(region.end);
        } else {
            merged.push(current);
            current = region;
        }
    }
    merged.push(current);
    merged
}
