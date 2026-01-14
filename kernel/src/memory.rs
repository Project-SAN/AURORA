use alloc::vec::Vec;
use core::cell::UnsafeCell;
use uefi::table::boot::{MemoryMap, MemoryType};

const PAGE_SIZE: u64 = 4096;
const MIN_USABLE_ADDR: u64 = PAGE_SIZE; // avoid returning phys 0

#[derive(Clone, Copy, Debug)]
struct Region {
    start: u64,
    end: u64,
}

pub struct MemoryManager {
    regions: Vec<Region>,
    region_index: usize,
    next_frame: u64,
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
    with_manager(|mgr| mgr.alloc_contiguous(1))?
}

pub fn alloc_contiguous(pages: usize) -> Option<u64> {
    with_manager(|mgr| mgr.alloc_contiguous(pages))?
}

pub fn alloc_dma_pages(pages: usize) -> Option<DmaBuffer> {
    let phys = alloc_contiguous(pages)?;
    Some(DmaBuffer {
        phys,
        size: pages * PAGE_SIZE as usize,
    })
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
                    .saturating_add(desc.page_count.saturating_mul(PAGE_SIZE));
                if start < end {
                    regions.push(Region { start, end });
                    total = total.saturating_add(end - start);
                }
            }
        }
        regions.sort_by_key(|r| r.start);
        let regions = coalesce(regions);

        Self {
            regions,
            region_index: 0,
            next_frame: 0,
            total_usable: total,
        }
    }

    fn stats(&self) -> MemoryStats {
        MemoryStats {
            total_usable: self.total_usable,
            region_count: self.regions.len(),
        }
    }

    fn alloc_contiguous(&mut self, pages: usize) -> Option<u64> {
        if pages == 0 {
            return None;
        }
        let size = (pages as u64).saturating_mul(PAGE_SIZE);
        while self.region_index < self.regions.len() {
            let region = self.regions[self.region_index];
            let cursor = if self.next_frame < region.start {
                region.start
            } else {
                self.next_frame
            };
            let cursor = align_up(cursor, PAGE_SIZE);
            if cursor.saturating_add(size) <= region.end {
                self.next_frame = cursor + size;
                return Some(cursor);
            }
            self.region_index += 1;
            self.next_frame = 0;
        }
        None
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
