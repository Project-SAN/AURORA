use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB for now

static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

pub struct BumpAllocator {
    start: AtomicUsize,
    end: AtomicUsize,
    next: AtomicUsize,
}

impl BumpAllocator {
    pub const fn new() -> Self {
        Self {
            start: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
        }
    }

    pub fn init(&self) {
        let start = core::ptr::addr_of!(HEAP) as usize;
        let end = start + HEAP_SIZE;
        self.start.store(start, Ordering::SeqCst);
        self.end.store(end, Ordering::SeqCst);
        self.next.store(start, Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();

pub fn init() {
    ALLOCATOR.init();
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let start = self.start.load(Ordering::Relaxed);
        let end = self.end.load(Ordering::Relaxed);
        if start == 0 || end == 0 {
            return null_mut();
        }

        let mut current = self.next.load(Ordering::Relaxed);
        loop {
            let aligned = align_up(current, layout.align());
            let new_next = match aligned.checked_add(layout.size()) {
                Some(next) => next,
                None => return null_mut(),
            };
            if new_next > end {
                return null_mut();
            }
            match self.next.compare_exchange(
                current,
                new_next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(next) => current = next,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // no-op for bump allocator
    }
}

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}
