use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

extern "C" {
    static _heap_start: u8;
    static _heap_end: u8;
}

static HEAP_START: AtomicUsize = AtomicUsize::new(0);
static HEAP_END: AtomicUsize = AtomicUsize::new(0);
static NEXT: AtomicUsize = AtomicUsize::new(0);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    let start = core::ptr::addr_of!(_heap_start) as usize;
    let end = core::ptr::addr_of!(_heap_end) as usize;
    HEAP_START.store(start, Ordering::Release);
    HEAP_END.store(end, Ordering::Release);
    NEXT.store(start, Ordering::Release);
}

struct BumpAllocator;

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !INITIALIZED.load(Ordering::Acquire) {
            init();
        }
        let start = HEAP_START.load(Ordering::Acquire);
        let end = HEAP_END.load(Ordering::Acquire);
        if start == 0 || end <= start {
            return null_mut();
        }
        let align = layout.align().max(1);
        let size = layout.size().max(1);
        let mut current = NEXT.load(Ordering::Relaxed);
        loop {
            let aligned = align_up(current.max(start), align);
            let next = match aligned.checked_add(size) {
                Some(val) => val,
                None => return null_mut(),
            };
            if next > end {
                return null_mut();
            }
            match NEXT.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return aligned as *mut u8,
                Err(prev) => current = prev,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            core::ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[alloc_error_handler]
fn oom(_layout: Layout) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

#[inline]
const fn align_up(value: usize, align: usize) -> usize {
    (value + (align - 1)) & !(align - 1)
}
