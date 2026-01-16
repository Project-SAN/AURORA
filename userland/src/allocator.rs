use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

// Simple bump allocator for userland. Adjust size as needed.
const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

#[repr(align(16))]
struct AlignedHeap([u8; HEAP_SIZE]);

static mut HEAP: AlignedHeap = AlignedHeap([0; HEAP_SIZE]);
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAlloc;

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(1);
        let size = layout.size().max(1);
        let mut current = NEXT.load(Ordering::Relaxed);
        loop {
            let aligned = (current + (align - 1)) & !(align - 1);
            let next = match aligned.checked_add(size) {
                Some(val) => val,
                None => return null_mut(),
            };
            if next > HEAP_SIZE {
                return null_mut();
            }
            match NEXT.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return HEAP.0.as_mut_ptr().add(aligned),
                Err(prev) => current = prev,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAlloc = BumpAlloc;

#[alloc_error_handler]
fn oom(_layout: Layout) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
