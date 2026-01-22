use core::alloc::Layout;
use core::sync::atomic::{AtomicBool, Ordering};

use linked_list_allocator::LockedHeap;

extern "C" {
    static _heap_start: u8;
    static _heap_end: u8;
}

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    let start = core::ptr::addr_of!(_heap_start) as usize;
    let end = core::ptr::addr_of!(_heap_end) as usize;
    let size = end.saturating_sub(start);
    unsafe {
        ALLOCATOR.lock().init(start as *mut u8, size);
    }
}

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[alloc_error_handler]
fn oom(_layout: Layout) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
