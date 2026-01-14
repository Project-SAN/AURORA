use crate::arch::syscall::SyscallFrame;
use crate::serial;
use crate::{net, virtio};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 2;
const SYS_YIELD: u64 = 3;

struct YieldContext {
    stack: *mut net::NetStack,
    device: *mut net::VirtioDevice,
}

struct YieldContextCell(UnsafeCell<MaybeUninit<YieldContext>>);

unsafe impl Sync for YieldContextCell {}

static YIELD_CTX: YieldContextCell = YieldContextCell(UnsafeCell::new(MaybeUninit::uninit()));
static YIELD_READY: AtomicBool = AtomicBool::new(false);

pub fn install_yield(stack: *mut net::NetStack, device: *mut net::VirtioDevice) {
    unsafe {
        (*YIELD_CTX.0.get()).write(YieldContext { stack, device });
    }
    YIELD_READY.store(true, Ordering::Release);
}

pub extern "C" fn dispatch(frame: &mut SyscallFrame) {
    let num = frame.rax;
    frame.rax = match num {
        SYS_WRITE => sys_write(frame.rdi, frame.rsi, frame.rdx),
        SYS_EXIT => sys_exit(frame.rdi),
        SYS_YIELD => sys_yield(),
        _ => u64::MAX,
    };
}

fn sys_write(_fd: u64, buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
    for &b in slice {
        serial::write(format_args!("{}", b as char));
    }
    len
}

fn sys_exit(_code: u64) -> u64 {
    0
}

fn sys_yield() -> u64 {
    if YIELD_READY.load(Ordering::Acquire) {
        let ctx = unsafe { &*(*YIELD_CTX.0.get()).as_ptr() };
        let stack = unsafe { &mut *ctx.stack };
        let device = unsafe { &mut *ctx.device };
        let _ = stack.poll(device, net::now());
    }
    virtio::reclaim_tx();
    0
}
