use crate::arch::syscall::SyscallFrame;
use crate::interrupts;
use crate::serial;
use crate::{net, time, virtio};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use core::arch::asm;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 2;
const SYS_YIELD: u64 = 3;
const SYS_SLEEP: u64 = 4;
const SYS_NET_LISTEN: u64 = 10;
const SYS_NET_ACCEPT: u64 = 11;
const SYS_NET_RECV: u64 = 12;
const SYS_NET_SEND: u64 = 13;
const SYS_NET_CLOSE: u64 = 14;
const SYS_NET_CONNECT: u64 = 15;
const SYS_TIME_EPOCH: u64 = 16;
const TICK_MS: u64 = 10;

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
        SYS_SLEEP => sys_sleep(frame.rdi),
        SYS_NET_LISTEN => sys_net_listen(frame.rdi),
        SYS_NET_ACCEPT => sys_net_accept(),
        SYS_NET_RECV => sys_net_recv(frame.rdi, frame.rsi),
        SYS_NET_SEND => sys_net_send(frame.rdi, frame.rsi),
        SYS_NET_CLOSE => sys_net_close(),
        SYS_NET_CONNECT => sys_net_connect(frame.rdi, frame.rsi),
        SYS_TIME_EPOCH => sys_time_epoch(),
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

fn sys_time_epoch() -> u64 {
    match time::epoch_seconds_now(interrupts::ticks()) {
        Some(val) => val,
        None => u64::MAX,
    }
}

fn sys_yield() -> u64 {
    let result = with_net_ctx(0, |stack, device| {
        let _ = stack.poll(device, net::now());
        0
    });
    virtio::reclaim_tx();
    result
}

fn sys_sleep(ms: u64) -> u64 {
    if ms == 0 {
        return 0;
    }
    let wait_ticks = (ms + (TICK_MS - 1)) / TICK_MS;
    let target = interrupts::ticks().saturating_add(wait_ticks);
    let had_if = (read_rflags() & (1 << 9)) != 0;
    unsafe { asm!("sti", options(nomem, nostack, preserves_flags)) };
    while interrupts::ticks() < target {
        sys_yield();
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
    if !had_if {
        unsafe { asm!("cli", options(nomem, nostack, preserves_flags)) };
    }
    0
}

fn sys_net_listen(port: u64) -> u64 {
    if port == 0 || port > u16::MAX as u64 {
        return u64::MAX;
    }
    let port = port as u16;
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        if stack.listen(port) {
            0
        } else {
            u64::MAX
        }
    })
}

fn sys_net_accept() -> u64 {
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        if stack.accept() {
            1
        } else {
            0
        }
    })
}

fn sys_net_recv(buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    let max_len = usize::try_from(len).unwrap_or(usize::MAX);
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, max_len) };
        stack.recv(slice) as u64
    })
}

fn sys_net_send(buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    let max_len = usize::try_from(len).unwrap_or(usize::MAX);
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, max_len) };
        stack.send(slice) as u64
    })
}

fn sys_net_close() -> u64 {
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        stack.close();
        0
    })
}

fn sys_net_connect(ip: u64, port: u64) -> u64 {
    if port == 0 || port > u16::MAX as u64 || ip == 0 {
        return u64::MAX;
    }
    let ip = (ip as u32).to_be_bytes();
    let port = port as u16;
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        let result = match stack.connect(ip, port) {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(_) => u64::MAX,
        };
        let _ = stack.poll(device, net::now());
        result
    })
}

fn with_net_ctx<F, R>(default: R, f: F) -> R
where
    F: FnOnce(&mut net::NetStack, &mut net::VirtioDevice) -> R,
{
    if !YIELD_READY.load(Ordering::Acquire) {
        return default;
    }
    let ctx = unsafe { &*(*YIELD_CTX.0.get()).as_ptr() };
    let stack = unsafe { &mut *ctx.stack };
    let device = unsafe { &mut *ctx.device };
    f(stack, device)
}

fn read_rflags() -> u64 {
    let rflags: u64;
    unsafe {
        asm!("pushfq; pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }
    rflags
}
