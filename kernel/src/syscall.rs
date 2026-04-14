use crate::arch::syscall::SyscallFrame;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
use crate::interrupts;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
use crate::net;
use crate::serial;
use crate::time;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
use crate::fs;
#[cfg(target_arch = "x86_64")]
use crate::virtio as netdev;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
use crate::virtio_mmio as netdev;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
use core::arch::asm;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
use core::cell::UnsafeCell;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
use core::mem::MaybeUninit;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
use core::str;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
use core::sync::atomic::{AtomicBool, Ordering};

const SYS_WRITE: u64 = 1;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT: u64 = 2;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_YIELD: u64 = 3;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_SLEEP: u64 = 4;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_NET_SOCKET: u64 = 9;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_NET_LISTEN: u64 = 10;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_NET_ACCEPT: u64 = 11;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_NET_RECV: u64 = 12;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_NET_SEND: u64 = 13;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_NET_CLOSE: u64 = 14;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_NET_CONNECT: u64 = 15;
const SYS_TIME_EPOCH: u64 = 16;
const SYS_FS_OPEN: u64 = 32;
const SYS_FS_READ: u64 = 33;
const SYS_FS_WRITE: u64 = 34;
const SYS_FS_CLOSE: u64 = 35;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
const SYS_FS_MKDIR: u64 = 36;
#[cfg(target_arch = "x86_64")]
const SYS_FS_OPENDIR: u64 = 37;
#[cfg(target_arch = "x86_64")]
const SYS_FS_READDIR: u64 = 38;
const SYS_FS_SYNC: u64 = 39;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
))]
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
    let num = frame.number();
    let ret = match num {
        SYS_WRITE => sys_write(frame.arg0(), frame.arg1(), frame.arg2()),
        SYS_TIME_EPOCH => sys_time_epoch(),
        #[cfg(target_arch = "x86_64")]
        SYS_EXIT => sys_exit(frame.arg0()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_YIELD => sys_yield(),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_SLEEP => sys_sleep(frame.arg0()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_NET_SOCKET => sys_net_socket(),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_NET_LISTEN => sys_net_listen(frame.arg0(), frame.arg1()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_NET_ACCEPT => sys_net_accept(frame.arg0()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_NET_RECV => sys_net_recv(frame.arg0(), frame.arg1(), frame.arg2()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_NET_SEND => sys_net_send(frame.arg0(), frame.arg1(), frame.arg2()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_NET_CLOSE => sys_net_close(frame.arg0()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_NET_CONNECT => sys_net_connect(frame.arg0(), frame.arg1(), frame.arg2()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_FS_OPEN => sys_fs_open(frame.arg0(), frame.arg1(), frame.arg2() as u32),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_FS_READ => sys_fs_read(frame.arg0(), frame.arg1(), frame.arg2()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_FS_WRITE => sys_fs_write(frame.arg0(), frame.arg1(), frame.arg2()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_FS_CLOSE => sys_fs_close(frame.arg0()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_FS_MKDIR => sys_fs_mkdir(frame.arg0(), frame.arg1()),
        #[cfg(target_arch = "x86_64")]
        SYS_FS_OPENDIR => sys_fs_opendir(frame.arg0(), frame.arg1()),
        #[cfg(target_arch = "x86_64")]
        SYS_FS_READDIR => sys_fs_readdir(frame.arg0(), frame.arg1(), frame.arg2()),
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        ))]
        SYS_FS_SYNC => sys_fs_sync(),
        _ => u64::MAX,
    };
    frame.set_ret(ret);
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

#[cfg(target_arch = "x86_64")]
fn sys_exit(_code: u64) -> u64 {
    0
}

fn sys_time_epoch() -> u64 {
    match time::epoch_seconds_now(current_ticks()) {
        Some(val) => val,
        None => u64::MAX,
    }
}

fn current_ticks() -> u64 {
    interrupts::ticks()
}

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "uefi")
)))]
fn current_ticks() -> u64 {
    0
}

fn sys_fs_open(path: u64, len: u64, flags: u32) -> u64 {
    let path = match get_user_str(path, len) {
        Some(p) => p,
        None => return u64::MAX,
    };
    match fs::open(path, flags) {
        Some(handle) => handle,
        None => u64::MAX,
    }
}

fn sys_fs_read(handle: u64, buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    let max_len = usize::try_from(len).unwrap_or(usize::MAX);
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, max_len) };
    match fs::read(handle, slice) {
        Some(n) => n as u64,
        None => u64::MAX,
    }
}

fn sys_fs_write(handle: u64, buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    let max_len = usize::try_from(len).unwrap_or(usize::MAX);
    let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, max_len) };
    match fs::write(handle, slice) {
        Some(n) => n as u64,
        None => u64::MAX,
    }
}

fn sys_fs_close(handle: u64) -> u64 {
    if fs::close(handle) {
        0
    } else {
        u64::MAX
    }
}

fn sys_fs_mkdir(path: u64, len: u64) -> u64 {
    let path = match get_user_str(path, len) {
        Some(p) => p,
        None => return u64::MAX,
    };
    if fs::mkdir(path) {
        0
    } else {
        u64::MAX
    }
}

#[cfg(target_arch = "x86_64")]
fn sys_fs_opendir(path: u64, len: u64) -> u64 {
    let path = match get_user_str(path, len) {
        Some(p) => p,
        None => return u64::MAX,
    };
    match fs::opendir(path) {
        Some(handle) => handle,
        None => u64::MAX,
    }
}

#[cfg(target_arch = "x86_64")]
fn sys_fs_readdir(handle: u64, buf: u64, len: u64) -> u64 {
    if buf == 0 || len < core::mem::size_of::<fs::Dirent>() as u64 {
        return u64::MAX;
    }
    let entry = unsafe { &mut *(buf as *mut fs::Dirent) };
    match fs::readdir(handle, entry) {
        Some(true) => 1,
        Some(false) => 0,
        None => u64::MAX,
    }
}

fn sys_fs_sync() -> u64 {
    if fs::sync() {
        0
    } else {
        u64::MAX
    }
}

fn sys_yield() -> u64 {
    let result = with_net_ctx(0, |stack, device| {
        let _ = stack.poll(device, net::now());
        0
    });
    netdev::reclaim_tx();
    result
}

fn sys_sleep(ms: u64) -> u64 {
    if ms == 0 {
        return 0;
    }
    let wait_ticks = (ms + (TICK_MS - 1)) / TICK_MS;
    let target = interrupts::ticks().saturating_add(wait_ticks);
    #[cfg(target_arch = "x86_64")]
    let had_if = (read_rflags() & (1 << 9)) != 0;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
    while interrupts::ticks() < target {
        sys_yield();
        #[cfg(target_arch = "x86_64")]
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
        #[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
        unsafe {
            asm!("wfi", options(nomem, nostack, preserves_flags));
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        )))]
        core::hint::spin_loop();
    }
    #[cfg(target_arch = "x86_64")]
    if !had_if {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            asm!("cli", options(nomem, nostack, preserves_flags));
        }
    }
    0
}

fn sys_net_socket() -> u64 {
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        stack.socket().unwrap_or(u64::MAX)
    })
}

fn sys_net_listen(handle: u64, port: u64) -> u64 {
    if port == 0 || port > u16::MAX as u64 {
        return u64::MAX;
    }
    let port = port as u16;
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        if stack.listen(handle, port) {
            serial::write(format_args!(
                "net: listen handle={} port={}\n",
                handle, port
            ));
            0
        } else {
            u64::MAX
        }
    })
}

fn sys_net_accept(handle: u64) -> u64 {
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        match stack.accept(handle) {
            Ok(Some(id)) => {
                serial::write(format_args!("net: accept handle={} -> {}\n", handle, id));
                id
            }
            Ok(None) => 0,
            Err(_) => {
                serial::write(format_args!("net: accept error handle={}\n", handle));
                u64::MAX
            }
        }
    })
}

fn sys_net_recv(handle: u64, buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    let max_len = usize::try_from(len).unwrap_or(usize::MAX);
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, max_len) };
        let n = stack.recv(handle, slice) as u64;
        if n > 0 {
            serial::write(format_args!("net: recv handle={} len={}\n", handle, n));
        }
        n
    })
}

fn sys_net_send(handle: u64, buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    let max_len = usize::try_from(len).unwrap_or(usize::MAX);
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, max_len) };
        if max_len <= 4096 {
            stack.trace_socket_state(handle, "send_pre");
        }
        let sent = stack.send(handle, slice) as u64;
        if sent > 0 {
            let drain_loops = if max_len <= 4096 { 20_000 } else { 2_048 };
            for _ in 0..drain_loops {
                let _ = stack.poll(device, net::now());
                if stack.send_queue(handle).unwrap_or(0) == 0 {
                    break;
                }
            }
        }
        if max_len <= 4096 {
            stack.trace_socket_state(handle, "send_post");
        }
        sent
    })
}

fn sys_net_close(handle: u64) -> u64 {
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        stack.trace_socket_state(handle, "close_pre");
        if stack.shutdown(handle) {
            for _ in 0..500 {
                let _ = stack.poll(device, net::now());
            }
            stack.trace_socket_state(handle, "close_post_shutdown");
            return 0;
        }
        stack.close(handle);
        stack.trace_socket_state(handle, "close_post_abort");
        0
    })
}

fn sys_net_connect(handle: u64, ip: u64, port: u64) -> u64 {
    if port == 0 || port > u16::MAX as u64 || ip == 0 {
        return u64::MAX;
    }
    let ip = (ip as u32).to_be_bytes();
    let port = port as u16;
    with_net_ctx(u64::MAX, |stack, device| {
        let _ = stack.poll(device, net::now());
        let result = match stack.connect(handle, ip, port) {
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

#[cfg(target_arch = "x86_64")]
fn read_rflags() -> u64 {
    let rflags: u64;
    unsafe {
        asm!("pushfq; pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }
    rflags
}

fn get_user_str(ptr: u64, len: u64) -> Option<&'static str> {
    if ptr == 0 || len == 0 {
        return None;
    }
    let max_len = usize::try_from(len).ok()?;
    let slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, max_len) };
    str::from_utf8(slice).ok()
}
