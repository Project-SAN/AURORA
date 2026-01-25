#[cfg(target_arch = "x86_64")]
#[path = "sys_x86_64.rs"]
mod imp;

#[cfg(not(target_arch = "x86_64"))]
#[path = "sys_stub.rs"]
mod imp;

pub use self::imp::{syscall0, syscall1, syscall2, syscall3};

pub const SYS_WRITE: u64 = 1;
pub const SYS_SLEEP: u64 = 4;
pub const SYS_NET_SOCKET: u64 = 9;
#[allow(dead_code)]
pub const SYS_NET_LISTEN: u64 = 10;
#[allow(dead_code)]
pub const SYS_NET_ACCEPT: u64 = 11;
pub const SYS_NET_RECV: u64 = 12;
pub const SYS_NET_SEND: u64 = 13;
pub const SYS_NET_CLOSE: u64 = 14;
pub const SYS_NET_CONNECT: u64 = 15;
pub const SYS_TIME_EPOCH: u64 = 16;
pub const SYS_FS_OPEN: u64 = 32;
pub const SYS_FS_READ: u64 = 33;
pub const SYS_FS_WRITE: u64 = 34;
pub const SYS_FS_CLOSE: u64 = 35;
pub const SYS_FS_MKDIR: u64 = 36;
pub const SYS_FS_OPENDIR: u64 = 37;
pub const SYS_FS_READDIR: u64 = 38;
pub const SYS_FS_SYNC: u64 = 39;

pub fn write(fd: u64, buf: &[u8]) -> u64 {
    unsafe { syscall3(SYS_WRITE, fd, buf.as_ptr() as u64, buf.len() as u64) }
}

pub fn sleep(ms: u64) {
    unsafe {
        let _ = syscall1(SYS_SLEEP, ms);
    }
}

pub fn time_epoch() -> Option<u64> {
    let ret = unsafe { syscall0(SYS_TIME_EPOCH) };
    if ret == u64::MAX {
        None
    } else {
        Some(ret)
    }
}
