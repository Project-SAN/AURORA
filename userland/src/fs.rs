use crate::sys;

pub const O_READ: u32 = 1;
pub const O_WRITE: u32 = 2;
pub const O_CREATE: u32 = 4;
pub const O_TRUNC: u32 = 8;

pub fn open(path: &str, flags: u32) -> Option<u64> {
    let ret = unsafe {
        sys::syscall3(
            sys::SYS_FS_OPEN,
            path.as_ptr() as u64,
            path.len() as u64,
            flags as u64,
        )
    };
    if ret == u64::MAX {
        None
    } else {
        Some(ret)
    }
}

pub fn read(handle: u64, buf: &mut [u8]) -> Option<usize> {
    let ret = unsafe {
        sys::syscall3(
            sys::SYS_FS_READ,
            handle,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    };
    if ret == u64::MAX {
        None
    } else {
        Some(ret as usize)
    }
}

pub fn write(handle: u64, buf: &[u8]) -> Option<usize> {
    let ret = unsafe {
        sys::syscall3(
            sys::SYS_FS_WRITE,
            handle,
            buf.as_ptr() as u64,
            buf.len() as u64,
        )
    };
    if ret == u64::MAX {
        None
    } else {
        Some(ret as usize)
    }
}

pub fn close(handle: u64) -> bool {
    let ret = unsafe { sys::syscall1(sys::SYS_FS_CLOSE, handle) };
    ret != u64::MAX
}

pub fn mkdir(path: &str) -> bool {
    let ret = unsafe { sys::syscall2(sys::SYS_FS_MKDIR, path.as_ptr() as u64, path.len() as u64) };
    ret != u64::MAX
}

pub fn sync() -> bool {
    let ret = unsafe { sys::syscall0(sys::SYS_FS_SYNC) };
    ret != u64::MAX
}
