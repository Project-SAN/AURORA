use crate::arch::syscall::SyscallFrame;
use crate::serial;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 2;

pub extern "C" fn dispatch(frame: &mut SyscallFrame) {
    let num = frame.rax;
    frame.rax = match num {
        SYS_WRITE => sys_write(frame.rdi, frame.rsi, frame.rdx),
        SYS_EXIT => sys_exit(frame.rdi),
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
