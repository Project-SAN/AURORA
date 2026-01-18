#[cfg(feature = "hornet-log")]
extern crate alloc;

#[cfg(feature = "hornet-log")]
use alloc::string::String;
#[cfg(feature = "hornet-log")]
use core::fmt::{self, Write as FmtWrite};

#[cfg(feature = "hornet-log")]
static mut HOOK: Option<fn(&str)> = None;

#[cfg(feature = "hornet-log")]
pub fn set_hook(hook: fn(&str)) {
    unsafe { HOOK = Some(hook) };
}

#[cfg(feature = "hornet-log")]
pub fn emit(args: fmt::Arguments<'_>) {
    let mut buf = String::new();
    let _ = FmtWrite::write_fmt(&mut buf, args);
    unsafe {
        if let Some(hook) = HOOK {
            hook(&buf);
        }
    }
}

#[cfg(not(feature = "hornet-log"))]
pub fn set_hook(_: fn(&str)) {}

#[cfg(not(feature = "hornet-log"))]
pub fn emit(_: core::fmt::Arguments<'_>) {}
