extern crate errno;
extern crate libc;

use errno::{Errno, set_errno};
use libc::{c_char, c_void, ENOMEM, realloc, size_t};
use std::{ptr};

#[macro_use]
mod macros {
    macro_rules! assert_nonzero {
        ($s:expr) => {{
            assert_ne!($s, 0);
            $s
        }};
    }

    macro_rules! cstr {
        ($s:expr) => (
            concat!($s, "\0") as *const str as *const [c_char] as *const c_char
        );
    }
}

pub mod platform;
pub mod ptrace;

extern {
    pub fn error(_: *const c_char, ...) -> ();
    pub fn debug(_: *const c_char, ...) -> ();
}

#[no_mangle]
pub extern fn xreallocarray(optr: *mut c_void, nmemb: size_t, size: size_t) -> *mut c_void {
    if nmemb > 0 && usize::max_value() / nmemb < size {
        set_errno(Errno(ENOMEM));
        return ptr::null_mut();
    }

    unsafe { realloc(optr, size * nmemb) }
}
