extern crate errno;
extern crate libc;

pub mod platform;

use errno::{Errno, set_errno};
use libc::{c_void, ENOMEM, realloc, size_t};
use std::ptr;

#[no_mangle]
pub extern fn xreallocarray(optr: *mut c_void, nmemb: size_t, size: size_t) -> *mut c_void {
    if nmemb > 0 && usize::max_value() / nmemb < size {
        set_errno(Errno(ENOMEM));
        return ptr::null_mut();
    }

    unsafe { realloc(optr, size * nmemb) }
}
