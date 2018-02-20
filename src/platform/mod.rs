extern crate libc;

use libc::{c_int, c_void, free};
use std::mem::{size_of};
use std::ptr;

use xreallocarray;

#[repr(C)]
pub struct fd_array {
    fds: *mut c_int,
    n: c_int,
    allocated: c_int
}

#[no_mangle]
pub extern fn fd_array_push(fda: *mut fd_array, fd: c_int) -> c_int {
    unsafe {
        if (*fda).n == (*fda).allocated {
            (*fda).allocated = if (*fda).allocated > 0 {
                2 * (*fda).allocated
            } else {
                2
            };

            let tmp = xreallocarray(
              (*fda).fds as *mut c_void,
              (*fda).allocated as usize,
              size_of::<c_int>()
            ) as *mut c_int;

            if tmp.is_null() {
                free((*fda).fds as *mut c_void);
                (*fda).fds = ptr::null_mut();
                (*fda).allocated = 0;
                return -1;
            }
            (*fda).fds = tmp;
        }

        let cur_fd_slot = (*fda).fds.offset((*fda).n as isize) as *mut c_int;
        *cur_fd_slot = fd;
        (*fda).n += 1;
    }

    0
}
