extern crate libc;

use libc::{
  c_char,
  c_int,
  c_ulong,
  c_void,
  dev_t,
  free,
  PATH_MAX,
  pid_t,
  sockaddr,
  sockaddr_un,
  uid_t
};
use std::mem::{size_of};
use std::ptr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;

use ptrace::{ptrace_child};
use xreallocarray;

const TASK_COMM_LENGTH: usize = 16;

#[repr(C)]
pub struct fd_array {
    fds: *mut c_int,
    n: c_int,
    allocated: c_int
}

#[repr(C)]
pub struct proc_stat {
    pid: pid_t,
    comm: [c_char; TASK_COMM_LENGTH+1],
    state: c_char,
    ppid: pid_t,
    sid: pid_t,
    pgid: pid_t,
    ctty: dev_t
}

#[repr(C)]
union SockAddrUnion {
  addr: sockaddr,
  addr_un: sockaddr_un
}

#[repr(C)]
pub struct steal_pty_state {
    target_stat: proc_stat,

    emulator_pid: pid_t,
    emulator_uid: uid_t,

    master_fds: fd_array,

    tmpdir: [c_char; PATH_MAX as usize],
    sa: SockAddrUnion,
    sockfd: c_int,

    child: ptrace_child,
    child_scratch: c_ulong,
    child_fd: c_int,

    ptyfd: c_int
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