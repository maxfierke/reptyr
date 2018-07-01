extern crate libc;

use libc::c_void;
use libc::{
  c_int,
  c_long,
  c_ulong,
  pid_t,
  user
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum child_state {
    ptrace_detached = 0,
    ptrace_at_syscall,
    ptrace_after_syscall,
    ptrace_running,
    ptrace_stopped,
    ptrace_exited
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ptrace_child {
    pub pid: pid_t,
    pub state: child_state,
    pub personality: c_int,
    pub status: c_int,
    pub error: c_int,
    pub forked_pid: c_ulong,
    pub saved_syscall: c_ulong,
    #[cfg(target_os = "linux")]
    pub user: user
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct syscall_numbers {
    pub nr_mmap: c_long,
    pub nr_mmap2: c_long,
    pub nr_munmap: c_long,
    pub nr_getsid: c_long,
    pub nr_setsid: c_long,
    pub nr_setpgid: c_long,
    pub nr_fork: c_long,
    pub nr_wait4: c_long,
    pub nr_signal: c_long,
    pub nr_rt_sigaction: c_long,
    pub nr_open: c_long,
    pub nr_close: c_long,
    pub nr_ioctl: c_long,
    pub nr_dup2: c_long,
    pub nr_socket: c_long,
    pub nr_connect: c_long,
    pub nr_sendmsg: c_long,
    pub nr_socketcall: c_long
}

extern {
    pub fn ptrace_finish_attach(child: *mut ptrace_child, pid: pid_t) -> c_int;
    pub fn ptrace_remote_syscall(
        child: *mut ptrace_child,
        sysno: c_ulong,
        p0: c_ulong, p1: c_ulong,
        p2: c_ulong, p3: c_ulong,
        p4: c_ulong, p5: c_ulong
    ) -> c_long;
    pub fn ptrace_syscall_numbers(child: *mut ptrace_child) -> *mut syscall_numbers;
    pub fn ptrace_memcpy_from_child(
        child: *mut ptrace_child,
        dst: *mut c_void,
        src: c_ulong,
        size: usize
    ) -> c_int;
    pub fn ptrace_memcpy_to_child(
        child: *mut ptrace_child,
        from: c_ulong,
        to: *mut c_void,
        size: usize
    ) -> c_int;
}
