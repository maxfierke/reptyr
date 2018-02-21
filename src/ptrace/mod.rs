extern crate libc;

use libc::{
  c_int,
  c_ulong,
  pid_t,
  user
};

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum child_state {
    ptrace_detached = 0,
    ptrace_at_syscall,
    ptrace_after_syscall,
    ptrace_running,
    ptrace_stopped,
    ptrace_exited
}

#[repr(C)]
pub struct ptrace_child {
    pid: pid_t,
    state: child_state,
    personality: c_int,
    status: c_int,
    error: c_int,
    forked_pid: c_ulong,
    saved_syscall: c_ulong,
    #[cfg(target_os = "linux")]
    user: user
}
