extern crate libc;
extern crate nix;

use libc::{
  c_int,
  c_long,
  c_void,
  pid_t
};
use ptrace::{
  child_state,
  ptrace_child,
  ptrace_finish_attach
};
use self::nix::Error::{
  Sys
};
#[allow(deprecated)]
use self::nix::sys::ptrace::{
  attach,
  cont,
  detach,
  getevent,
  Options,
  ptrace,
  Request,
  setoptions,
  step,
  syscall,
  traceme
};
use self::nix::sys::signal::{
  Signal
};
use self::nix::unistd::{
    Pid
};
use std::mem;
use std::ptr;

#[no_mangle]
pub extern fn ptrace_attach_child(child: *mut ptrace_child, pid: pid_t) -> c_int {
  unsafe {
    (*child) = mem::zeroed();
    (*child).pid = pid;
  }

  if __ptrace_command(child, Request::PTRACE_ATTACH, ptr::null_mut(), ptr::null_mut()) < 0 {
    return -1;
  }

  unsafe { ptrace_finish_attach(child, pid) }
}

#[no_mangle]
pub extern fn ptrace_detach_child(child: *mut ptrace_child) -> c_int {
  if __ptrace_command(child, Request::PTRACE_DETACH, ptr::null_mut(), ptr::null_mut()) < 0 {
    return -1;
  }

  unsafe {
    (*child).state = child_state::ptrace_detached;
  };

  0
}

#[no_mangle]
#[allow(deprecated)]
pub extern fn __ptrace_command(
  child: *mut ptrace_child,
  req: Request,
  addr: *mut c_void,
  data: *mut c_void
) -> c_long {
  let pid = Pid::from_raw(unsafe { (*child).pid });

  let ptrace_result = match req {
    Request::PTRACE_ATTACH => attach(pid).map(|_| 0),
    Request::PTRACE_CONT => {
      let sig = Signal::from_c_int(data as i32).unwrap();
      cont(pid, sig).map(|_| 0)
    },
    Request::PTRACE_DETACH => detach(pid).map(|_| 0),
    Request::PTRACE_GETEVENTMSG => getevent(pid),
    Request::PTRACE_SETOPTIONS => setoptions(
      pid,
      Options::from_bits_truncate(data as i32)
    ).map(|_| 0),
    Request::PTRACE_SINGLESTEP => {
      let sig = Signal::from_c_int(data as i32).unwrap();
      step(pid, sig).map(|_| 0)
    },
    Request::PTRACE_SYSCALL => syscall(pid).map(|_| 0),
    Request::PTRACE_TRACEME => traceme().map(|_| 0),
    _ => unsafe { ptrace(req, pid, addr, data) }
  };


  match ptrace_result {
    Err(Sys(errno)) => {
      unsafe { (*child).error = errno as i32; }
      -1
    },
    Err(_) => {
      unsafe { (*child).error = 0; }
       -1
    },
    Ok(ret) => ret
  }
}
