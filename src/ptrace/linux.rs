extern crate libc;
extern crate nix;

use libc::{
  c_long,
  c_void
};
use ptrace::{
  ptrace_child
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
use self::nix::sys::signal::Signal;
use self::nix::unistd::{
    Pid
};

#[no_mangle]
#[allow(deprecated)]
pub unsafe extern fn __ptrace_command(
  child: *mut ptrace_child,
  req: Request,
  addr: *mut c_void,
  data: *mut c_void
) -> c_long {
  let pid = Pid::from_raw((*child).pid);

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
    _ => ptrace(req, pid, addr, data)
  };


  match ptrace_result {
    Err(Sys(errno)) => {
      (*child).error = errno as i32;
      -1
    },
    Err(_) => {
      (*child).error = 0;
       -1
    },
    Ok(ret) => ret
  }
}
