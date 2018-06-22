extern crate libc;
extern crate nix;
extern crate procinfo;
extern crate walkdir;

use ptrace::{
    ptrace_memcpy_from_child,
    ptrace_memcpy_to_child,
    ptrace_remote_syscall,
    ptrace_syscall_numbers
};
use errno::errno;
use error;
use debug;
use platform::{
    fd_array,
    fd_array_push,
    proc_stat,
    steal_pty_state,
    TASK_COMM_LENGTH
};
use ptrace::ptrace_child;
use libc::{
  c_char,
  c_int,
  c_ulong,
  c_void,
  close,
  EINVAL,
  ENOMEM,
  ENOTTY,
  ESRCH,
  getpgid,
  isatty,
  major,
  minor,
  makedev,
  memcpy,
  O_NOCTTY,
  O_RDONLY,
  O_RDWR,
  open,
  PATH_MAX,
  pid_t,
  snprintf,
  tcgetattr,
  termios,
};
use std::fs::File;
use std::io::Error;
use std::io::prelude::*;
use std::{mem, str};
use self::walkdir::{DirEntry, WalkDir};

// From #include <linux/major.h>
// Defined as UNIX98_PTY_MASTER_MAJOR + UNIX98_PTY_MAJOR_COUNT
const UNIX98_PTY_SLAVE_MAJOR: u32 = 128 + 8;

fn is_hidden(entry: &DirEntry) -> bool {
    entry.file_name()
         .to_str()
         .map(|s| s.starts_with("."))
         .unwrap_or(false)
}

fn is_depth_one(entry: &DirEntry) -> bool {
    entry.depth() <= 1
}

#[no_mangle]
pub extern fn check_ptrace_scope() -> () {
    let mut f = match File::open("/proc/sys/kernel/yama/ptrace_scope") {
      Err(_) => return,
      Ok(f) => f
    };

    let mut contents = String::new();
    f.read_to_string(&mut contents).unwrap();

    match contents.parse::<i32>() {
      Ok(n) => if n == 0 { return }
      Err(_) => return
    }

    eprintln!("The kernel denied permission while attaching. If your uid matches");
    eprintln!("the target's, check the value of /proc/sys/kernel/yama/ptrace_scope.");
    eprintln!("For more information, see /etc/sysctl.d/10-ptrace.conf");
}

pub fn read_proc_stat(pid: pid_t, out: &mut proc_stat) -> Result<proc_stat, Error> {
    let process_proc_stat = match procinfo::pid::stat(pid) {
        Err(err) => return Err(err),
        Ok(stat) => stat,
    };

    // TODO: Do this less gross. Macro maybe?
    let mut command = process_proc_stat.command.into_bytes();
    command.resize(TASK_COMM_LENGTH+1, 0);
    let mut comm: [u8; TASK_COMM_LENGTH+1] = Default::default();
    comm.copy_from_slice(command.as_slice());
    comm[TASK_COMM_LENGTH] = '\0' as u8;

    out.pid = process_proc_stat.pid;
    out.comm = comm;
    out.state = process_proc_stat.state as u8;
    out.ppid = process_proc_stat.ppid;
    out.pgid = process_proc_stat.pgrp;
    out.sid = process_proc_stat.session;
    out.ctty = process_proc_stat.tty_nr as u64;

    Ok(*out)
}

pub fn read_uid(pid: pid_t) -> Result<u32, Error> {
    let status = match procinfo::pid::status(pid) {
        Err(err) => {
            // FIXME: This doesn't _seem_ right, but it seems to mirror the C
            // functionality & behavior, so revisit if there's something funky
            reptyr_debug!("Unable to parse emulator uid: no Uid line found");
            return Err(err);
        },
        Ok(st) => st
    };

    Ok(status.uid_real)
}

#[no_mangle]
pub extern fn check_pgroup(target: pid_t) -> c_int {
    let mut err: c_int = 0;
    let mut pid_stat: proc_stat = Default::default();

    reptyr_debug!("Checking for problematic process group members...");

    let pg: pid_t = unsafe { getpgid(target) };
    if pg < 0 {
        reptyr_error!("Unable to get pgid for pid {}", target);
        return errno().0;
    }

    let proc_dir = WalkDir::new("/proc/").into_iter()
        .filter_entry(|e| is_depth_one(e) && !is_hidden(e))
        .filter_map(|e| e.ok());
    for proc_entry in proc_dir {
        let pid = proc_entry.file_name().to_str().unwrap().parse::<i32>().unwrap_or(-1);

        if pid != target.into() && unsafe { getpgid(pid) } == pg {
            /*
             * We are actually being somewhat overly-conservative here
             * -- if pid is a child of target, and has not yet called
             * execve(), reptyr's setpgid() strategy may suffice. That
             * is a fairly rare case, and annoying to check for, so
             * for now let's just bail out.
             */
            if read_proc_stat(pid, &mut pid_stat).is_ok() {
                unsafe {
                    memcpy(
                        pid_stat.comm.as_ptr() as *mut c_void,
                        cstr!("???") as *mut c_void,
                        4
                    );
                }
            }
            reptyr_error!(
                "Process {} ({}) shares {}'s process group. Unable to attach.\n(This most commonly means that {} has sub-processes).",
                pid as c_int,
                str::from_utf8(&pid_stat.comm).unwrap_or("NOCOMM"),
                target as c_int,
                target as c_int
            );
            err = EINVAL;
            break;
        }
    }

    return err;
}

#[no_mangle]
pub extern fn get_child_tty_fds(child: *mut ptrace_child, _statfd: c_int, count: *mut c_int) -> *mut c_int {
    let mut child_status: proc_stat = Default::default();
    let mut fds: fd_array = Default::default();
    let pid = unsafe { (*child).pid };

    reptyr_debug!("Looking up fds for tty in child.");

    if let Err(err) = read_proc_stat(pid, &mut child_status) {
        unsafe { (*child).error = err.raw_os_error().unwrap(); }
        return 0 as *mut c_int;
    } else {
        unsafe { (*child).error = 0; }
    }

    reptyr_debug!("Resolved child tty: {}", child_status.ctty);

    let tty_st = match nix::sys::stat::stat("/dev/tty") {
        Err(_) => {
            unsafe { (*child).error = assert_nonzero!(errno().0); };
            reptyr_error!("Unable to stat /dev/tty");
            return 0 as *mut c_int;
        },
        Ok(st) => st
    };

    let console_st = match nix::sys::stat::stat("/dev/console") {
        Err(_) => {
            reptyr_error!("Unable to stat /dev/console");
            let mut st: nix::sys::stat::FileStat = unsafe { mem::zeroed() };
            st.st_rdev = u64::max_value();
            st
        },
        Ok(st) => st
    };

    let proc_dir_path = format!("/proc/{}/fd/", pid);
    let proc_dir = WalkDir::new(proc_dir_path).into_iter()
        .filter_entry(|e| is_depth_one(e) && !is_hidden(e))
        .filter_map(|e| e.ok());
    for proc_entry in proc_dir {
        let fd = proc_entry.file_name().to_str().unwrap().parse::<i32>().unwrap_or(-1);
        let fd_path = proc_entry.path();

        let st = match nix::sys::stat::stat(fd_path) {
            Err(_) => continue,
            Ok(fd_stat) => fd_stat
        };

        if st.st_rdev == child_status.ctty ||
           st.st_rdev == tty_st.st_rdev ||
           st.st_rdev == console_st.st_rdev {
            reptyr_debug!("Found an alias for the tty: {}", fd);
            if fd_array_push(&mut fds, fd) != 0 {
                unsafe {
                    (*child).error = assert_nonzero!(errno().0);
                };
                reptyr_error!("Unable to allocate memory for fd array.");
                break;
            }
        }
    }

    unsafe { *count = fds.n };
    return fds.fds;
}

// Find the PID of the terminal emulator for `target's terminal.
//
// We assume that the terminal emulator is the parent of the session
// leader. This is true in most cases, although in principle you can
// construct situations where it is false. We should fail safe later
// on if this turns out to be wrong, however.
pub fn find_terminal_emulator(
    steal: &mut steal_pty_state
) -> Result<&steal_pty_state, Error> {
    reptyr_debug!("[+] session leader of pid {} = {}",
        steal.target_stat.pid,
        steal.target_stat.sid
    );
    let parent_pid = steal.target_stat.sid;
    let leader_st = match procinfo::pid::stat(parent_pid) {
        Err(err) => return Err(err),
        Ok(stat) => stat,
    };

    reptyr_debug!("[+] found terminal emulator process: {}", leader_st.ppid);

    steal.emulator_pid = leader_st.ppid;

    Ok(steal)
}

#[no_mangle]
pub extern fn check_proc_stopped(pid: pid_t, _fd: c_int) -> c_int {
    let st = match procinfo::pid::stat(pid) {
        Err(_) => return 1,
        Ok(stat) => stat,
    };

    if st.state == procinfo::pid::State::Stopped || st.state == procinfo::pid::State::TraceStopped {
        return 1;
    }

    0
}

#[no_mangle]
pub unsafe extern fn get_terminal_state(steal: *mut steal_pty_state, target: pid_t) -> c_int {
    if let Err(err) = read_proc_stat(target, &mut (*steal).target_stat) {
        return err.raw_os_error().unwrap();
    }

    if major((*steal).target_stat.ctty) != UNIX98_PTY_SLAVE_MAJOR {
        error(cstr!("Child is not connected to a pseudo-TTY. Unable to steal TTY."));
        return EINVAL;
    }

    if let Err(err) = find_terminal_emulator(&mut (*steal)) {
        return err.raw_os_error().unwrap();
    }

    let uid = match read_uid((*steal).emulator_pid) {
        Err(err) => return err.raw_os_error().unwrap_or(0),
        Ok(uid_real) => uid_real
    };

    (*steal).emulator_uid = uid;

    0
}

// Find the fd(s) in the terminal emulator process that corresponds to
// the master side of the target's pty. Store the result in
// steal->master_fds.
#[no_mangle]
pub unsafe extern fn find_master_fd(steal: *mut steal_pty_state) -> c_int {
    // from original source:
    // ptmx(4) and Linux Documentation/devices.txt document
    // /dev/ptmx has having major 5 and minor 2. I can't find any
    // constants in headers after a brief glance that I should be
    // using here.
    let ptmx_device = makedev(5, 2);
    let pid = (*steal).child.pid;
    let proc_dir_path = format!("/proc/{}/fd/", pid);
    let proc_dir = WalkDir::new(proc_dir_path).into_iter()
        .filter_entry(|e| is_depth_one(e) && !is_hidden(e))
        .filter_map(|e| e.ok());
    for proc_entry in proc_dir {
        let file_name = proc_entry.file_name().to_str().unwrap();
        let fd = file_name.parse::<i32>().unwrap_or(-1);
        let fd_path = proc_entry.path();

        let st = match nix::sys::stat::stat(fd_path) {
            Err(_) => {
                reptyr_debug!("Couldn't stat. Skipping to the next FD.");
                continue;
            },
            Ok(fd_stat) => fd_stat
        };

        reptyr_debug!("Checking fd: {}: st_dev={}", fd, st.st_rdev);

        if st.st_rdev != ptmx_device {
            reptyr_debug!("Not a ptmx. Skipping to the next FD.");
            continue;
        }

        reptyr_debug!("found a ptmx fd: {}", fd);

        let child = &mut (*steal).child;
        let syscalls = &*ptrace_syscall_numbers(child as *mut ptrace_child);

        // TODO: use the ioctls crate or something instead of this magic number
        const TIOCGPTN: u64 = 0x80045430;

        let mut err = ptrace_remote_syscall(
            child,
            syscalls.nr_ioctl as u64,
            fd as u64,
            TIOCGPTN,
            (*steal).child_scratch,
            0,
            0,
            0
        );

        if err < 0 {
            reptyr_debug!("Error doing TIOCGPTN: {}", -err as i32);
            continue;
        }

        reptyr_debug!("TIOCGPTN succeeded.");

        let mut ptn: c_int = mem::zeroed();

        err = ptrace_memcpy_from_child(
            child,
            &mut ptn as *mut c_int as *mut c_void,
            (*steal).child_scratch,
            mem::size_of::<c_int>()
        ).into();

        if err < 0 {
            reptyr_debug!(" error getting ptn: {}", child.error);
            continue;
        }

        if ptn == minor((*steal).target_stat.ctty) as c_int {
            reptyr_debug!("found a master fd: {}", fd);
            if fd_array_push(&mut (*steal).master_fds, fd) != 0 {
                reptyr_error!("unable to allocate memory for fd array!");
                return ENOMEM;
            }
        }
    }

    if (*steal).master_fds.n == 0 {
        return ESRCH;
    }

    0
}

/* Homebrew posix_openpt() */
#[no_mangle]
pub unsafe extern fn get_pt() -> c_int {
    open(cstr!("/dev/ptmx"), O_RDWR | O_NOCTTY)
}

#[no_mangle]
pub unsafe extern fn get_process_tty_termios(pid: pid_t, tio: *mut termios) -> c_int {
    let mut err = EINVAL;
    let buf = ['\0' as c_char; PATH_MAX as usize];

    for i in 0..3 {
        if err != 0 {
            err = 0;

            debug(cstr!("checking fd to see if it's ptmx: %s"), i);

            snprintf(
                buf.as_ptr() as *mut i8,
                PATH_MAX as usize,
                cstr!("/proc/%d/fd/%d"),
                pid,
                i
            );

            let fd = open(buf.as_ptr(), O_RDONLY);

            if fd < 0 {
                err = -fd;
            } else if isatty(fd) == 0 {
                err = ENOTTY;
                close(fd);
                break;
            } else if tcgetattr(fd, tio) < 0 {
                err = -assert_nonzero!(errno().0);
            }

            close(fd);
        }
    }

    return err;
}

#[no_mangle]
pub extern fn move_process_group(child: *mut ptrace_child, from: pid_t, to: pid_t) -> () {
    let proc_dir = WalkDir::new("/proc/").into_iter()
        .filter_entry(|e| is_depth_one(e) && !is_hidden(e))
        .filter_map(|e| e.ok());
    for proc_entry in proc_dir {
        let pid = proc_entry.file_name().to_str().unwrap().parse::<i32>().unwrap_or(-1);

        if unsafe { getpgid(pid) } == from {
            reptyr_debug!("Change pgid for pid {}", pid);
            let syscalls = unsafe { &*ptrace_syscall_numbers(child as *mut ptrace_child) };

            let err = unsafe {
                ptrace_remote_syscall(
                    child,
                    syscalls.nr_setpgid as u64,
                    pid as u64,
                    to as u64,
                    0,
                    0,
                    0,
                    0
                )
            };

            if err < 0 {
                reptyr_error!(" failed: {}", -err as i32);
            }
        }
    }
}

#[no_mangle]
pub extern fn copy_user(dest: *mut ptrace_child, src: *mut ptrace_child) -> () {
    unsafe {
        memcpy(
            &mut (*dest).user as *mut libc::user as *mut c_void,
            &(*src).user as *const libc::user as *const c_void,
            mem::size_of::<libc::user>()
        );
    };

    ()
}

#[no_mangle]
pub unsafe extern fn ptrace_socketcall(
    child: *mut ptrace_child,
    scratch: c_ulong,
    socketcall: c_ulong,
    p0: u32,
    p1: u32,
    p2: u32,
    p3: u32,
    p4: u32
) -> u32 {
    // We assume that socketcall is only used on 32-bit
    // architectures. If there are any 64-bit architectures that do
    // socketcall, and we port to them, this will need to change.
    let args = [p0, p1, p2, p3, p4];
    let err = ptrace_memcpy_to_child(
        child,
        scratch,
        args.as_ptr() as *mut c_void,
        mem::size_of_val(&args)
    );

    if err < 0 {
        return err as u32;
    }

    ptrace_remote_syscall(
        child,
        socketcall,
        socketcall,
        scratch,
        0,
        0,
        0,
        0
    ) as u32
}
