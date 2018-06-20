extern crate libc;
extern crate nix;
extern crate procinfo;

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
  atoi,
  c_char,
  c_int,
  c_ulong,
  c_void,
  close,
  closedir,
  DIR,
  EINVAL,
  ENOMEM,
  ENOTTY,
  ESRCH,
  getpgid,
  isatty,
  major,
  minor,
  makedev,
  memchr,
  memcpy,
  O_NOCTTY,
  O_RDONLY,
  O_RDWR,
  open,
  opendir,
  PATH_MAX,
  pid_t,
  read,
  readdir,
  snprintf,
  sscanf,
  stat,
  strerror,
  strlen,
  strncmp,
  strtol,
  tcgetattr,
  termios,
  uid_t
};
use std::fs::File;
use std::io::Error;
use std::io::prelude::*;
use std::mem;
use std::ptr;

// From #include <linux/major.h>
// Defined as UNIX98_PTY_MASTER_MAJOR + UNIX98_PTY_MAJOR_COUNT
const UNIX98_PTY_SLAVE_MAJOR: u32 = 128 + 8;

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

#[no_mangle]
pub extern fn read_proc_stat(pid: pid_t, out: &mut proc_stat) -> Result<proc_stat, Error> {
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

#[no_mangle]
pub unsafe extern fn read_uid(pid: pid_t, out: *mut uid_t) -> c_int {
    let buf = ['\0' as c_char; 1024];
    let mut p = buf.as_ptr() as *mut i8;
    let stat_path = ['\0' as c_char; PATH_MAX as usize];
    let statfd: c_int;
    let err: c_int = 0;

    snprintf(
        stat_path.as_ptr() as *mut i8,
        PATH_MAX as usize,
        cstr!("/proc/%d/status"),
        pid
    );

    statfd = open(stat_path.as_ptr() as *mut i8, O_RDONLY);
    if statfd < 0 {
        error(cstr!("Unable to open %s: %s"), stat_path, strerror(errno().0));
        return -statfd;
    }

    let n = read(statfd, buf.as_ptr() as *mut c_void, 1024);

    if n < 0 {
        close(statfd);
        return assert_nonzero!(errno().0);
    }

    while *p < *buf.as_ptr().offset(n) {
        if strncmp(p, cstr!("Uid:\t"), strlen(cstr!("Uid:\t"))) == 0 {
            break;
        }
        p = memchr(
            p as *const c_void,
            '\n' as c_int,
            (*buf.as_ptr().offset(n) - *p) as usize
        ) as *mut i8;
        if p.is_null() {
            break;
        }
        *p += 1;
    }

    if p.is_null() || *p >= *buf.as_ptr().offset(n) {
        debug(cstr!("Unable to parse emulator uid: no Uid line found"));
        *out = u32::max_value();
        close(statfd);
        return err;
    }
    if sscanf(p, cstr!("Uid:\t%d"), out) < 0 {
        debug(cstr!("Unable to parse emulator uid: unparseable Uid line"));
    }

    close(statfd);
    return err;
}

#[no_mangle]
pub unsafe extern fn check_pgroup(target: pid_t) -> c_int {
    let mut p = ptr::null::<c_char>() as *mut c_char;
    let mut err: c_int = 0;
    let mut pid_stat: proc_stat = Default::default();

    debug(cstr!("Checking for problematic process group members..."));

    let pg: pid_t = getpgid(target);
    if pg < 0 {
        error(cstr!("Unable to get pgid for pid %d"), target as c_int);
        return errno().0;
    }

    let dir: *mut DIR = opendir(cstr!("/proc/"));

    if dir.is_null() {
        return assert_nonzero!(errno().0);
    }

    let mut d = readdir(dir);

    while !d.is_null() {
        if (*d).d_name[0] == ('.' as i8) {
            d = readdir(dir);
            continue;
        }

        let pid = strtol((*d).d_name.as_ptr(), &mut p as *mut *mut c_char, 10);

        if p.is_null() || (*p) != 0 || pid == target.into() {
            // Noop
        } else if getpgid(pid as i32) == pg {
            /*
             * We are actually being somewhat overly-conservative here
             * -- if pid is a child of target, and has not yet called
             * execve(), reptyr's setpgid() strategy may suffice. That
             * is a fairly rare case, and annoying to check for, so
             * for now let's just bail out.
             */
            if read_proc_stat(pid as i32, &mut pid_stat).is_ok() {
                memcpy(
                    pid_stat.comm.as_ptr() as *mut c_void,
                    cstr!("???") as *mut c_void,
                    4
                );
            }
            error(
                cstr!("Process %d (%.*s) shares %d's process group. Unable to attach.\n(This most commonly means that %d has sub-processes)."),
                pid as c_int,
                TASK_COMM_LENGTH,
                pid_stat.comm,
                target as c_int,
                target as c_int
            );
            err = EINVAL;
            break;
        }

        d = readdir(dir);
    }

    closedir(dir);
    return err;
}

#[no_mangle]
pub unsafe extern fn get_child_tty_fds(child: *mut ptrace_child, _statfd: c_int, count: *mut c_int) -> *mut c_int {
    let mut child_status: proc_stat = Default::default();
    let mut tty_st: stat = mem::zeroed();
    let mut console_st: stat = mem::zeroed();
    let mut st: stat = mem::zeroed();
    let buf = ['\0' as c_char; PATH_MAX as usize];
    let mut fds: fd_array = Default::default();

    debug(cstr!("Looking up fds for tty in child."));

    if let Err(err) = read_proc_stat((*child).pid, &mut child_status) {
        (*child).error = err.raw_os_error().unwrap();
        return 0 as *mut c_int;
    } else {
        (*child).error = 0;
    }

    debug(cstr!("Resolved child tty: %x"), child_status.ctty);

    if stat(cstr!("/dev/tty"), &mut tty_st) < 0 {
        (*child).error = assert_nonzero!(errno().0);
        error(cstr!("Unable to stat /dev/tty"));
        return 0 as *mut c_int;
    }

    if stat(cstr!("/dev/console"), &mut console_st) < 0 {
        error(cstr!("Unable to stat /dev/console"));
        console_st.st_rdev = u64::max_value();
    }

    snprintf(
        buf.as_ptr() as *mut i8,
        PATH_MAX as usize,
        cstr!("/proc/%d/fd/"),
        (*child).pid
    );


    let dir: *mut DIR = opendir(buf.as_ptr() as *mut i8);

    if dir.is_null() {
        assert_nonzero!(errno().0);
        return 0 as *mut c_int;
    }

    let mut d = readdir(dir);

    while !d.is_null() {
        if (*d).d_name[0] == ('.' as i8) {
            d = readdir(dir);
            continue;
        }

        snprintf(
            buf.as_ptr() as *mut i8,
            PATH_MAX as usize,
            cstr!("/proc/%d/fd/%s"),
            (*child).pid,
            (*d).d_name
        );

        if stat(buf.as_ptr(), &mut st) < 0 {
            d = readdir(dir);
            continue;
        }

        if st.st_rdev == child_status.ctty ||
           st.st_rdev == tty_st.st_rdev ||
           st.st_rdev == console_st.st_rdev {
            debug(cstr!("Found an alias for the tty: %s"), &(*d).d_name as *const c_char);
            if fd_array_push(&mut fds, atoi(&(*d).d_name as *const c_char)) != 0 {
                (*child).error = assert_nonzero!(errno().0);
                error(cstr!("Unable to allocate memory for fd array."));
                break;
            }
        }

        d = readdir(dir);
    }

    *count = fds.n;
    closedir(dir);
    return fds.fds;
}

// Find the PID of the terminal emulator for `target's terminal.
//
// We assume that the terminal emulator is the parent of the session
// leader. This is true in most cases, although in principle you can
// construct situations where it is false. We should fail safe later
// on if this turns out to be wrong, however.
#[no_mangle]
pub unsafe extern fn find_terminal_emulator(steal: *mut steal_pty_state) -> c_int {
    debug(
        cstr!("session leader of pid %d = %d"),
        (*steal).target_stat.pid as c_int,
        (*steal).target_stat.sid as c_int
    );
    let parent_pid = (*steal).target_stat.sid;
    let leader_st = match procinfo::pid::stat(parent_pid) {
        Err(err) => return err.raw_os_error().unwrap(),
        Ok(stat) => stat,
    };

    debug(cstr!("found terminal emulator process: %d"), leader_st.ppid as c_int);

    (*steal).emulator_pid = leader_st.ppid;

    0
}

#[no_mangle]
pub extern fn check_proc_stopped(pid: pid_t, _fd: c_int) -> c_int {
    let st = match procinfo::pid::stat(pid) {
        Err(_) => return 1,
        Ok(stat) => stat,
    };

    if st.state == procinfo::pid::State::TraceStopped {
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

    let mut err = find_terminal_emulator(steal);

    if err != 0 {
        return err;
    }

    err = read_uid((*steal).emulator_pid, &mut (*steal).emulator_uid);

    err
}

// Find the fd(s) in the terminal emulator process that corresponds to
// the master side of the target's pty. Store the result in
// steal->master_fds.
#[no_mangle]
pub unsafe extern fn find_master_fd(steal: *mut steal_pty_state) -> c_int {
    let mut st: stat = mem::zeroed();
    let buf = ['\0' as c_char; PATH_MAX as usize];

    snprintf(
        buf.as_ptr() as *mut i8,
        PATH_MAX as usize,
        cstr!("/proc/%d/fd/"),
        (*steal).child.pid
    );

    let dir: *mut DIR = opendir(buf.as_ptr() as *mut i8);

    if dir.is_null() {
        assert_nonzero!(errno().0);
        return 0;
    }

    let mut d = readdir(dir);

    // from original source:
    // ptmx(4) and Linux Documentation/devices.txt document
    // /dev/ptmx has having major 5 and minor 2. I can't find any
    // constants in headers after a brief glance that I should be
    // using here.
    let ptmx_device = makedev(5, 2);

    while !d.is_null() {
        if (*d).d_name[0] == ('.' as i8) {
            d = readdir(dir);
            continue;
        }

        debug(cstr!("checking fd to see if it's ptmx: %s"), (*d).d_name.as_ptr());

        snprintf(
            buf.as_ptr() as *mut i8,
            PATH_MAX as usize,
            cstr!("/proc/%d/fd/%s"),
            (*steal).child.pid,
            (*d).d_name.as_ptr()
        );

        if stat(buf.as_ptr(), &mut st) < 0 {
            debug(cstr!("Couldn't stat. Skipping to the next FD."));
            d = readdir(dir);
            continue;
        }

        debug(
            cstr!("Checking fd: %s: st_dev=%x"),
            (*d).d_name.as_ptr(),
            st.st_rdev as c_int
        );

        if st.st_rdev != ptmx_device {
            debug(cstr!("Not a ptmx. Skipping to the next FD."));
            d = readdir(dir);
            continue;
        }


        debug(cstr!("found a ptmx fd: %s"), (*d).d_name.as_ptr());

        let child = &mut (*steal).child;
        let syscalls = &*ptrace_syscall_numbers(child as *mut ptrace_child);

        // TODO: use the ioctls crate or something instead of this magic number
        const TIOCGPTN: u64 = 0x80045430;

        let tty_id = atoi((*d).d_name.as_ptr());
        let mut err = ptrace_remote_syscall(
            child,
            syscalls.nr_ioctl as u64,
            tty_id as u64,
            TIOCGPTN,
            (*steal).child_scratch,
            0,
            0,
            0
        );

        if err < 0 {
            debug(cstr!("Error doing TIOCGPTN: %s"), strerror(-err as i32));
            d = readdir(dir);
            continue;
        }

        debug(cstr!("TIOCGPTN succeeded."));

        let mut ptn: c_int = mem::zeroed();

        err = ptrace_memcpy_from_child(
            child,
            &mut ptn as *mut c_int as *mut c_void,
            (*steal).child_scratch,
            mem::size_of::<c_int>()
        ).into();

        if err < 0 {
            debug(cstr!(" error getting ptn: %s"), strerror(child.error));
            d = readdir(dir);
            continue;
        }

        if ptn == minor((*steal).target_stat.ctty) as c_int {
            debug(cstr!("found a master fd: %d"), tty_id);
            if fd_array_push(&mut (*steal).master_fds, tty_id) != 0 {
                error(cstr!("unable to allocate memory for fd array!"));
                return ENOMEM;
            }
        }

        d = readdir(dir);
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
pub unsafe extern fn move_process_group(child: *mut ptrace_child, from: pid_t, to: pid_t) -> () {
    let mut p = ptr::null::<c_char>() as *mut c_char;
    let dir: *mut DIR = opendir(cstr!("/proc/"));

    if dir.is_null() {
        return;
    }

    let mut d = readdir(dir);

    while !d.is_null() {
        if (*d).d_name[0] == ('.' as i8) {
            d = readdir(dir);
            continue;
        }

        let pid = strtol((*d).d_name.as_ptr(), &mut p as *mut *mut c_char, 10);

        if p.is_null() || (*p) != 0 {
            // Noop
        } else if getpgid(pid as i32) == from {
            debug(cstr!("Change pgid for pid %d"), pid);
            let syscalls = &*ptrace_syscall_numbers(child as *mut ptrace_child);

            let err = ptrace_remote_syscall(
                child,
                syscalls.nr_setpgid as u64,
                pid as u64,
                to as u64,
                0,
                0,
                0,
                0
            );

            if err < 0 {
                error(cstr!(" failed: %s"), strerror(-err as i32));
            }
        }

        d = readdir(dir);
    }

    closedir(dir);
}

#[no_mangle]
pub unsafe extern fn copy_user(dest: *mut ptrace_child, src: *mut ptrace_child) -> () {
    memcpy(
        &mut (*dest).user as *mut libc::user as *mut c_void,
        &(*src).user as *const libc::user as *const c_void,
        mem::size_of::<libc::user>()
    );

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
