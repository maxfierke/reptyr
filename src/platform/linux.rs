extern crate libc;

use ptrace::{
    ptrace_memcpy_from_child,
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
  c_void,
  close,
  closedir,
  DIR,
  EINVAL,
  EOF,
  ENOMEM,
  ESRCH,
  getpgid,
  lseek,
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
  SEEK_SET,
  snprintf,
  sscanf,
  stat,
  strerror,
  strlen,
  strncmp,
  strtol,
  uid_t
};
use std::fs::File;
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
pub unsafe extern fn parse_proc_stat(statfd: c_int, out: *mut proc_stat) -> c_int {
    let buf: [c_char; 1024] = ['\0' as c_char; 1024];
    let dev: u64 = 0;

    lseek(statfd, 0, SEEK_SET);
    if read(statfd, buf.as_ptr() as *mut c_void, 1024) < 0 {
        return assert_nonzero!(errno().0);
    }

    let n = sscanf(&buf as *const i8,
        cstr!("%d (%16[^)]) %c %d %d %d %hu"),
        &(*out).pid,
        (*out).comm.as_ptr(),
        &(*out).state,
        &(*out).ppid,
        &(*out).pgid,
        &(*out).sid,
        &dev
    );

    if n == EOF {
        return assert_nonzero!(errno().0);
    }
    if n != 7 {
        return EINVAL;
    }
    (*out).ctty = dev;

    return 0;
}

#[no_mangle]
pub unsafe extern fn read_proc_stat(pid: pid_t, out: *mut proc_stat) -> c_int {
    let stat_path = ['\0' as c_char; PATH_MAX as usize];
    let statfd: c_int;
    let err: c_int;

    snprintf(
        stat_path.as_ptr() as *mut i8,
        PATH_MAX as usize,
        cstr!("/proc/%d/stat"),
        pid
    );
    statfd = open(stat_path.as_ptr() as *mut i8, O_RDONLY);
    if statfd < 0 {
        error(cstr!("Unable to open %s: %s"), stat_path, strerror(errno().0));
        return -statfd;
    }
    err = parse_proc_stat(statfd, out);

    close(statfd);
    return err;
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

        if p.is_null() {
            // Noop
        } else if (*p) != 0 {
            // Noop
        } else if pid == target.into() {
            // Noop
        } else if getpgid(pid as i32) == pg {
            /*
             * We are actually being somewhat overly-conservative here
             * -- if pid is a child of target, and has not yet called
             * execve(), reptyr's setpgid() strategy may suffice. That
             * is a fairly rare case, and annoying to check for, so
             * for now let's just bail out.
             */
            if read_proc_stat(pid as i32, &mut pid_stat as *mut proc_stat) != 0 {
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
pub unsafe extern fn get_child_tty_fds(child: *mut ptrace_child, statfd: c_int, count: *mut c_int) -> *mut c_int {
    let mut child_status: proc_stat = Default::default();
    let mut tty_st: stat = mem::zeroed();
    let mut console_st: stat = mem::zeroed();
    let mut st: stat = mem::zeroed();
    let buf = ['\0' as c_char; PATH_MAX as usize];
    let mut fds: fd_array = Default::default();

    debug(cstr!("Looking up fds for tty in child."));

    (*child).error = parse_proc_stat(statfd, &mut child_status);

    if (*child).error != 0 {
        return 0 as *mut c_int;
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
    let mut leader_st: proc_stat = Default::default();

    let err = read_proc_stat((*steal).target_stat.sid, &mut leader_st as *mut proc_stat);

    if err != 0 {
        return err;
    }

    debug(cstr!("found terminal emulator process: %d"), leader_st.ppid as c_int);

    (*steal).emulator_pid = leader_st.ppid;

    0
}

#[no_mangle]
pub unsafe extern fn check_proc_stopped(_pid: pid_t, fd: c_int) -> c_int {
    let mut st: proc_stat = Default::default();

    if parse_proc_stat(fd, &mut st) != 0 {
        return 1;
    }

    if (st.state as u8 as char) == 'T' {
        return 1;
    }

    return 0;
}

#[no_mangle]
pub unsafe extern fn get_terminal_state(steal: *mut steal_pty_state, target: pid_t) -> c_int {
    let mut err = read_proc_stat(target, &mut (*steal).target_stat);

    if err != 0 {
        return err;
    }

    if major((*steal).target_stat.ctty) != UNIX98_PTY_SLAVE_MAJOR {
        error(cstr!("Child is not connected to a pseudo-TTY. Unable to steal TTY."));
        return EINVAL;
    }

    err = find_terminal_emulator(steal);

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
