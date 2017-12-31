/*
 * Copyright (C) 2017 Max Fierke <max@maxfierke.com> (Darwin)
 *
 * Based on FreeBSD implementation:
 * Copyright (C) 2014 Christian Heckendorf <heckendorfc@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifdef __APPLE__

#include "darwin.h"
#include "../platform.h"
#include "../../reptyr.h"
#include "../../ptrace.h"

struct kinfo_proc* get_proc_info(unsigned int req, pid_t pid, unsigned int* cnt) {
    struct kinfo_proc *kp;
    size_t length;

    int mib[4] = { CTL_KERN, KERN_PROC, req, pid };
    if (sysctl(mib, 4, NULL, &length, NULL, 0) < 0) {
        perror("Could not call sysctl");
        return 0;
    }
    kp = (struct kinfo_proc *) malloc(length);

    if (sysctl(mib, 4, kp, &length, NULL, 0) < 0) {
        free(kp);
        return 0;
    }
    *cnt = length / sizeof(struct kinfo_proc);

    return kp;
}

void check_ptrace_scope(void) {
}

int check_pgroup(pid_t target) {
    unsigned int cnt;

    pid_t pg = getpgid(target);
    struct kinfo_proc *kp = get_proc_info(KERN_PROC_PGRP, pg, &cnt);
    free(kp);

    if (cnt > 1) {
        error("Process %d shares a process group with %d other processes. Unable to attach.\n", target, cnt - 1);
        return EINVAL;
    }

    return 0;
}

int check_proc_stopped(pid_t pid, int fd) {
    int state;
    unsigned int cnt;

    struct kinfo_proc *kp = get_proc_info(KERN_PROC_PID, pid, &cnt);

    if (cnt > 0) {
        state = kp->kp_proc.p_stat;
    }

    free(kp);

    if (cnt < 1)
        return 1;


    if (state == SSTOP)
        return 1;

    return 0;
}

int *get_child_tty_fds(struct ptrace_child *child, int statfd, int *count) {
    unsigned int cnt;
    struct fd_array fds = {};
    int fd = NODEV;

    struct kinfo_proc *kp = get_proc_info(KERN_PROC_PID, child->pid, &cnt);

    for (int i = 0; i < cnt; i++) {
        fd = kp[i].kp_eproc.e_tdev;
        if (fd != NODEV && fd_array_push(&fds, fd) != 0) {
            error("Unable to allocate memory for fd array.");
            goto out;
        }
    }

out:
    free(kp);
    *count = fds.n;
    debug("Found %d tty fds in child %d.", fds.n, child->pid);
    return fds.fds;
}

// Find the PID of the terminal emulator for `target's terminal.
//
// We assume that the terminal emulator is the parent of the session
// leader. This is true in most cases, although in principle you can
// construct situations where it is false. We should fail safe later
// on if this turns out to be wrong, however.
int find_terminal_emulator(struct steal_pty_state *steal) {
    struct kinfo_proc *kp;
    unsigned int cnt;

    kp = get_proc_info(KERN_PROC_PID, steal->target_stat.sid, &cnt);

    if (kp && cnt > 0) {
        steal->emulator_pid = kp->kp_eproc.e_ppid;
    }

    free(kp);

    return 0;
}

int get_terminal_state(struct steal_pty_state *steal, pid_t target) {
    unsigned int cnt;
    int err = 0;

    struct kinfo_proc *kp = get_proc_info(KERN_PROC_PID, target, &cnt);

    if (kp == NULL || cnt < 1)
        goto done;

    if (kp->kp_eproc.e_tdev == NODEV) {
        error("Child is not connected to a pseudo-TTY. Unable to steal TTY.");
        err = EINVAL;
        goto done;
    }

    if ((err = find_terminal_emulator(steal)))
        free(kp);
        return err;

done:
    free(kp);
    return err;
}

int find_master_fd(struct steal_pty_state *steal) {
    error("How do I find master in FreeBSD? FIXME.");
    return EINVAL;
}

int get_pt() {
    return posix_openpt(O_RDWR | O_NOCTTY);
}

int get_process_tty_termios(pid_t pid, struct termios *tio) {
    int err = EINVAL;
    unsigned int cnt;
    int fd = NODEV;
    struct kinfo_proc *kp = get_proc_info(KERN_PROC_PGRP, pid, &cnt);

    if (kp && cnt > 0) {
        fd = kp->kp_eproc.e_tdev;

        if (fd != NODEV  && isatty(fd)) {
            if (tcgetattr(fd, tio) < 0) {
                err = -assert_nonzero(errno);
            } else {
                err = 0;
                goto done;
            }
        }
    }
done:
    free(kp);
    return err;
}

void move_process_group(struct ptrace_child *child, pid_t from, pid_t to) {
    unsigned int cnt;
    int err;

    struct kinfo_proc *kp = get_proc_info(KERN_PROC_PGRP, from, &cnt);

    for (int i = 0; i < cnt; i++) {
        debug("Change pgid for pid %d to %d", kp[i].kp_proc.p_pid, to);
        err = do_syscall(child, setpgid, kp[i].kp_proc.p_pid, to, 0, 0, 0, 0);
        if (err < 0)
            error(" failed: %s", strerror(-err));
    }
    free(kp);
}

void copy_user(struct ptrace_child *d, struct ptrace_child *s) {
    memcpy(&d->thread_state, &s->thread_state, sizeof(s->thread_state));
}

#endif
