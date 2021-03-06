/*
 * Copyright (C) 2011 by Nelson Elhage
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

#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef __APPLE__
#error "reptyr does not currently support macOS"
#endif

#include "linux/linux.h"
#include "freebsd/freebsd.h"
#include "../ptrace.h"

struct fd_array {
    int *fds;
    int n;
    int allocated;
};
extern int fd_array_push(struct fd_array *fda, int fd);

#define TASK_COMM_LENGTH 16
struct proc_stat {
    pid_t pid;
    char comm[TASK_COMM_LENGTH+1];
    char state;
    pid_t ppid, sid, pgid;
    dev_t ctty;
};

struct steal_pty_state {
    struct proc_stat target_stat;

    pid_t emulator_pid;
    uid_t emulator_uid;

    struct fd_array master_fds;

    char tmpdir[PATH_MAX];
    union {
        struct sockaddr addr;
        struct sockaddr_un addr_un;
    };
    int sockfd;

    struct ptrace_child child;
    child_addr_t child_scratch;
    int child_fd;

    int ptyfd;
};

extern void check_ptrace_scope(void);
extern int check_pgroup(pid_t target);
extern int check_proc_stopped(pid_t pid, int fd);
extern int *get_child_tty_fds(struct ptrace_child *child, int statfd, int *count);
extern int get_terminal_state(struct steal_pty_state *steal, pid_t target);
extern int find_master_fd(struct steal_pty_state *steal);
extern int get_pt();
extern int get_process_tty_termios(pid_t pid, struct termios *tio);
extern void move_process_group(struct ptrace_child *child, pid_t from, pid_t to);
extern void copy_user(struct ptrace_child *d, struct ptrace_child *s);

#endif
