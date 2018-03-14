/*
 * Copyright (C) 2011 by Nelson Elhage
 * Copyright (C) 2017 by Max Fierke
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

#include "../../../ptrace.h"
#include "../darwin.h"

#define ptr(user, off) ((unsigned long*)((void*)(user)+(off)))

struct x86_personality {
    size_t ax;
};

struct x86_personality x86_personality[];

static inline struct x86_personality *x86_pers(struct ptrace_child *child) {
    return &x86_personality[child->personality];
}

static inline thread_act_port_array_t _get_threads(struct ptrace_child *child) {
    kern_return_t err;
    thread_act_port_array_t threads;
    mach_msg_type_number_t thread_length;

    err = task_threads(child->task_port, &threads, &thread_length);
    if (err) {
        fprintf(stderr, "Could not retrieve threads for mach task. Errno %d\n", err);
        exit(err);
    }

    return threads;
}

static inline int arch_get_regs(struct ptrace_child *child) {
    kern_return_t err;
    thread_act_port_array_t threads = _get_threads(child);

    mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
    err = thread_get_state(threads[0], x86_THREAD_STATE64, (thread_state_t) &child->thread_state, &state_count);
    if (err) {
        fprintf(stderr, "Could not retrieve state of main thread. Errno %d\n", err);
        return err;
    }

    return 0;
}

static inline int arch_set_regs(struct ptrace_child *child) {
    kern_return_t err;
    thread_act_port_array_t threads = _get_threads(child);

    err = thread_set_state(threads[0], x86_THREAD_STATE64, (thread_state_t) &child->thread_state, x86_THREAD_STATE64_COUNT);
    if (err) {
        fprintf(stderr, "Could not set state of main thread. Errno %d\n", err);
        return err;
    }

    return 0;
}

static inline void arch_fixup_regs(struct ptrace_child *child) {
    struct x86_personality *x86pers = x86_pers(child);
    struct ptrace_personality *pers = personality(child);
    *ptr(&child->thread_state, pers->reg_ip) -= 2;
    *ptr(&child->thread_state, x86pers->ax) = child->saved_syscall;
    //https://lists.freebsd.org/pipermail/freebsd-hackers/2009-July/029206.html
}

static inline unsigned long arch_get_register(struct ptrace_child *child, unsigned long oft) {
    return *ptr(&child->thread_state, oft);
}

static inline void arch_set_register(struct ptrace_child *child, unsigned long oft, unsigned long val){
    *ptr(&child->thread_state, oft) = val;
}

static inline int arch_save_syscall(struct ptrace_child *child) {
    child->saved_syscall = *ptr(&child->thread_state, x86_pers(child)->ax);
    return 0;
}

static inline int arch_get_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    return *ptr(&child->thread_state, personality(child)->syscall_rv);
}

static inline int arch_restore_syscall(struct ptrace_child *child) {
    return 0;
}

#undef ptr
