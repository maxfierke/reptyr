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

#include "x86_common.h"

#define ARCH_HAVE_MULTIPLE_PERSONALITIES

static struct ptrace_personality arch_personality[2] = {
    {
        offsetof(x86_thread_state64_t, __rax),
        offsetof(x86_thread_state64_t, __rdi),
        offsetof(x86_thread_state64_t, __rsi),
        offsetof(x86_thread_state64_t, __rdx),
        offsetof(x86_thread_state64_t, __rcx),
        //offsetof(x86_thread_state64_t, __r10),
        offsetof(x86_thread_state64_t, __r8),
        offsetof(x86_thread_state64_t, __r9),
        offsetof(x86_thread_state64_t, __rip),
    },
    {
        offsetof(x86_thread_state64_t, __rax),
        offsetof(x86_thread_state64_t, __rbx),
        offsetof(x86_thread_state64_t, __rcx),
        offsetof(x86_thread_state64_t, __rdx),
        offsetof(x86_thread_state64_t, __rsi),
        offsetof(x86_thread_state64_t, __rdi),
        offsetof(x86_thread_state64_t, __rbp),
        offsetof(x86_thread_state64_t, __rip),
    },
};

struct x86_personality x86_personality[2] = {
    {
        offsetof(x86_thread_state64_t, __rax),
    },
    {
        offsetof(x86_thread_state64_t, __rax),
    },
};

struct syscall_numbers arch_syscall_numbers[2] = {
#include "default-syscalls.h"
#include "default-syscalls.h"
};

int arch_get_personality(struct ptrace_child *child) {
    unsigned long cs;

    cs = arch_get_register(child, offsetof(x86_thread_state64_t, __cs));
    if (child->error)
        return -1;
    if (cs == 0x23)
        child->personality = 1;
    return 0;
}
