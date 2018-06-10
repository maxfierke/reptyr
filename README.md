# rust port of reptyr

This branch is for porting reptyr to rust

## Why?

1. I wanted to learn Rust
2. I started adding macOS support and was getting annoyed by the lack of docs
   for mach APIs. Then I stumbled upon the `mach` crate in Rust. Two birds.

## Who?

[Me.](https://github.com/maxfierke)

## Does it work?

Yes (or at least the tests pass). My aim is keep this branch passing the test
suite as I work.

## When?

Your guess is as good as mine. Some functions are a quick and easy port. Others
are much more tricky. There's still some stuff that _has_ to be C for now, which
needs to be worked around, so there can be some tricky pointer & FFI stuff. It
will hopefully speed up once the Linux platform stuff is squared away.

## Plans?

1. Port over base Linux platform stuff (linux.c)
2. Port over Linux ptrace stuff (linux_ptrace.c)
3. Port over Linux arch stuff (if possible)
4. Port over main reptyr code (reptyr.c, attach.c)
5. Refactor existing Rust code to be as ideomatic as practical
6. ???
12. Tackle other platforms
13. Tackle macOS
14. Delete any remaining C code

### Open Questions

1. Retain 32-bit x86 support? (Leaning no. Probably not worth the effort.)
2. Retain ARM support? (Would like to, but not sure if I have any spare hardware.)
3. Keep FreeBSD support? (Probably will. A few things to share with macOS.)

## Can I help?

Sure! Grab a function, port it over, make sure the tests pass, and put up a PR!

---

# reptyr - A tool for "re-ptying" programs.

reptyr is a utility for taking an existing running program and
attaching it to a new terminal. Started a long-running process over
ssh, but have to leave and don't want to interrupt it? Just start a
screen, use reptyr to grab it, and then kill the ssh session and head
on home.

## USAGE

    reptyr PID

"reptyr PID" will grab the process with id PID and attach it to your
current terminal.

After attaching, the process will take input from and write output to
the new terminal, including ^C and ^Z. (Unfortunately, if you
background it, you will still have to run "bg" or "fg" in the old
terminal. This is likely impossible to fix in a reasonable way without
patching your shell.)

### Typical usage pattern

* Start a long running process, e.g. `top`
* Background the process with CTRL-Z
* Resume the process in the background: `bg`
* Display your running background jobs with `jobs -l`, this should look like this:
  * `[1]+  4711 Stopped (signal)        top`
  * (The `-l` in `jobs -l` makes sure you'll get the PID)
* Disown the jobs from the current parent with `disown top`. After that, `jobs` will not show the job any more, but `ps -a` will.
* Start your terminal multiplexer of choice, e.g. `tmux`
* Reattach to the backgrounded process: `reptyr 4711`
* Detach your terminal multiplexer (e.g. CTRL-A D) and close ssh
* Reconnect ssh, attach to your multiplexer (e.g. `tmux attach`), rejoice!

## "But wait, isn't this just screenify?"

There's a shell script called "screenify" that's been going around the
internet for nigh on 10 years now that uses gdb to (supposedly)
accomplish the same thing. The difference is that reptyr works much,
much, better.

If you attach a "less" using screenify, it will still take input from
the old terminal. If you attach an ncurses program using screenify,
and resize the window, your program won't notice. If you attach a
process with screenify, ^C in the new terminal won't work.

reptyr fixes all of these problems, and is the only such tool I know
of that does so. See below for some more details on how it
accomplishes this.

## PORTABILITY

reptyr supports Linux and FreeBSD. Not all functionality is currently
available on FreeBSD. (Notably, FreeBSD doesn't support `reptyr -T` at
this time.

`reptyr` uses ptrace to attach to the target and control it at the
syscall level, so it is highly dependent on details of the syscall
API, available syscalls, and terminal ioctl()s. A port to other
operating systems may be technically feasible, but requires
significant low-level knowledge of the relevant platform, and may
entail significant refactors.

reptyr works on i386, x86_64, and ARM. Ports to other architectures should be
straightforward, and should in most cases be as simple as adding an arch/ARCH.h
file and adding a clause to the ifdef ladder in ptrace.c.

### ptrace_scope on Ubuntu Maverick and up

`reptyr` depends on the `ptrace` system call to attach to the remote program. On
Ubuntu Maverick and higher, this ability is disabled by default for security
reasons. You can enable it temporarily by doing

    # echo 0 > /proc/sys/kernel/yama/ptrace_scope

as root, or permanently by editing the file /etc/sysctl.d/10-ptrace.conf, which
also contains more information about exactly what this setting accomplishes.

## reptyr -l

As a bonus feature, if you run "reptyr -l", reptyr will create a new
pseudo-terminal pair with nothing attached to the slave end, and print
its name out.

If you are debugging a program in gdb, you can pass that name to "set
inferior-pty". Because there is no existing program listening to that
tty, this will work much better than passing an existing shell's
terminal.

## How does it work?

The main thing that reptyr does that no one else does is that it
actually changes the controlling terminal of the process you are
attaching. I wrote a
[blog post](https://blog.nelhage.com/2011/02/changing-ctty/)
explaining just what the shenanigans involved are.

## PRONUNCIATION

I pronounce it like "repeater", but since that's easily ambiguous,
"re-P-T-Y-er" is also acceptable.


## CREDITS

reptyr was written by Nelson Elhage <nelhage@nelhage.com>. Contact him
with any questions or bug reports.

## URL

http://github.com/nelhage/reptyr
