import pexpect
import sys

if sys.platform.startswith("darwin"):
  reptyr_command = "sudo ./reptyr %d"
else:
  reptyr_command = "./reptyr %d"

child = pexpect.spawn("test/victim")
child.setecho(False)
child.sendline("hello")
child.expect("ECHO: hello")

reptyr = pexpect.spawn(reptyr_command % (child.pid,))
# Allow macOS users to type sudo password
if sys.platform.startswith("darwin"):
  reptyr.interact(escape_character='x13')
  reptyr.expect('[+] ptrace_finish_attach: sending SIGCONT')
reptyr.sendline("world")
reptyr.expect("ECHO: world")

child.sendline("final")
child.expect(pexpect.EOF)

reptyr.sendeof()
reptyr.expect(pexpect.EOF)
assert not reptyr.isalive()
