#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Drives the real `rootwatch --tui` binary on a pseudo-terminal.

Checks the terminal lifecycle at the escape-sequence level (alternate screen,
mouse capture, restore on q / Ctrl-C), navigation through every view, rescan,
resize handling, and that non-TUI behaviour is unchanged.

    cargo build --release && python3 scripts/pty_smoke.py
"""
import sys, os, re, struct, fcntl, termios, signal, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pty_drive as P
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("ROOTWATCH_BIN", os.path.join(ROOT, "target/release/rootwatch"))
FX = "/tmp/rootwatch-pty-fixture"
import shutil, subprocess
shutil.rmtree(FX, ignore_errors=True)
os.makedirs(FX + "/alpha/one"); os.makedirs(FX + "/beta")
open(FX + "/alpha/one/a.bin", "wb").write(os.urandom(3_000_000))
open(FX + "/beta/b.bin", "wb").write(os.urandom(1_000_000))
ENTER=b"\x1b[?1049h"; LEAVE=b"\x1b[?1049l"; MOUSE_ON=b"\x1b[?1000h"; MOUSE_OFF=b"\x1b[?1000l"
def strip(b): return re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", b).decode("utf8","replace")
ok=True
def check(name, cond, extra=""):
    global ok
    print(("PASS " if cond else "FAIL ")+name+(" "+extra if (extra and not cond) else ""))
    ok &= bool(cond)

out, st = P.run([BIN,"--tui",FX], ["q"])
check("quit with q: exit code 0", st is not None and os.WIFEXITED(st) and os.WEXITSTATUS(st)==0, str(st))
check("enters alternate screen", ENTER in out)
check("enables mouse capture", MOUSE_ON in out)
check("leaves alternate screen on quit", LEAVE in out and out.rfind(LEAVE) > out.rfind(ENTER))
check("disables mouse capture on quit", MOUSE_OFF in out)
txt=strip(out)
check("scan finished and overview drawn", "Largest areas" in txt and "ready" in txt, txt[-300:])
check("header/tabs/footer drawn", "ROOTWATCH" in txt and "1 Overview" in txt and "Quit" in txt)

out, st = P.run([BIN,"--tui",FX], [b"\x03"])
check("Ctrl-C quits cleanly (exit 0, screen restored)", st is not None and os.WIFEXITED(st) and os.WEXITSTATUS(st)==0 and LEAVE in out, str(st))

out, st = P.run([BIN,"--tui",FX], ["2","\r",0.3,"3","j","l","3","/","a","l","\r","?",0.2,"\x1b","5","6","7","q"])
txt=strip(out)
check("navigated every view, exit 0", st is not None and os.WIFEXITED(st) and os.WEXITSTATUS(st)==0, str(st))
for needle in ["Findings","Finding","Tree","Storage pools","Coverage","Keys","Temporary"]:
    check("saw "+needle, needle in txt)

out, st = P.run([BIN,"--tui","--scope","all",FX], ["r",0.5,"q"])
check("rescan with r then quit, exit 0", st is not None and os.WIFEXITED(st) and os.WEXITSTATUS(st)==0, str(st))
check("scope all accepted in TUI", b"Largest areas" in out)

# resize: start at 100x30, shrink below minimum, then grow
pid_fd=None
import pty, select
pid, fd = pty.fork()
if pid==0: os.execv(BIN,[BIN,"--tui",FX])
def setsize(r,c):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", r,c,0,0)); os.kill(pid, signal.SIGWINCH)
def drain(t):
    buf=b""; end=time.time()+t
    while time.time()<end:
        r,_,_=select.select([fd],[],[],0.05)
        if r:
            try: d=os.read(fd,65536)
            except OSError: break
            buf+=d
    return buf
setsize(30,100); drain(1.5)
setsize(20,60); small=strip(drain(0.6))
check("resize below 80x24 shows message", "Terminal too small" in small and "60x20" in small, small[-200:])
setsize(40,140); big=strip(drain(0.6))
check("resize back up redraws the UI", "ROOTWATCH" in big and "Largest areas" in big, big[-200:])
os.write(fd,b"q"); drain(0.5)
p,st=os.waitpid(pid,0)
check("exit 0 after resizes", os.WIFEXITED(st) and os.WEXITSTATUS(st)==0, str(st))

# non-tty refusal & report mode unchanged
import subprocess
r=subprocess.run([BIN,"--tui",FX],stdin=subprocess.DEVNULL,capture_output=True)
check("--tui without a tty refuses with exit 2", r.returncode==2 and b"interactive terminal" in r.stderr)
r=subprocess.run([BIN,FX],capture_output=True)
check("default mode is still the text report", r.returncode==0 and b"filesystems scanned" in r.stdout and b"\x1b[?1049h" not in r.stdout)
r=subprocess.run([BIN,"--tui","--privileged","/tmp"],capture_output=True)
check("--tui --privileged rejected", r.returncode==2 and b"cannot be combined" in r.stderr)
sys.exit(0 if ok else 1)
