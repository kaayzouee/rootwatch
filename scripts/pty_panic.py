#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Proves the terminal is restored when the application panics.

Release builds use panic = "abort", so no destructor runs: only the panic hook
can restore the terminal, and it must do so *before* the message is printed.

    cargo build --release --example panic_probe && python3 scripts/pty_panic.py
"""
import sys, os, re, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pty_drive as P
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target/release/examples/panic_probe")
out, st = P.run([BIN], [0.6])
ENTER=b"\x1b[?1049h"; LEAVE=b"\x1b[?1049l"; RAW_OFF=None
i_enter=out.find(ENTER); i_leave=out.find(LEAVE); i_msg=out.find(b"probe panic")
print("entered alt screen:", i_enter>=0)
print("left alt screen   :", i_leave>=0)
print("panic message seen:", i_msg>=0)
print("restore happened BEFORE the message (message is readable on the normal screen):", 0 <= i_leave < i_msg)
print("mouse capture disabled:", b"\x1b[?1000l" in out)
print("cursor shown again:", b"\x1b[?25h" in out)
print("process aborted (not a hang):", st is not None and os.WIFSIGNALED(st), "signal", os.WTERMSIG(st) if st and os.WIFSIGNALED(st) else None)
ok = i_enter>=0 and 0 <= i_leave < i_msg and b"\x1b[?25h" in out
sys.exit(0 if ok else 1)
