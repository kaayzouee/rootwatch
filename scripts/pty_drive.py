import os, pty, sys, time, select, signal, struct, fcntl, termios, re
def run(args, keys, rows=30, cols=100, settle=0.15, timeout=20):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(args[0], args)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    out = b""
    def drain(t):
        nonlocal out
        end = time.time()+t
        while time.time() < end:
            r,_,_ = select.select([fd],[],[],0.05)
            if r:
                try: d = os.read(fd, 65536)
                except OSError: return False
                if not d: return False
                out += d
        return True
    drain(1.5)
    for k in keys:
        if isinstance(k, float): drain(k); continue
        os.write(fd, k if isinstance(k, bytes) else k.encode()); drain(settle)
    t0=time.time(); status=None
    while time.time()-t0 < timeout:
        drain(0.1)
        p, st = os.waitpid(pid, os.WNOHANG)
        if p: status=st; break
    else:
        os.kill(pid, signal.SIGKILL); os.waitpid(pid,0)
    return out, status
if __name__ == "__main__":
    pass
