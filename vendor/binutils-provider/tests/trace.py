#!/usr/bin/env python3
"""Owned x86-64 Linux tracees; stop after native probe close, not a BFD mock."""
import argparse
import ctypes
import fcntl
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.restype = ctypes.c_long


def ptrace(request, pid, address=0, data=0):
    result = LIBC.ptrace(request, pid, ctypes.c_void_p(address), ctypes.c_void_p(data))
    if result == -1:
        raise OSError(ctypes.get_errno(), "ptrace")
    return result


def trace(binary, primary, pc, after_close=None, replace=None, seed=None, library_path=None):
    output = os.memfd_create("gnu-proof-output", 0)
    selected = os.memfd_create("gnu-selected", os.MFD_ALLOW_SEALING)
    with primary.open("rb") as source, os.fdopen(os.dup(selected), "wb") as destination:
        shutil.copyfileobj(source, destination)
    fcntl.fcntl(selected, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    os.set_inheritable(selected, True)
    canonical = str(primary.resolve())
    if seed:
        seed()
    pid = os.fork()
    if pid == 0:
        os.dup2(output, 1)
        os.dup2(output, 2)
        ptrace(0, 0)
        os.kill(os.getpid(), signal.SIGSTOP)
        env = dict(os.environ, PYRO_PRIMARY_FD=str(selected), PYRO_PRIMARY_NAME=str(primary), PYRO_PRIMARY_CANONICAL=canonical)
        if library_path:
            env["LD_LIBRARY_PATH"] = library_path
        os.execve(str(binary), [str(binary), "-f", "-e", str(primary), pc], env)
    os.close(selected)
    identity = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    inherited_command = Path("/proc/self/cmdline").read_bytes()
    deadline = time.monotonic() + 4
    stopped = False
    entering = True
    probe_fd = None
    pending_open = False
    pending_close = False
    replaced = False
    status = None
    timed_out = False
    reaped = False
    live_open_attempts = 0
    try:
        while time.monotonic() < deadline:
            waited, next_status = os.waitpid(pid, os.WNOHANG)
            if not waited:
                time.sleep(0.001)
                continue
            status = next_status
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                reaped = True
                break
            sig = os.WSTOPSIG(status)
            if not stopped:
                ptrace(0x4200, pid, 0, 1 | 0x100000)  # TRACESYSGOOD | EXITKILL
                stopped = True
            elif sig == signal.SIGTRAP | 0x80:
                regs = (ctypes.c_ulonglong * 27)()
                ptrace(12, pid, 0, ctypes.addressof(regs))
                if entering:
                    pending_open = False
                    pending_close = False
                    if regs[15] == 257:  # openat
                        path = bytearray()
                        offset = 0
                        while len(path) < 4096:
                            # PEEKDATA can legitimately return -1; paths here are short ASCII.
                            word = ptrace(2, pid, regs[13] + offset)
                            data = (word & ((1 << 64) - 1)).to_bytes(8, "little")
                            path.extend(data.split(b"\0", 1)[0])
                            if 0 in data:
                                break
                            offset += 8
                        pending_open = os.fsdecode(bytes(path)) == str(after_close or primary)
                        live_open_attempts += pending_open
                    pending_close = after_close and not replaced and regs[15] == 3 and regs[14] == probe_fd
                else:
                    if pending_open and regs[10] < (1 << 63):
                        probe_fd = regs[10]
                    if pending_close and regs[10] == 0:
                        replace()
                        replaced = True
                entering = not entering
            # Suppress exec's plain SIGTRAP, forward other real signals.
            ptrace(24, pid, 0, 0 if sig in (signal.SIGSTOP, signal.SIGTRAP, signal.SIGTRAP | 0x80) else sig)
        else:
            timed_out = True
    finally:
        if not reaped:
            # Unreaped, directly owned child PID remains pinned, never a process group.
            current_identity = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
            current_command = Path(f"/proc/{pid}/cmdline").read_bytes()
            expected_command = b"\0".join(os.fsencode(arg) for arg in [str(binary), "-f", "-e", str(primary), pc]) + b"\0"
            assert current_identity == identity
            assert current_command in (inherited_command, expected_command)
            os.kill(pid, signal.SIGKILL)
            cleanup_deadline = time.monotonic() + 1
            while time.monotonic() < cleanup_deadline:
                waited, next_status = os.waitpid(pid, os.WNOHANG)
                if waited and (os.WIFEXITED(next_status) or os.WIFSIGNALED(next_status)):
                    status = next_status
                    reaped = True
                    break
                time.sleep(0.001)
            assert reaped, "owned tracee did not reap within cleanup deadline"
        os.lseek(output, 0, os.SEEK_SET)
        with os.fdopen(output, "rb") as captured:
            text = captured.read().decode(errors="replace")
    return text, timed_out, replaced, status, live_open_attempts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--oracle", type=Path)
    parser.add_argument("--library-path")
    parser.add_argument("--name", required=True)
    parser.add_argument("--primary", type=Path, required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--leaf", required=True)
    parser.add_argument("--provider", action="store_true")
    parser.add_argument("--watch", type=Path)
    mutation = parser.add_mutually_exclusive_group()
    mutation.add_argument("--replace-primary", type=Path)
    mutation.add_argument("--replace-after-close", type=Path)
    mutation.add_argument("--fifo-after-close", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    primary = args.primary
    if (args.replace_after_close or args.fifo_after_close) and not args.watch:
        parser.error("post-close mutation requires --watch")

    def fifo():
        args.watch.unlink()
        os.mkfifo(args.watch)

    replace = None
    seed = None
    if args.fifo_after_close:
        replace = fifo
    elif args.replace_after_close:
        replace = lambda: os.replace(args.replace_after_close, args.watch)
    elif args.replace_primary:
        seed = lambda: os.replace(args.replace_primary, primary)
    output, hung, replaced, status, opens = trace(binary, primary, args.address, args.watch, replace, seed, args.library_path)
    lines = output.splitlines()
    ok = not hung and status == 0 and bool(lines) and lines[0] == args.leaf
    if args.provider:
        ok = ok and opens == (1 if args.watch else 0)
    if args.oracle and args.name.startswith("valid-"):
        native_env = dict(os.environ)
        native_env.pop("LD_LIBRARY_PATH", None)
        for key in ("PYRO_PRIMARY_FD", "PYRO_PRIMARY_NAME", "PYRO_PRIMARY_CANONICAL"):
            native_env.pop(key, None)
        native = subprocess.check_output([str(args.oracle), "-f", "-e", str(primary), args.address],
                                         env=native_env, timeout=4, text=True)
        ok = ok and output == native
    if args.watch and not replaced:
        ok = False
    print(f"{'PASS' if ok else 'FAIL'} {args.name}: timeout={hung} replaced={replaced} status={status} live_opens={opens} output={output.strip()!r}", flush=True)
    return not ok


if __name__ == "__main__":
    raise SystemExit(main())
