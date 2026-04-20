"""Keep-alive stub process that owns NS_FW's lifetime.

Rationale: pyroute2's ``netns.create(name)`` leaves a bind-mount at
``/run/netns/<name>`` that the kernel will never reclaim on its own
— if the controller dies by SIGKILL, the mount persists and so
does the net namespace. That leaks netns across test runs.

The stub below is a tiny forked child that:

1. Creates its own net namespace via ``unshare(CLONE_NEWNET)``.
2. Bind-mounts ``/proc/self/ns/net`` onto ``/run/netns/<name>``.
3. Tells the parent "ready".
4. Reads from a keep-alive pipe until the parent closes it or
   dies. Either way the read returns EOF.
5. Umounts the bind mount, removes the pinned path, exits.

Steps 1–2 give us a named netns compatible with pyroute2.NetNS
and ``ip netns exec``. Steps 4–5 give us kernel-level cleanup: no
matter how the controller dies, the parent's side of the pipe is
closed by the kernel on exit → the stub wakes up → the mount is
removed → the kernel reclaims the netns.

Additional belt-and-braces: ``PR_SET_PDEATHSIG(SIGTERM)`` sends
the stub a SIGTERM if its parent disappears, so the cleanup fires
even if the pipe EOF path is somehow bypassed. A SIGTERM handler
performs the same cleanup as the EOF path.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import signal
from typing import Any

# Linux syscalls + constants
_CLONE_NEWNET = 0x40000000
_MS_BIND      = 0x1000
_PR_SET_PDEATHSIG = 1

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _libc_check(name: str, rc: int) -> None:
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{name} failed: {os.strerror(err)}")


def _stub_main(name: str, read_fd: int, write_fd: int) -> None:  # pragma: no cover
    """Body of the forked child."""
    # Die automatically if parent dies — gives SIGTERM first for cleanup.
    _libc.prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)

    # Step 1: unshare our net namespace.
    _libc_check("unshare(CLONE_NEWNET)", _libc.unshare(_CLONE_NEWNET))

    # Step 2: bind-mount /proc/self/ns/net → /run/netns/<name>
    os.makedirs("/run/netns", exist_ok=True)
    target = f"/run/netns/{name}"
    # Create the target file if missing (bind mount onto an empty file)
    fd = os.open(target, os.O_CREAT | os.O_WRONLY, 0o644)
    os.close(fd)
    _libc_check(
        "mount(bind)",
        _libc.mount(b"/proc/self/ns/net", target.encode(),
                    b"none", _MS_BIND, None),
    )

    def cleanup(signum: int = 0, frame: Any = None) -> None:
        # Best-effort umount + unlink + exit. Writes a marker file so
        # the operator can tell whether this path actually ran when
        # debugging SIGKILL-based tests.
        try:
            with open(f"/tmp/simlab-stub-cleanup.{os.getpid()}", "w") as f:
                f.write(f"signum={signum} target={target}\n")
        except OSError:
            pass
        try:
            rc = _libc.umount(target.encode())
            if rc != 0:
                try:
                    with open(f"/tmp/simlab-stub-cleanup.{os.getpid()}", "a") as f:
                        f.write(f"umount rc={rc} errno={ctypes.get_errno()}\n")
                except OSError:
                    pass
        except Exception:
            pass
        try:
            os.remove(target)
        except OSError:
            pass
        os._exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGHUP, cleanup)

    # Step 3: tell the parent we are ready.
    # Use write_fd which was opened for writing in the child-only pair.
    try:
        os.write(write_fd, b"R")
    except OSError:
        pass
    try:
        os.close(write_fd)
    except OSError:
        pass

    # Step 4: block on the keep-alive read fd until EOF.
    try:
        while True:
            data = os.read(read_fd, 64)
            if not data:
                break
    except OSError:
        pass
    cleanup()


def spawn_nsstub(name: str) -> int:
    """Fork a stub process pinning a new netns named ``name``.

    Returns the stub's pid. The caller keeps the stub alive by
    holding the write end of the keep-alive pipe open. On shutdown,
    closing that pipe end causes the stub to cleanup and exit.

    A single file descriptor is stored on the returned ``pid``
    indirectly: the caller should remember to close
    ``spawn_nsstub.<name>_fd`` before expecting the stub to exit —
    but for simplicity we attach the fd to the process group via
    a module-level dict.
    """
    # Keep-alive pipe: parent holds the write end; stub holds read.
    ka_r, ka_w = os.pipe()
    # Readiness pipe: stub writes 'R' when done setup; parent reads.
    ready_r, ready_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        # Child — close parent-only ends
        os.close(ka_w)
        os.close(ready_r)
        try:
            _stub_main(name, ka_r, ready_w)
        finally:
            os._exit(1)
    # Parent
    os.close(ka_r)
    os.close(ready_w)

    # Wait for readiness signal.
    try:
        buf = os.read(ready_r, 1)
        if buf != b"R":
            raise RuntimeError(
                f"nsstub for {name!r} didn't signal readiness "
                f"(got {buf!r})"
            )
    finally:
        os.close(ready_r)

    # Stash the write-end fd so the caller can close it on shutdown.
    _keepalive_fds[(name, pid)] = ka_w
    return pid


def stop_nsstub(name: str, pid: int, *, timeout: float = 2.0) -> None:
    """Signal the stub to clean up, then reap it."""
    fd = _keepalive_fds.pop((name, pid), None)
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass
    # Best-effort waitpid
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if wpid == pid:
            return
        time.sleep(0.02)
    # Stub didn't exit — escalate
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


_keepalive_fds: dict[tuple[str, int], int] = {}
