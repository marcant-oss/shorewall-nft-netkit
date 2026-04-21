"""Fork+setns+pickle-IPC primitive for netns-aware operations.

Background
----------
``libnftables.Nftables()`` caches its netlink socket on first ``.cmd()``
call.  If the parent process calls ``setns(CLONE_NEWNET)`` after the socket
was already opened, the cached socket is **not** rebound — it still talks to
the old netns.  The same applies to ``pyroute2.IPRoute()`` when opened
without ``netns='…'``.

The only safe pattern is therefore:

    fork → child enters netns via ``setns()`` → child opens its netlink
    objects → child does the work → child returns result to parent via IPC
    → parent reaps child

This module provides two primitives built on that pattern:

``run_in_netns_fork``
    One-shot: fork, setns, run one callable, return result, reap child.
    Uses an ``os.pipe()`` pair for result IPC.  Suitable for infrequent
    operations (compile + load a ruleset, run a one-off netlink query, …).

``PersistentNetnsWorker``
    Long-lived child bound to a netns; parent communicates over a
    ``SOCK_SEQPACKET`` socketpair.  The child loops reading length-prefixed
    request datagrams and writing length-prefixed reply datagrams.  Suitable
    for hot-path dispatch (many operations per second).  Auto-respawn is NOT
    implemented — callers own restart policy (see ``shorewalld``'s
    ``ParentWorker`` for a full auto-respawn implementation).

Anti-patterns to avoid
----------------------
* **Do not call from inside an asyncio event loop** — both primitives are
  synchronous (``os.fork``, blocking ``select``).  Async callers must wrap
  with ``loop.run_in_executor(None, ...)``.
* **Do not use** ``subprocess.run(["ip", "netns", "exec", ns, ...])`` as a
  replacement — that forks+execs a separate binary on every call and cannot
  reuse in-process libnftables handles.
* **Do not call** ``setns()`` on the parent process directly — any netlink
  socket or file descriptor opened in the parent before the call will still
  be bound to the original netns after ``setns()`` succeeds.

IPC framing for PersistentNetnsWorker
--------------------------------------
Length-prefixed protocol over ``SOCK_SEQPACKET``:

    [uint32 BE length][payload bytes]

``SOCK_SEQPACKET`` preserves datagram boundaries so the length prefix is
only needed to allow payloads larger than ``PIPE_BUF``/kernel recv buffer;
each ``send``/``recv`` call maps to exactly one message.

Signals
-------
``PR_SET_PDEATHSIG(SIGTERM)`` is set in every child immediately after fork
so that if the parent dies (even by ``SIGKILL``) the child receives
``SIGTERM`` and can run its cleanup handler — avoiding orphaned bind-mounts
in ``/run/netns/``.  **SIGKILL is intentionally NOT used here** — ``SIGKILL``
skips user-space cleanup handlers and has historically caused orphaned
bind-mount entries (see ``nsstub_bindmount_orphan`` note in operator memory).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import pickle
import select
import signal
import socket
import struct
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Linux constants + libc bindings
# ---------------------------------------------------------------------------

_CLONE_NEWNET: int = 0x40000000
_PR_SET_PDEATHSIG: int = 1
_SIGTERM: int = signal.SIGTERM

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _setns(fd: int, nstype: int) -> int:
    """Thin wrapper around the ``setns(2)`` syscall via libc."""
    return _libc.setns(ctypes.c_int(fd), ctypes.c_int(nstype))


def _prctl_pdeathsig(sig: int) -> None:
    rc = _libc.prctl(_PR_SET_PDEATHSIG, sig, 0, 0, 0)
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"prctl(PR_SET_PDEATHSIG) failed: {os.strerror(err)}")


# ---------------------------------------------------------------------------
# Public exception hierarchy
# ---------------------------------------------------------------------------


class NetnsForkError(Exception):
    """Base class for fork/setns/IPC failures."""


class NetnsNotFoundError(NetnsForkError):
    """/run/netns/<name> does not exist (checked before fork)."""


class NetnsSetnsError(NetnsForkError):
    """``setns(2)`` failed in the child (EPERM, EINVAL, …)."""


class ChildCrashedError(NetnsForkError):
    """Child died without producing a result (signal or non-zero exit)."""

    def __init__(
        self,
        msg: str,
        *,
        signal: int | None = None,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(msg)
        self.signal = signal
        self.exit_code = exit_code


class NetnsForkTimeout(NetnsForkError):
    """Parent SIGTERM'd the child because the timeout elapsed."""


# ---------------------------------------------------------------------------
# Internal: child IPC helpers
# ---------------------------------------------------------------------------

_RESULT_OK: bytes = b"\x00"
_RESULT_EXC: bytes = b"\x01"
_RESULT_SETNS_ERR: bytes = b"\x02"

# Maximum bytes read in a single chunk from the pipe. Chosen to be large
# enough for typical results without excessive memory allocation in the
# common path; chunking handles larger payloads transparently.
_CHUNK: int = 65536


def _pipe2_cloexec() -> tuple[int, int]:
    """Return (r, w) pipe pair with O_CLOEXEC set on both ends."""
    if hasattr(os, "pipe2"):
        return os.pipe2(os.O_CLOEXEC)  # type: ignore[attr-defined]
    r, w = os.pipe()
    os.set_inheritable(r, False)
    os.set_inheritable(w, False)
    return r, w


def _write_all(fd: int, data: bytes) -> None:
    """Write all of ``data`` to ``fd``, handling short writes."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _read_all(fd: int) -> bytes:
    """Read everything from ``fd`` until EOF, returning accumulated bytes."""
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, _CHUNK)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _read_all_with_timeout(fd: int, timeout: float) -> bytes | None:
    """Read everything from ``fd`` up to ``timeout`` seconds.

    Returns accumulated bytes on EOF, or ``None`` if the timeout expired
    before EOF.  Uses ``select`` so no SIGALRM is needed.
    """
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return None
        chunk = os.read(fd, _CHUNK)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


# ---------------------------------------------------------------------------
# One-shot: run_in_netns_fork
# ---------------------------------------------------------------------------


def run_in_netns_fork(
    netns: str,
    fn: Callable[..., Any],
    *args: Any,
    timeout: float = 30.0,
    **kwargs: Any,
) -> Any:
    """Run ``fn(*args, **kwargs)`` inside a fresh child process bound to
    the target netns before any netlink sockets are opened.

    Semantics
    ---------
    * The parent forks.  The child sets ``PR_SET_PDEATHSIG=SIGTERM`` (NOT
      SIGKILL — SIGKILL skips cleanup and has caused bind-mount orphans
      in ``/run/netns/`` historically).
    * The child opens ``/run/netns/<name>`` and calls
      ``setns(fd, CLONE_NEWNET)``.
    * On success, the child runs ``fn(*args, **kwargs)`` and
      pickle-serialises the result to the IPC pipe; on exception, pickles
      the exception info instead (type + args + formatted traceback).
    * The parent reads from the pipe with ``select`` honouring the timeout.
      On timeout: SIGTERM the child, wait 1 s grace, SIGKILL if still alive,
      reap, raise ``NetnsForkTimeout``.
    * On child crash (exit without writing the pipe, or WIFSIGNALED): raise
      ``ChildCrashedError`` with signal info.
    * Parent always reaps the child (no zombies).  Always closes its pipe FD.
    * ``fn`` and ``args``/``kwargs`` must be pickleable.  The check is done
      in the parent before fork to give a better error and avoid a wasted
      fork.

    Raises
    ------
    NetnsNotFoundError
        ``/run/netns/<name>`` is missing (checked before fork).
    NetnsSetnsError
        ``setns(2)`` failed in the child (EPERM, EINVAL, …).
    ChildCrashedError
        Child died without sending a result.
    NetnsForkTimeout
        Parent SIGTERM'd the child because the timeout elapsed.
    TypeError
        ``fn`` is not pickleable (lambda, local function, …).
    Any exception raised inside ``fn`` is re-raised in the parent with the
    original type preserved; ``__cause__`` carries the child traceback text.
    """
    netns_path = f"/run/netns/{netns}"
    if not os.path.exists(netns_path):
        raise NetnsNotFoundError(f"netns not found: {netns_path!r}")

    # Fail fast on un-pickleable callables — don't waste a fork.
    try:
        pickle.dumps(fn)
        pickle.dumps(args)
        pickle.dumps(kwargs)
    except (pickle.PicklingError, AttributeError, TypeError) as exc:
        raise TypeError(
            f"run_in_netns_fork: fn or its arguments are not pickleable: {exc}"
        ) from exc

    # Pipe for the child to write back its result.
    r_fd, w_fd = _pipe2_cloexec()

    pid = os.fork()
    if pid == 0:
        # ---- Child -------------------------------------------------------
        try:
            os.close(r_fd)
            _child_one_shot(netns_path, fn, args, kwargs, w_fd)
        finally:
            os._exit(1)
        # unreachable

    # ---- Parent ----------------------------------------------------------
    os.close(w_fd)
    try:
        raw = _read_all_with_timeout(r_fd, timeout)
    finally:
        os.close(r_fd)

    if raw is None:
        # Timeout — escalate child shutdown.
        _kill_and_reap(pid, grace=1.0)
        raise NetnsForkTimeout(
            f"run_in_netns_fork: timeout ({timeout}s) waiting for result "
            f"from child in netns {netns!r}"
        )

    # Child wrote something (or nothing at all — crash before any write).
    if not raw:
        # EOF without any data — child crashed before writing the tag byte.
        exit_info = _reap_child(pid)
        raise ChildCrashedError(
            f"run_in_netns_fork: child exited without sending a result "
            f"({exit_info})",
            signal=exit_info[1],
            exit_code=exit_info[0],
        )

    # Reap the child (should have already exited after writing).
    _reap_child(pid)

    # Decode the result payload.
    tag = raw[:1]
    payload = raw[1:]

    if tag == _RESULT_SETNS_ERR:
        msg = payload.decode("utf-8", errors="replace")
        raise NetnsSetnsError(
            f"run_in_netns_fork: setns failed in child: {msg}"
        )

    if tag == _RESULT_EXC:
        exc_type, exc_args, tb_text = pickle.loads(payload)  # noqa: S301
        try:
            exc = exc_type(*exc_args)
        except Exception:  # noqa: BLE001
            exc = RuntimeError(f"child raised {exc_type.__name__}: {exc_args!r}")
        cause = RuntimeError(f"child traceback:\n{tb_text}")
        raise exc from cause

    if tag == _RESULT_OK:
        return pickle.loads(payload)  # noqa: S301

    raise NetnsForkError(f"run_in_netns_fork: unknown result tag {tag!r}")


def _child_one_shot(
    netns_path: str,
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    w_fd: int,
) -> None:
    """Body executed in the forked child for one-shot calls.

    Never returns — always terminates via ``os._exit``.
    """
    # PR_SET_PDEATHSIG = SIGTERM (not SIGKILL) so cleanup handlers fire.
    try:
        _prctl_pdeathsig(_SIGTERM)
    except OSError:
        pass  # non-fatal; best effort

    # Reset inherited signal handlers to defaults.
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (OSError, ValueError):
            pass

    # Enter the target netns.
    try:
        fd = os.open(netns_path, os.O_RDONLY)
    except OSError as exc:
        _child_write_setns_err(w_fd, f"open({netns_path!r}) failed: {exc}")
        os._exit(1)

    try:
        rc = _setns(fd, _CLONE_NEWNET)
    finally:
        os.close(fd)

    if rc != 0:
        err = ctypes.get_errno()
        _child_write_setns_err(
            w_fd,
            f"setns(CLONE_NEWNET) failed: {os.strerror(err)} (errno={err})",
        )
        os._exit(1)

    # Run the user function.
    try:
        result = fn(*args, **kwargs)
        payload = _RESULT_OK + pickle.dumps(result)
    except Exception as exc:  # noqa: BLE001
        tb = traceback.format_exc()
        payload = _RESULT_EXC + pickle.dumps((type(exc), exc.args, tb))

    try:
        _write_all(w_fd, payload)
    except OSError:
        pass
    try:
        os.close(w_fd)
    except OSError:
        pass
    os._exit(0)


def _child_write_setns_err(w_fd: int, msg: str) -> None:
    try:
        _write_all(w_fd, _RESULT_SETNS_ERR + msg.encode("utf-8"))
        os.close(w_fd)
    except OSError:
        pass


def _reap_child(pid: int, *, timeout: float = 2.0) -> tuple[int | None, int | None]:
    """Reap ``pid`` (non-blocking then blocking) within ``timeout`` seconds.

    Returns ``(exit_code, signal_num)`` — at most one will be non-None.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return (None, None)
        if wpid == pid:
            if os.WIFSIGNALED(status):
                return (None, os.WTERMSIG(status))
            if os.WIFEXITED(status):
                return (os.WEXITSTATUS(status), None)
            return (None, None)
        time.sleep(0.01)
    # Last attempt: blocking reap.
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        return (None, None)
    if os.WIFSIGNALED(status):
        return (None, os.WTERMSIG(status))
    if os.WIFEXITED(status):
        return (os.WEXITSTATUS(status), None)
    return (None, None)


def _kill_and_reap(pid: int, *, grace: float = 1.0) -> None:
    """Send SIGTERM, wait ``grace`` seconds, SIGKILL if still alive, reap."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if wpid == pid:
            return
        time.sleep(0.02)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


# ---------------------------------------------------------------------------
# Persistent worker: PersistentNetnsWorker
# ---------------------------------------------------------------------------

# Length prefix format: 4-byte big-endian unsigned int.
_LEN_HEADER: struct.Struct = struct.Struct("!I")
_LEN_HEADER_SIZE: int = _LEN_HEADER.size  # 4


def _send_framed(sock: socket.socket, data: bytes) -> None:
    """Send a length-prefixed message over ``sock``."""
    header = _LEN_HEADER.pack(len(data))
    sock.sendall(header + data)


def _recv_framed(sock: socket.socket) -> bytes | None:
    """Receive a length-prefixed message from ``sock``.

    Returns ``None`` on EOF / closed socket.
    """
    try:
        header = _recv_exact(sock, _LEN_HEADER_SIZE)
    except (OSError, EOFError):
        return None
    if header is None:
        return None
    (length,) = _LEN_HEADER.unpack(header)
    if length == 0:
        return b""
    try:
        return _recv_exact(sock, length)
    except (OSError, EOFError):
        return None


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly ``n`` bytes from ``sock``; return ``None`` on EOF."""
    buf = bytearray(n)
    view = memoryview(buf)
    received = 0
    while received < n:
        chunk = sock.recv_into(view[received:], n - received)
        if chunk == 0:
            return None
        received += chunk
    return bytes(buf)


@dataclass(frozen=True)
class ChildContext:
    """Passed to ``PersistentNetnsWorker.child_main`` as the first argument.

    Gives the child a way to receive requests and send replies, plus
    metadata about itself.
    """

    pid: int
    netns: str
    recv: Callable[[], bytes | None]
    """Returns the next request payload, or ``None`` on EOF / shutdown."""
    send: Callable[[bytes], None]
    """Send a reply payload back to the parent."""


class PersistentNetnsWorker:
    """Long-lived child bound to a netns; parent communicates over a
    ``SOCK_SEQPACKET`` socketpair.

    Use for hot-path dispatch (many operations per second).  For one-shot
    operations, use ``run_in_netns_fork`` instead.

    The ``child_main`` callable is invoked once in the child with a
    :class:`ChildContext`; it should loop reading requests and sending
    replies until the parent calls :meth:`stop` (which closes the parent
    socket, causing the child to see EOF and return).

    Auto-respawn is NOT implemented here — that belongs in callers who
    know their own restart semantics (see shorewalld's ``ParentWorker``).

    Wire protocol: every request and reply is a length-prefixed message::

        [uint32 BE length][payload bytes]

    A 0-length payload is valid (empty message).
    """

    def __init__(
        self, netns: str, child_main: Callable[[ChildContext], None]
    ) -> None:
        self._netns = netns
        self._child_main = child_main
        self._parent_sock: socket.socket | None = None
        self._child_pid: int | None = None
        self._started = False

    # ---- Properties ------------------------------------------------------

    @property
    def pid(self) -> int:
        if self._child_pid is None:
            raise RuntimeError("PersistentNetnsWorker not started")
        return self._child_pid

    @property
    def is_alive(self) -> bool:
        if self._child_pid is None:
            return False
        try:
            wpid, _ = os.waitpid(self._child_pid, os.WNOHANG)
        except ChildProcessError:
            self._child_pid = None
            return False
        if wpid == self._child_pid:
            self._child_pid = None
            return False
        return True

    # ---- Lifecycle -------------------------------------------------------

    def start(self) -> None:
        """Fork the child, enter the netns, invoke ``child_main`` in the child.

        Safe to call only once per instance.  Raises ``NetnsNotFoundError``
        if the target netns path does not exist.
        """
        if self._started:
            raise RuntimeError("PersistentNetnsWorker.start() already called")
        netns_path = f"/run/netns/{self._netns}"
        if not os.path.exists(netns_path):
            raise NetnsNotFoundError(f"netns not found: {netns_path!r}")

        parent_sock, child_sock = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )

        pid = os.fork()
        if pid == 0:
            # ---- Child ---------------------------------------------------
            try:
                parent_sock.close()
                _persistent_child_main(
                    netns_path, self._netns, child_sock, self._child_main
                )
            finally:
                os._exit(1)
            # unreachable

        # ---- Parent ------------------------------------------------------
        child_sock.close()
        self._parent_sock = parent_sock
        self._child_pid = pid
        self._started = True

    def dispatch(self, request: bytes, *, timeout: float = 5.0) -> bytes:
        """Send ``request`` and return the reply bytes.

        Blocks until the child replies or ``timeout`` expires.

        Raises
        ------
        RuntimeError
            Worker not started or not alive.
        NetnsForkTimeout
            No reply received within ``timeout`` seconds.
        ChildCrashedError
            Child exited without sending a reply.
        """
        if self._parent_sock is None or not self._started:
            raise RuntimeError("PersistentNetnsWorker not started")
        if not self.is_alive:
            raise ChildCrashedError(
                "PersistentNetnsWorker: worker not alive",
                signal=None, exit_code=None,
            )

        _send_framed(self._parent_sock, request)

        # Wait for reply with timeout.
        self._parent_sock.settimeout(timeout)
        try:
            reply = _recv_framed(self._parent_sock)
        except (socket.timeout, TimeoutError):
            raise NetnsForkTimeout(
                f"PersistentNetnsWorker: no reply within {timeout}s"
            )
        finally:
            self._parent_sock.settimeout(None)

        if reply is None:
            # EOF — child exited.
            exit_info = _reap_child(self._child_pid or 0)
            self._child_pid = None
            raise ChildCrashedError(
                "PersistentNetnsWorker: child exited without sending a reply",
                signal=exit_info[1],
                exit_code=exit_info[0],
            )
        return reply

    def stop(self, *, grace: float = 1.0) -> None:
        """Shutdown the worker child.

        Closes the parent socket (the child sees EOF and should exit), waits
        ``grace`` seconds, then SIGKILL if the child is still running.
        """
        if self._parent_sock is not None:
            try:
                self._parent_sock.close()
            except OSError:
                pass
            self._parent_sock = None

        pid = self._child_pid
        if pid is None:
            return

        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            try:
                wpid, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                self._child_pid = None
                return
            if wpid == pid:
                self._child_pid = None
                return
            time.sleep(0.02)

        # Escalate.
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            self._child_pid = None
            return
        # Give SIGTERM a moment, then force-kill.
        time.sleep(min(0.2, grace))
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            self._child_pid = None
            return
        if wpid == pid:
            self._child_pid = None
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        self._child_pid = None


def _persistent_child_main(
    netns_path: str,
    netns_name: str,
    sock: socket.socket,
    child_main: Callable[[ChildContext], None],
) -> None:
    """Body executed in the forked child for persistent workers.

    Never returns — always terminates via ``os._exit``.
    """
    # PR_SET_PDEATHSIG = SIGTERM (not SIGKILL) — see module docstring.
    try:
        _prctl_pdeathsig(_SIGTERM)
    except OSError:
        pass

    # Reset inherited signal handlers.
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (OSError, ValueError):
            pass

    # Enter the target netns.
    try:
        fd = os.open(netns_path, os.O_RDONLY)
    except OSError as exc:
        # Can't enter netns — exit; parent will see a crash.
        try:
            sock.close()
        except OSError:
            pass
        os._exit(2)

    try:
        rc = _setns(fd, _CLONE_NEWNET)
    except Exception:  # noqa: BLE001
        rc = -1
    finally:
        os.close(fd)

    if rc != 0:
        try:
            sock.close()
        except OSError:
            pass
        os._exit(2)

    def _recv() -> bytes | None:
        return _recv_framed(sock)

    def _send(data: bytes) -> None:
        _send_framed(sock, data)

    ctx = ChildContext(
        pid=os.getpid(),
        netns=netns_name,
        recv=_recv,
        send=_send,
    )

    try:
        child_main(ctx)
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    os._exit(0)
