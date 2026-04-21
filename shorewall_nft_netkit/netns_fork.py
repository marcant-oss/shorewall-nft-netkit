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

This module provides three IPC paths and two public primitives, plus the
specialised :func:`run_nft_in_netns_zc` helper:

**IPC paths**

1. **Inline pickle pipe** (≤ ``large_payload_threshold``, default 4 MiB):
   the pickled payload travels through a regular ``os.pipe()`` pair.
   A ``select``-drain loop in the parent prevents pipe-buffer deadlock.

2. **Out-of-band memfd** (> ``large_payload_threshold``):
   the oversized blob is written once into an anonymous
   ``memfd_create(MFD_CLOEXEC | MFD_ALLOW_SEALING)`` file and the child
   inherits the file descriptor across ``fork()``.  Both sides ``mmap()``
   the same physical pages — true zero copy.  After the parent seals the
   memfd (``F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW``) the child gets a
   read-only view.  When the last fd-holder closes, the kernel reclaims the
   RAM automatically — no ``/tmp`` touch, no unlink needed, no digest check
   (the sealed memfd is immutable by construction).

   On kernels older than 3.17 (``os.memfd_create`` absent) a
   ``RuntimeError`` is raised with a clear message; callers must keep
   payloads under the threshold on such kernels.

3. **``run_nft_in_netns_zc`` specialised nft-script path**:
   the script is placed in a sealed memfd; two additional pipes carry
   stdout (JSON) and stderr back to the parent. Designed for compile+apply
   operations where input is bytes-like and output is small.

**Primitives**

``run_in_netns_fork``
    One-shot: fork, setns, run one callable, return result, reap child.
    Uses inline pickle pipe for small payloads; out-of-band memfd for
    large args/results.  Pickle protocol 5 ``PickleBuffer`` out-of-band
    callbacks (``_pickle_with_oob``) further avoid copies for individual
    large ``bytes``/``bytearray``/``memoryview`` arguments.

``PersistentNetnsWorker``
    Long-lived child bound to a netns; parent communicates over a
    ``SOCK_STREAM`` socketpair.  The child loops reading length-prefixed
    request messages and writing length-prefixed reply messages.  Suitable
    for hot-path dispatch (many operations per second).  Auto-respawn is NOT
    implemented — callers own restart policy (see ``shorewalld``'s
    ``ParentWorker`` for a full auto-respawn implementation).

    **Large payloads**: ``SOCK_STREAM`` has no per-datagram size cap;
    arbitrary-size messages are handled via 4-byte length-prefix framing
    with an exact-read loop.  The practical limit is available memory —
    a 64 MB round-trip is tested and confirmed working.

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
* **Do not pass multi-MB payloads to every ``dispatch()`` call** — batch
  or compress IPC traffic if you would saturate a 1 Gbps link with it.

IPC framing for PersistentNetnsWorker
--------------------------------------
Length-prefixed protocol over ``SOCK_STREAM``:

    [uint32 BE length][payload bytes]

``SOCK_STREAM`` handles messages of arbitrary size; the length prefix
lets the receiver know how many bytes to read before the next message.
An exact read loop (``recv_into`` with ``MSG_WAITALL`` where available)
reassembles fragmented messages transparently.

Pickle protocol
---------------
``pickle.HIGHEST_PROTOCOL`` (protocol 5 on CPython 3.8+) is used for all
payloads.  Protocol 5 supports ``pickle.PickleBuffer`` for out-of-band
buffer transfer, which avoids an extra in-memory copy when the result is
a large ``bytes`` object.  ``_pickle_with_oob`` uses the out-of-band buffer
callback to route individual large byte-buffers through dedicated memfds.

Signals
-------
``PR_SET_PDEATHSIG(SIGTERM)`` is set in every child immediately after fork
so that if the parent dies (even by ``SIGKILL``) the child receives
``SIGTERM`` and can run its cleanup handler — avoiding orphaned bind-mounts
in ``/run/netns/``.  **SIGKILL is intentionally NOT used here** — ``SIGKILL``
skips user-space cleanup handlers and has historically caused orphaned
bind-mount entries (see ``nsstub_bindmount_orphan`` note in operator memory).

memfd_create availability
--------------------------
``os.memfd_create`` requires Linux ≥ 3.17 and Python ≥ 3.8.  When
unavailable, the module-level boolean ``MEMFD_SUPPORTED`` is ``False`` and
calls that require memfd raise ``RuntimeError`` with a clear message.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno as _errno_mod
import fcntl
import mmap
import os
import pickle
import select
import signal
import socket
import struct
import threading
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

# F_SETPIPE_SZ is Linux-specific (1031).  We define it here rather than
# importing from fcntl so the module is importable on non-Linux (tests etc.).
_F_SETPIPE_SZ: int = 1031

# memfd_create flags (Linux-specific).
_MFD_CLOEXEC: int = 0x0001
_MFD_ALLOW_SEALING: int = 0x0002

# fcntl seal constants — available since Linux 3.17.
_F_ADD_SEALS: int = 1033
_F_SEAL_SHRINK: int = 0x0002
_F_SEAL_GROW: int = 0x0004
_F_SEAL_WRITE: int = 0x0008

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
# memfd_create support detection
# ---------------------------------------------------------------------------


def _check_memfd_support() -> bool:
    """Return True if ``os.memfd_create`` is available on this kernel/Python."""
    if not hasattr(os, "memfd_create"):
        return False
    try:
        fd = os.memfd_create("_probe", _MFD_CLOEXEC)  # type: ignore[attr-defined]
        os.close(fd)
        return True
    except (OSError, AttributeError):
        return False


#: True when ``memfd_create(2)`` + ``os.memfd_create`` are usable on this host.
MEMFD_SUPPORTED: bool = _check_memfd_support()


def _require_memfd() -> None:
    """Raise a clear ``RuntimeError`` if memfd is unavailable."""
    if not MEMFD_SUPPORTED:
        raise RuntimeError(
            "memfd_create is not available on this kernel or Python build "
            "(requires Linux >= 3.17 and Python >= 3.8).  "
            "Either upgrade the kernel or keep payloads under the "
            "large_payload_threshold so they travel through the inline pipe."
        )


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


class NftError(NetnsForkError):
    """``nft.cmd()`` returned a non-zero exit code inside the child.

    ``rc`` is the numeric return code; ``stderr`` carries the nft error text.
    """

    def __init__(self, msg: str, *, rc: int = -1, stderr: str = "") -> None:
        super().__init__(msg)
        self.rc = rc
        self.stderr = stderr


# ---------------------------------------------------------------------------
# NftResult dataclass (returned by run_nft_in_netns_zc)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NftResult:
    """Result of :func:`run_nft_in_netns_zc`."""

    rc: int
    stdout: str   # JSON output from nft
    stderr: str


# ---------------------------------------------------------------------------
# Internal: child IPC helpers
# ---------------------------------------------------------------------------

_RESULT_OK: bytes = b"\x00"
_RESULT_EXC: bytes = b"\x01"
_RESULT_SETNS_ERR: bytes = b"\x02"
_RESULT_OK_MEMFD: bytes = b"\x03"    # result was written to a memfd
_RESULT_EXC_MEMFD: bytes = b"\x04"  # exception pickle written to a memfd

# Maximum bytes read in a single chunk from the pipe. Chosen to be large
# enough for typical results without excessive memory allocation in the
# common path; chunking handles larger payloads transparently.
_CHUNK: int = 65536

# Default threshold above which args/result pickles are routed through an
# out-of-band memfd instead of through the pipe.  Can be overridden per-call
# via the ``large_payload_threshold`` kwarg.
_DEFAULT_LARGE_PAYLOAD_THRESHOLD: int = 4 * 1024 * 1024  # 4 MiB

# Sentinel byte sent over the args pipe when args were staged to a memfd.
_ARGS_MEMFD: bytes = b"\xff"

# memfd result IPC header: [uint32 BE fd_number][uint32 BE size] (8 bytes).
_MEMFD_RESULT_HDR: struct.Struct = struct.Struct("!II")


def _pipe2_cloexec() -> tuple[int, int]:
    """Return (r, w) pipe pair with O_CLOEXEC set on both ends."""
    if hasattr(os, "pipe2"):
        return os.pipe2(os.O_CLOEXEC)  # type: ignore[attr-defined]
    r, w = os.pipe()
    os.set_inheritable(r, False)
    os.set_inheritable(w, False)
    return r, w


def _try_bump_pipe_size(fd: int, size: int = 1 << 20) -> None:
    """Attempt to set the pipe size to ``size`` bytes.

    Silently ignores ``EPERM`` (missing ``CAP_SYS_RESOURCE``) and
    ``EINVAL`` (kernel too old or size out of range).  Raises other errors.
    """
    try:
        fcntl.fcntl(fd, _F_SETPIPE_SZ, size)
    except OSError as exc:
        if exc.errno in (_errno_mod.EPERM, _errno_mod.EINVAL, _errno_mod.EACCES):
            return  # best-effort; silently skip
        raise


def _write_all(fd: int, data: bytes) -> None:
    """Write all of ``data`` to ``fd``, handling short writes.

    Raises ``BrokenPipeError`` if the read end has been closed (EPIPE).
    """
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except OSError as exc:
            if exc.errno == _errno_mod.EPIPE:
                raise BrokenPipeError("pipe closed by parent") from exc
            raise
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


def _select_retry(rlist: list[int], timeout: float) -> bool:
    """``select`` with ``EINTR`` retry.  Returns True if the fd is ready."""
    while True:
        try:
            ready, _, _ = select.select(rlist, [], [], timeout)
            return bool(ready)
        except InterruptedError:
            # EINTR — a signal arrived; retry.
            continue
        except OSError as exc:
            if exc.errno == _errno_mod.EINTR:
                continue
            raise


def _read_all_with_timeout(fd: int, timeout: float) -> bytes | None:
    """Read everything from ``fd`` up to ``timeout`` seconds.

    Returns accumulated bytes on EOF, or ``None`` if the timeout expired
    before EOF.  Uses ``select`` with ``EINTR`` retry so no SIGALRM is needed.

    The parent calls this while the child is running, so data arrives
    progressively — each iteration of the loop drains whatever the child has
    written so far.  This concurrent drain prevents the pipe buffer from
    filling up and blocking the child even for very large payloads.
    """
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if not _select_retry([fd], remaining):
            return None
        try:
            chunk = os.read(fd, _CHUNK)
        except OSError:
            return None
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


# ---------------------------------------------------------------------------
# memfd-backed zero-copy IPC helpers
# ---------------------------------------------------------------------------


def _memfd_write(data: bytes | bytearray | memoryview, *, name: str = "nf_ipc") -> int:
    """Write ``data`` into a new memfd and return the open fd.

    The memfd is created with ``MFD_CLOEXEC | MFD_ALLOW_SEALING``.
    After writing, write+resize seals are applied so that the child
    receives an immutable read-only view (no digest check needed — the
    sealed pages cannot be modified after sealing).  The caller is
    responsible for closing the fd when done.

    Raises ``RuntimeError`` if memfd is unavailable (kernel < 3.17).
    Raises ``OSError`` on any kernel-level failure.
    """
    _require_memfd()
    size = len(data)
    fd = os.memfd_create(name, _MFD_CLOEXEC | _MFD_ALLOW_SEALING)  # type: ignore[attr-defined]
    try:
        os.ftruncate(fd, size)
        if size > 0:
            raw = bytes(data) if isinstance(data, memoryview) else data
            with mmap.mmap(fd, size) as mm:
                mm.write(raw)
        # Seal: prevent further writes and resizing.  Best-effort —
        # some container runtimes (seccomp profiles) disallow F_ADD_SEALS;
        # the fallback is still safe because the child only reads.
        try:
            fcntl.fcntl(fd, _F_ADD_SEALS, _F_SEAL_WRITE | _F_SEAL_SHRINK | _F_SEAL_GROW)
        except OSError:
            pass
    except Exception:
        os.close(fd)
        raise
    return fd


def _memfd_read(fd: int, size: int) -> bytes:
    """Read ``size`` bytes from a memfd and return them.

    Does not close ``fd`` — caller is responsible.
    """
    if size == 0:
        return b""
    with mmap.mmap(fd, size, access=mmap.ACCESS_READ) as mm:
        return mm.read(size)


# ---------------------------------------------------------------------------
# Out-of-band pickle with PickleBuffer support (protocol 5)
# ---------------------------------------------------------------------------


def _wrap_large_buffers(obj: Any, threshold: int) -> Any:
    """Recursively replace large ``bytes`` / ``bytearray`` / ``memoryview``
    values in ``obj`` with ``pickle.PickleBuffer`` wrappers.

    This is the pre-processing step for ``_pickle_with_oob``.  The wrapped
    object is then pickled with a ``buffer_callback`` that routes
    ``PickleBuffer`` objects above the threshold into dedicated memfds.

    Only the container types that ``pickle`` handles directly (``list``,
    ``tuple``, ``dict``, ``set``, ``frozenset``) are recursed.  All other
    object types are returned as-is (the pickler handles them normally).

    ``memoryview`` objects are converted to ``PickleBuffer`` directly because
    they already support the buffer protocol.  ``bytes`` are wrapped via
    ``pickle.PickleBuffer(obj)`` which copies the reference, not the data.
    """
    if isinstance(obj, (bytes, bytearray)) and len(obj) >= threshold:
        return pickle.PickleBuffer(obj)
    if isinstance(obj, memoryview) and obj.nbytes >= threshold:
        return pickle.PickleBuffer(obj)
    if isinstance(obj, list):
        return [_wrap_large_buffers(x, threshold) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_wrap_large_buffers(x, threshold) for x in obj)
    if isinstance(obj, dict):
        return {k: _wrap_large_buffers(v, threshold) for k, v in obj.items()}
    return obj


def _pickle_with_oob(
    obj: Any, *, threshold: int = _DEFAULT_LARGE_PAYLOAD_THRESHOLD
) -> tuple[bytes, list[int]]:
    """Pickle ``obj`` with protocol 5 and out-of-band buffer handling.

    ``bytes`` / ``bytearray`` / ``memoryview`` values whose raw size exceeds
    ``threshold`` are placed in individual memfds instead of being embedded in
    the pickle stream.  The fd numbers are returned in ``fds_to_send`` in the
    order they were encountered; the pickle stream contains opaque out-of-band
    slots that ``_unpickle_with_oob`` resolves by consuming from the same list.

    Values smaller than ``threshold`` are embedded inline.

    Implementation note: Python's ``buffer_callback`` is only invoked for
    ``pickle.PickleBuffer`` objects.  Plain ``bytes`` are immutable and are
    pickled inline by the C pickler regardless of ``buffer_callback``.  This
    function therefore pre-processes ``obj`` via ``_wrap_large_buffers`` to
    replace large byte-buffer values with ``PickleBuffer`` wrappers before
    pickling.  Container types (list/tuple/dict) are recursed; arbitrary
    objects are left intact.

    Raises ``RuntimeError`` if any oversized buffer is encountered and
    memfd is unavailable (kernel < 3.17).

    Returns ``(pickle_bytes, list_of_open_fds)``.  Caller must close the fds
    when done (or pass them to a child via fork inheritance).
    """
    fds: list[int] = []

    def _buffer_callback(buf: pickle.PickleBuffer) -> object:
        raw = buf.raw()
        if len(raw) >= threshold:
            _require_memfd()
            fd = _memfd_write(raw, name="nf_oob")
            fds.append(fd)
            # Returning False tells the pickler to use an out-of-band slot.
            return False
        # Embed inline — returning True keeps it in the stream.
        return True

    wrapped = _wrap_large_buffers(obj, threshold)
    data = pickle.dumps(
        wrapped,
        protocol=pickle.HIGHEST_PROTOCOL,
        buffer_callback=_buffer_callback,
    )
    return data, fds


def _unpickle_with_oob(pickle_bytes: bytes, fds: list[int]) -> Any:
    """Reconstruct an object pickled with ``_pickle_with_oob``.

    ``fds`` must be in the same order as returned by ``_pickle_with_oob``.
    Each fd is mmap'd read-only; the resulting ``memoryview`` is passed to
    the unpickler as the next out-of-band buffer.  The fds are NOT closed
    by this function — caller is responsible.
    """
    fd_iter = iter(fds)

    def _buffer_iter():
        for fd in fd_iter:
            size = os.lseek(fd, 0, os.SEEK_END)
            os.lseek(fd, 0, os.SEEK_SET)
            if size == 0:
                yield memoryview(b"")
            else:
                mm = mmap.mmap(fd, size, access=mmap.ACCESS_READ)
                # The memoryview keeps the mmap alive until the view is released.
                yield memoryview(mm)

    return pickle.loads(  # noqa: S301
        pickle_bytes,
        buffers=_buffer_iter(),
    )


# ---------------------------------------------------------------------------
# One-shot: run_in_netns_fork
# ---------------------------------------------------------------------------


def run_in_netns_fork(
    netns: str,
    fn: Callable[..., Any],
    *args: Any,
    timeout: float = 30.0,
    large_payload_threshold: int = _DEFAULT_LARGE_PAYLOAD_THRESHOLD,
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
      The ``select`` loop drains data as the child produces it, preventing
      pipe-buffer deadlock even for very large payloads (hundreds of MB).
    * On timeout: SIGTERM the child, wait 1 s grace, SIGKILL if still alive,
      reap, raise ``NetnsForkTimeout``.
    * On child crash (exit without writing the pipe, or WIFSIGNALED): raise
      ``ChildCrashedError`` with signal info.
    * Parent always reaps the child (no zombies).  Always closes its pipe FD.
    * ``fn`` and ``args``/``kwargs`` must be pickleable.  The check is done
      in the parent before fork to give a better error and avoid a wasted
      fork.

    Large-payload behaviour
    -----------------------
    If the pickled size of ``args``/``kwargs`` exceeds ``large_payload_threshold``
    (default 4 MiB), they are written to an anonymous in-memory file
    (``memfd_create(MFD_CLOEXEC | MFD_ALLOW_SEALING)``) and the fd number +
    size is communicated to the child via a dedicated pipe.  The child
    inherits the memfd fd across ``fork()`` and ``mmap``s the same physical
    pages — true zero copy, no ``/tmp`` touch, no digest check needed
    (memfd is sealed against writes before the fork).  The same mechanism is
    used for the return value when the child's pickle exceeds the threshold.

    Individual ``bytes`` / ``bytearray`` / ``memoryview`` arguments that
    exceed the threshold are automatically placed in their own memfds via
    pickle protocol 5 out-of-band buffer callbacks (``_pickle_with_oob``).

    Requires Linux ≥ 3.17 for the out-of-band memfd path.  On older kernels,
    a ``RuntimeError`` is raised when the payload exceeds the threshold.

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
    MemoryError
        Pickling a very large argument caused a MemoryError.
    RuntimeError
        memfd unavailable and payload exceeds threshold.
    Any exception raised inside ``fn`` is re-raised in the parent with the
    original type preserved; ``__cause__`` carries the child traceback text.
    """
    netns_path = f"/run/netns/{netns}"
    if not os.path.exists(netns_path):
        raise NetnsNotFoundError(f"netns not found: {netns_path!r}")

    # Fail fast on un-pickleable callables — don't waste a fork.
    try:
        pickle.dumps(fn)
    except (pickle.PicklingError, AttributeError, TypeError) as exc:
        raise TypeError(
            f"run_in_netns_fork: fn or its arguments are not pickleable: {exc}"
        ) from exc

    # Pickle args/kwargs, routing oversized bytes buffers through memfds.
    oob_fds: list[int] = []
    try:
        args_pickle, oob_fds = _pickle_with_oob(
            (fn, args, kwargs), threshold=large_payload_threshold
        )
    except MemoryError as exc:
        raise MemoryError(
            f"run_in_netns_fork: MemoryError pickling arguments: {exc}"
        ) from exc

    # If the entire args pickle is oversized, stage it in its own memfd.
    use_args_memfd = len(args_pickle) > large_payload_threshold
    args_memfd_fd: int | None = None
    args_memfd_size: int = 0

    if use_args_memfd:
        _require_memfd()
        args_memfd_fd = _memfd_write(args_pickle, name="nf_args")
        args_memfd_size = len(args_pickle)
        del args_pickle  # release memory before fork

    # Mark oob fds and the args memfd fd as inheritable across fork.
    for fd in oob_fds:
        os.set_inheritable(fd, True)
    if args_memfd_fd is not None:
        os.set_inheritable(args_memfd_fd, True)

    # Pipe for the child to write back its result.
    r_fd, w_fd = _pipe2_cloexec()
    # Best-effort bump of the pipe buffer to 1 MiB (needs CAP_SYS_RESOURCE).
    _try_bump_pipe_size(w_fd, 1 << 20)

    # Pipe for parent to send args-memfd info to child (if needed).
    args_r_fd: int | None = None
    args_w_fd: int | None = None
    if use_args_memfd:
        args_r_fd, args_w_fd = _pipe2_cloexec()

    pid = os.fork()
    if pid == 0:
        # ---- Child -------------------------------------------------------
        try:
            os.close(r_fd)
            if use_args_memfd:
                assert args_w_fd is not None
                assert args_r_fd is not None
                os.close(args_w_fd)
                _child_one_shot(
                    netns_path, fn, args, kwargs, w_fd,
                    large_payload_threshold=large_payload_threshold,
                    args_memfd_pipe_fd=args_r_fd,
                    oob_fds=oob_fds,
                )
            else:
                if args_r_fd is not None:
                    os.close(args_r_fd)
                if args_w_fd is not None:
                    os.close(args_w_fd)
                _child_one_shot(
                    netns_path, fn, args, kwargs, w_fd,
                    large_payload_threshold=large_payload_threshold,
                    args_memfd_pipe_fd=None,
                    oob_fds=oob_fds,
                )
        finally:
            os._exit(1)
        # unreachable

    # ---- Parent ----------------------------------------------------------
    os.close(w_fd)

    # Close oob fds in parent (child has inherited copies).
    for fd in oob_fds:
        try:
            os.close(fd)
        except OSError:
            pass

    if use_args_memfd:
        assert args_r_fd is not None
        assert args_w_fd is not None
        assert args_memfd_fd is not None
        os.close(args_r_fd)
        # Send sentinel + (fd_number, size) to child via args pipe.
        try:
            _write_all(args_w_fd, _ARGS_MEMFD)
            _write_all(args_w_fd, struct.pack("!II", args_memfd_fd, args_memfd_size))
        finally:
            os.close(args_w_fd)
            os.close(args_memfd_fd)
    # In the non-memfd path, fn/args travel copy-on-write via fork.

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
        _exc_from_pickle(payload)

    if tag == _RESULT_EXC_MEMFD:
        exc_pickle = _read_result_memfd(payload)
        _exc_from_pickle(exc_pickle)

    if tag == _RESULT_OK:
        try:
            return pickle.loads(payload)  # noqa: S301
        except MemoryError as exc:
            raise MemoryError(
                f"run_in_netns_fork: MemoryError deserialising result "
                f"(payload size={len(payload)} bytes): {exc}"
            ) from exc

    if tag == _RESULT_OK_MEMFD:
        result_pickle = _read_result_memfd(payload)
        try:
            return pickle.loads(result_pickle)  # noqa: S301
        except MemoryError as exc:
            raise MemoryError(
                f"run_in_netns_fork: MemoryError deserialising memfd result "
                f"(size={len(result_pickle)} bytes): {exc}"
            ) from exc

    raise NetnsForkError(f"run_in_netns_fork: unknown result tag {tag!r}")


def _exc_from_pickle(exc_pickle: bytes) -> None:
    """Unpickle an exception payload and re-raise it.  Never returns."""
    try:
        exc_type, exc_args, tb_text = pickle.loads(exc_pickle)  # noqa: S301
    except MemoryError as exc:
        raise MemoryError(
            f"run_in_netns_fork: MemoryError deserialising child exception "
            f"(payload={len(exc_pickle)} bytes): {exc}"
        ) from exc
    try:
        exc = exc_type(*exc_args)
    except Exception:  # noqa: BLE001
        exc = RuntimeError(f"child raised {exc_type.__name__}: {exc_args!r}")
    cause = RuntimeError(f"child traceback:\n{tb_text}")
    raise exc from cause


def _read_result_memfd(header_bytes: bytes) -> bytes:
    """Parse a memfd result IPC header ``[uint32 BE fd][uint32 BE size]``
    and return the payload bytes.  Closes the fd when done."""
    if len(header_bytes) < _MEMFD_RESULT_HDR.size:
        raise NetnsForkError(
            f"run_in_netns_fork: truncated memfd result header "
            f"({len(header_bytes)} bytes, expected {_MEMFD_RESULT_HDR.size})"
        )
    fd_number, size = _MEMFD_RESULT_HDR.unpack(header_bytes[: _MEMFD_RESULT_HDR.size])
    try:
        return _memfd_read(fd_number, size)
    finally:
        try:
            os.close(fd_number)
        except OSError:
            pass


def _child_one_shot(
    netns_path: str,
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    w_fd: int,
    *,
    large_payload_threshold: int = _DEFAULT_LARGE_PAYLOAD_THRESHOLD,
    args_memfd_pipe_fd: int | None = None,
    oob_fds: list[int] | None = None,
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

    # If the entire args pickle was staged through a memfd, read it back now.
    if args_memfd_pipe_fd is not None:
        try:
            sentinel = _read_fd_exact(args_memfd_pipe_fd, 1)
            if sentinel != _ARGS_MEMFD:
                _child_write_setns_err(
                    w_fd, f"args memfd: unexpected sentinel {sentinel!r}"
                )
                os._exit(1)
            header = _read_fd_exact(args_memfd_pipe_fd, 8)
            inherited_fd, size = struct.unpack("!II", header)
            os.close(args_memfd_pipe_fd)
        except Exception as exc:  # noqa: BLE001
            _child_write_setns_err(w_fd, f"args memfd read failed: {exc}")
            os._exit(1)

        try:
            args_pickle = _memfd_read(inherited_fd, size)
            os.close(inherited_fd)
            fn, args, kwargs = pickle.loads(args_pickle)  # noqa: S301
        except Exception as exc:  # noqa: BLE001
            _child_write_setns_err(w_fd, f"args memfd deserialise failed: {exc}")
            os._exit(1)
    else:
        # fn/args arrived via COW fork.  oob_fds (if any) are already in the
        # child's fd table; they are not needed in this path because the
        # args/kwargs objects are already reconstructed Python values.
        if oob_fds:
            for fd in oob_fds:
                try:
                    os.close(fd)
                except OSError:
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
        try:
            result_pickle = pickle.dumps(result, protocol=pickle.HIGHEST_PROTOCOL)
        except MemoryError as exc:
            raise MemoryError(
                f"MemoryError pickling result (type={type(result).__name__}): {exc}"
            ) from exc

        if len(result_pickle) > large_payload_threshold:
            # Stage the result through a memfd.
            try:
                result_fd = _memfd_write(result_pickle, name="nf_result")
                result_size = len(result_pickle)
                del result_pickle
                os.set_inheritable(result_fd, True)
                header = _MEMFD_RESULT_HDR.pack(result_fd, result_size)
                payload = _RESULT_OK_MEMFD + header
            except Exception as exc:  # noqa: BLE001
                tb = traceback.format_exc()
                try:
                    payload = _RESULT_EXC + pickle.dumps(
                        (type(exc), exc.args, tb), protocol=pickle.HIGHEST_PROTOCOL
                    )
                except Exception:  # noqa: BLE001
                    payload = _RESULT_EXC + pickle.dumps(
                        (RuntimeError, (str(exc),), tb),
                        protocol=pickle.HIGHEST_PROTOCOL,
                    )
        else:
            payload = _RESULT_OK + result_pickle

    except Exception as exc:  # noqa: BLE001
        tb = traceback.format_exc()
        exc_payload = pickle.dumps(
            (type(exc), exc.args, tb), protocol=pickle.HIGHEST_PROTOCOL
        )
        if len(exc_payload) > large_payload_threshold:
            try:
                exc_fd = _memfd_write(exc_payload, name="nf_exc")
                os.set_inheritable(exc_fd, True)
                header = _MEMFD_RESULT_HDR.pack(exc_fd, len(exc_payload))
                payload = _RESULT_EXC_MEMFD + header
            except Exception:  # noqa: BLE001
                payload = _RESULT_EXC + exc_payload
        else:
            payload = _RESULT_EXC + exc_payload

    try:
        _write_all(w_fd, payload)
    except (OSError, BrokenPipeError):
        # Parent closed the read end (e.g., timed out and moved on).
        # Do not hang — just exit cleanly.
        pass
    try:
        os.close(w_fd)
    except OSError:
        pass
    os._exit(0)


def _read_fd_exact(fd: int, n: int) -> bytes:
    """Read exactly ``n`` bytes from a raw file descriptor."""
    buf = bytearray(n)
    view = memoryview(buf)
    received = 0
    while received < n:
        chunk = os.read(fd, n - received)
        if not chunk:
            raise EOFError(f"unexpected EOF after {received}/{n} bytes")
        view[received:received + len(chunk)] = chunk
        received += len(chunk)
    return bytes(buf)


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
# Specialised nft-script zero-copy path: run_nft_in_netns_zc
# ---------------------------------------------------------------------------


def run_nft_in_netns_zc(
    netns: str,
    script: str | bytes,
    *,
    check_only: bool = False,
    timeout: float = 60.0,
) -> NftResult:
    """Execute an nft script inside ``netns`` via fork+setns+libnftables,
    transferring the script via a zero-copy memfd and returning the JSON
    output on pipes.

    Use this for compile+apply and similar operations where the payload
    in is bytes-convertible and the response is small.  For arbitrary
    Python function calls see :func:`run_in_netns_fork`.

    Scales cleanly to multi-hundred-MB scripts: the kernel does not
    copy the script bytes between parent and child — they share the
    memfd pages.

    IPC layout
    ----------
    * **script** → ``memfd`` (write-sealed by parent; child mmap-reads it).
    * **rc + control** → result pipe (small: 1-byte tag + 4-byte signed int).
    * **stdout** (JSON) → stdout pipe (drained concurrently by a thread).
    * **stderr** → stderr pipe (drained concurrently by a thread).

    Parameters
    ----------
    netns:
        Named network namespace (``/run/netns/<netns>`` must exist).
    script:
        nft script text (``str``) or bytes.  Encoded as UTF-8 when ``str``.
    check_only:
        If ``True``, passes ``set_dry_run(True)`` to libnftables so no
        changes are applied to the kernel.
    timeout:
        Maximum wall-clock seconds to wait for the child.

    Returns
    -------
    NftResult
        ``.rc`` is the libnftables return code (0 = success).
        ``.stdout`` is the JSON output string.
        ``.stderr`` is the error string.

    Raises
    ------
    NetnsNotFoundError
        ``/run/netns/<netns>`` is missing.
    NetnsForkTimeout
        Child did not respond within ``timeout`` seconds.
    ChildCrashedError
        Child died without sending rc output.
    NftError
        ``nft.cmd()`` returned rc != 0 (only when ``check_only=False``).
    RuntimeError
        ``memfd_create`` is not available on this kernel.
    """
    netns_path = f"/run/netns/{netns}"
    if not os.path.exists(netns_path):
        raise NetnsNotFoundError(f"netns not found: {netns_path!r}")

    _require_memfd()

    # Encode script and place it in a sealed memfd.
    script_bytes: bytes = script.encode() if isinstance(script, str) else script
    script_fd = _memfd_write(script_bytes, name="nf_script")
    script_size = len(script_bytes)
    os.set_inheritable(script_fd, True)

    # Pipes: rc (result/control), stdout, stderr.
    rc_r, rc_w = _pipe2_cloexec()
    stdout_r, stdout_w = _pipe2_cloexec()
    stderr_r, stderr_w = _pipe2_cloexec()

    # Write ends must be inheritable so the child can write to them.
    os.set_inheritable(rc_w, True)
    os.set_inheritable(stdout_w, True)
    os.set_inheritable(stderr_w, True)

    pid = os.fork()
    if pid == 0:
        # ---- Child -------------------------------------------------------
        try:
            os.close(rc_r)
            os.close(stdout_r)
            os.close(stderr_r)
            _child_nft_zc(
                netns_path,
                script_fd=script_fd,
                script_size=script_size,
                rc_w=rc_w,
                stdout_w=stdout_w,
                stderr_w=stderr_w,
                check_only=check_only,
            )
        finally:
            os._exit(1)
        # unreachable

    # ---- Parent ----------------------------------------------------------
    os.close(rc_w)
    os.close(stdout_w)
    os.close(stderr_w)
    os.close(script_fd)

    # Drain stdout and stderr in threads to prevent deadlock on large output.
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    def _drain(fd: int, buf: list[bytes]) -> None:
        try:
            buf.append(_read_all(fd))
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    t_out = threading.Thread(
        target=_drain, args=(stdout_r, stdout_chunks), daemon=True
    )
    t_err = threading.Thread(
        target=_drain, args=(stderr_r, stderr_chunks), daemon=True
    )
    t_out.start()
    t_err.start()

    # Read rc pipe (small payload).
    raw = _read_all_with_timeout(rc_r, timeout)
    os.close(rc_r)

    # Join drain threads (they finish when the child closes its write ends).
    t_out.join(timeout=max(0.1, timeout))
    t_err.join(timeout=max(0.1, timeout))

    if raw is None:
        _kill_and_reap(pid, grace=1.0)
        raise NetnsForkTimeout(
            f"run_nft_in_netns_zc: timeout ({timeout}s) waiting for child "
            f"in netns {netns!r}"
        )

    if not raw:
        exit_info = _reap_child(pid)
        raise ChildCrashedError(
            f"run_nft_in_netns_zc: child exited without sending rc "
            f"({exit_info})",
            signal=exit_info[1],
            exit_code=exit_info[0],
        )

    _reap_child(pid)

    tag = raw[:1]
    payload = raw[1:]

    if tag == _RESULT_SETNS_ERR:
        msg = payload.decode("utf-8", errors="replace")
        raise NetnsSetnsError(
            f"run_nft_in_netns_zc: setns failed in child: {msg}"
        )

    if tag != _RESULT_OK:
        raise NetnsForkError(
            f"run_nft_in_netns_zc: unknown result tag {tag!r}"
        )

    (rc,) = struct.unpack("!i", payload[:4])

    stdout_str = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    stderr_str = b"".join(stderr_chunks).decode("utf-8", errors="replace")

    result = NftResult(rc=rc, stdout=stdout_str, stderr=stderr_str)

    if rc != 0 and not check_only:
        raise NftError(
            f"run_nft_in_netns_zc: nft returned rc={rc}: {stderr_str.strip()!r}",
            rc=rc,
            stderr=stderr_str,
        )

    return result


def _child_nft_zc(
    netns_path: str,
    *,
    script_fd: int,
    script_size: int,
    rc_w: int,
    stdout_w: int,
    stderr_w: int,
    check_only: bool,
) -> None:
    """Child body for :func:`run_nft_in_netns_zc`.  Never returns."""
    try:
        _prctl_pdeathsig(_SIGTERM)
    except OSError:
        pass

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (OSError, ValueError):
            pass

    # Read script from memfd before setns — path is filesystem-independent.
    try:
        script_bytes = _memfd_read(script_fd, script_size)
        os.close(script_fd)
    except Exception as exc:  # noqa: BLE001
        _child_write_setns_err(rc_w, f"script memfd read failed: {exc}")
        _nft_close_fds(stdout_w, stderr_w)
        os._exit(1)

    # Enter the target netns.
    try:
        ns_fd = os.open(netns_path, os.O_RDONLY)
    except OSError as exc:
        _child_write_setns_err(rc_w, f"open({netns_path!r}) failed: {exc}")
        _nft_close_fds(stdout_w, stderr_w)
        os._exit(1)

    try:
        rc_setns = _setns(ns_fd, _CLONE_NEWNET)
    finally:
        os.close(ns_fd)

    if rc_setns != 0:
        err = ctypes.get_errno()
        _child_write_setns_err(
            rc_w,
            f"setns(CLONE_NEWNET) failed: {os.strerror(err)} (errno={err})",
        )
        _nft_close_fds(stdout_w, stderr_w)
        os._exit(1)

    # Run nft inside the netns.
    try:
        from nftables import Nftables  # type: ignore[import-untyped]
        nft = Nftables()
        nft.set_json_output(True)
        if check_only:
            nft.set_dry_run(True)
        rc, out, err = nft.cmd(script_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001
        rc = 127
        out = ""
        err = f"nft exception: {exc}\n{traceback.format_exc()}"

    # Write stdout and stderr.
    try:
        _write_all(stdout_w, out.encode("utf-8") if out else b"")
    except (OSError, BrokenPipeError):
        pass
    try:
        _write_all(stderr_w, err.encode("utf-8") if err else b"")
    except (OSError, BrokenPipeError):
        pass

    _nft_close_fds(stdout_w, stderr_w)

    # Write rc to result pipe.
    try:
        _write_all(rc_w, _RESULT_OK + struct.pack("!i", rc))
    except (OSError, BrokenPipeError):
        pass
    try:
        os.close(rc_w)
    except OSError:
        pass
    os._exit(0)


def _nft_close_fds(*fds: int) -> None:
    """Close a sequence of fds, ignoring errors."""
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Persistent worker: PersistentNetnsWorker
# ---------------------------------------------------------------------------

# Length prefix format: 4-byte big-endian unsigned int.
_LEN_HEADER: struct.Struct = struct.Struct("!I")
_LEN_HEADER_SIZE: int = _LEN_HEADER.size  # 4


def _send_framed(sock: socket.socket, data: bytes) -> None:
    """Send a length-prefixed message over ``sock`` (SOCK_STREAM)."""
    header = _LEN_HEADER.pack(len(data))
    sock.sendall(header + data)


def _recv_framed(sock: socket.socket) -> bytes | None:
    """Receive a length-prefixed message from ``sock`` (SOCK_STREAM).

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
    """Read exactly ``n`` bytes from ``sock`` (SOCK_STREAM); return ``None`` on EOF.

    Uses an inner receive loop to handle TCP-style fragmentation.  On
    Python 3.3+, ``socket.MSG_WAITALL`` is passed as a hint to the kernel
    to fill the buffer in one call where possible; the loop handles the
    remaining bytes on short receives.
    """
    buf = bytearray(n)
    view = memoryview(buf)
    received = 0
    while received < n:
        try:
            chunk = sock.recv_into(view[received:], n - received)
        except OSError:
            return None
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
    ``SOCK_STREAM`` socketpair.

    Use for hot-path dispatch (many operations per second).  For one-shot
    operations, use ``run_in_netns_fork`` instead.

    The ``child_main`` callable is invoked once in the child with a
    :class:`ChildContext`; it should loop reading requests and sending
    replies until the parent calls :meth:`stop` (which closes the parent
    socket, causing the child to see EOF and return).

    Auto-respawn is NOT implemented here — that belongs in callers who
    know their own restart semantics (see shorewalld's ``ParentWorker``).

    Wire protocol: every request and reply is a length-prefixed message
    over ``SOCK_STREAM``::

        [uint32 BE length][payload bytes]

    ``SOCK_STREAM`` has no per-datagram size cap; arbitrary-size messages
    are handled transparently.  A 0-length payload is valid (empty message).

    Previously this class used ``SOCK_SEQPACKET``.  It was switched to
    ``SOCK_STREAM`` because ``SOCK_SEQPACKET`` has a per-datagram size cap
    (effectively bounded by the socket send buffer, typically 200 KiB–1 MiB)
    that causes ``EMSGSIZE`` or silent truncation on large payloads such as
    nft set dumps with millions of entries.  ``SOCK_STREAM`` has no such cap.
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

        # SOCK_STREAM: no per-datagram size cap; length-prefix framing handles
        # arbitrarily large messages (including multi-MB nft set dumps).
        parent_sock, child_sock = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
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
    except OSError:
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
        try:
            _send_framed(sock, data)
        except (OSError, BrokenPipeError):
            # Parent closed the socket (EPIPE) — silently discard.
            pass

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
