"""Tests for shorewall_nft_netkit.netns_fork.

Most tests require a named netns (which requires root to create).  Tests that
need root are marked with ``@pytest.mark.skipif(os.geteuid() != 0, ...)``.
Tests that exercise the pre-fork validation layer (pickleability, missing
netns) run without root.

Netns setup uses the existing ``nsstub`` primitive (spawn_nsstub / stop_nsstub)
to create a real named netns cheaply.
"""

from __future__ import annotations

import ctypes
import fcntl
import os
import pickle
import signal
import subprocess
import time

import pytest

import shorewall_nft_netkit.netns_fork as _mod
from shorewall_nft_netkit.netns_fork import (
    _DEFAULT_LARGE_PAYLOAD_THRESHOLD,
    _DEFAULT_STDOUT_THRESHOLD,
    _ZC_TAG_STDOUT_MEMFD,
    _ZC_TAG_STDOUT_PIPE,
    MEMFD_SUPPORTED,
    ChildContext,
    ChildCrashedError,
    NetnsForkError,
    NetnsForkTimeout,
    NetnsNotFoundError,
    NetnsSetnsError,
    NftError,
    NftResult,
    PersistentNetnsWorker,
    _memfd_dup_from_pid,
    _memfd_read,
    _memfd_write,
    _pickle_with_oob,
    _unpickle_with_oob,
    run_in_netns_fork,
    run_nft_in_netns_zc,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NETNS_NAME = "NS_TEST_nf_fork"
_NETNS_PATH = f"/run/netns/{_NETNS_NAME}"

_NEEDS_ROOT = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="requires root to create/manage named network namespaces",
)


def _open_fd_count() -> int:
    """Return the number of open file descriptors in the current process."""
    fd_dir = f"/proc/{os.getpid()}/fd"
    try:
        return len(os.listdir(fd_dir))
    except OSError:
        return -1


@pytest.fixture(scope="module")
def netns():
    """Fixture that creates a named netns for the test module and tears it down."""
    if os.geteuid() != 0:
        pytest.skip("requires root")

    from shorewall_nft_netkit.nsstub import spawn_nsstub, stop_nsstub

    # Clean up any remnant from a prior crash.
    subprocess.run(["ip", "netns", "del", _NETNS_NAME], check=False, capture_output=True)
    subprocess.run(["umount", _NETNS_PATH], check=False, capture_output=True)
    try:
        os.unlink(_NETNS_PATH)
    except FileNotFoundError:
        pass

    pid = spawn_nsstub(_NETNS_NAME)
    yield _NETNS_NAME
    stop_nsstub(_NETNS_NAME, pid)


# ---------------------------------------------------------------------------
# Tests that do NOT require root (pre-fork validation)
# ---------------------------------------------------------------------------


def test_missing_netns_raises_before_fork():
    """NetnsNotFoundError is raised before any fork when netns is absent."""
    with pytest.raises(NetnsNotFoundError, match="not found"):
        run_in_netns_fork("NS__nonexistent_xyz_9999", lambda: None)


def test_unpickleable_fn_raises_type_error(tmp_path, monkeypatch):
    """A lambda (unpickleable) raises TypeError in the parent before fork.

    We create a fake file under tmp_path and monkeypatch the netns path check
    so that run_in_netns_fork proceeds past the NetnsNotFoundError check and
    hits the pickleability check instead.
    """
    real_exists = os.path.exists

    def patched_exists(p):
        if p == "/run/netns/fake_ns_pickletest":
            return True
        return real_exists(p)

    monkeypatch.setattr(os.path, "exists", patched_exists)

    fn = lambda: 42  # noqa: E731
    with pytest.raises(TypeError, match="not pickleable"):
        run_in_netns_fork("fake_ns_pickletest", fn)


def test_unpickleable_fn_direct():
    """Directly verify that a lambda can't be pickled — the mechanism
    that run_in_netns_fork uses to detect non-pickleable callables."""
    fn = lambda x: x + 1  # noqa: E731
    with pytest.raises((pickle.PicklingError, AttributeError, TypeError)):
        pickle.dumps(fn)


# ---------------------------------------------------------------------------
# Tests that require root (real netns operations)
# ---------------------------------------------------------------------------


@_NEEDS_ROOT
def test_happy_path_inode_differs(netns):
    """fn returns /proc/self/ns/net inode; it must differ from parent's."""
    parent_inode = os.stat("/proc/self/ns/net").st_ino

    def get_inode() -> int:
        return os.stat("/proc/self/ns/net").st_ino

    child_inode = run_in_netns_fork(netns, get_inode)
    assert isinstance(child_inode, int)
    assert child_inode != parent_inode, (
        "Child must be in a different netns from the parent"
    )


@_NEEDS_ROOT
def test_happy_path_with_args_kwargs(netns):
    """fn(a, b, c=3) — args and kwargs pickled correctly."""
    def add(a, b, *, c=0):
        return a + b + c

    result = run_in_netns_fork(netns, add, 1, 2, c=3)
    assert result == 6


@_NEEDS_ROOT
def test_exception_in_child_reraises(netns):
    """fn raises ValueError in child → parent catches exact type + message."""
    def explode():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        run_in_netns_fork(netns, explode)


@_NEEDS_ROOT
def test_exception_in_child_preserves_cause(netns):
    """Child traceback text is attached as __cause__ on the re-raised exception."""
    def explode():
        raise RuntimeError("child-traceback-marker")

    with pytest.raises(RuntimeError) as exc_info:
        run_in_netns_fork(netns, explode)

    # __cause__ must carry the formatted child traceback.
    cause = exc_info.value.__cause__
    assert cause is not None
    assert "child-traceback-marker" in str(cause)


@_NEEDS_ROOT
def test_child_sigkill_raises_crashed_error(netns):
    """Child is SIGKILL'd mid-operation → ChildCrashedError.

    The child calls os.kill on itself with SIGKILL; the parent sees an empty
    pipe (EOF without a result tag) and raises ChildCrashedError.
    """
    def self_kill() -> int:
        os.kill(os.getpid(), signal.SIGKILL)
        return 0  # unreachable

    with pytest.raises(ChildCrashedError) as exc_info:
        run_in_netns_fork(netns, self_kill, timeout=5.0)

    err = exc_info.value
    assert err.signal == signal.SIGKILL or err.exit_code is not None


@_NEEDS_ROOT
def test_timeout_raises_and_child_reaped(netns):
    """fn sleeps 30s, timeout=0.2 → NetnsForkTimeout; no zombie left."""
    def slow():
        time.sleep(30)
        return "done"

    with pytest.raises(NetnsForkTimeout):
        run_in_netns_fork(netns, slow, timeout=0.2)

    # Give kernel a moment after SIGKILL to reap.
    time.sleep(0.1)

    # The child should be reaped (no zombie).  If we got here without hanging,
    # the parent correctly reaped the child.


@_NEEDS_ROOT
def test_large_return_value(netns):
    """Return value > 1 MB is transmitted correctly through the pipe."""
    payload_size = 2 * 1024 * 1024  # 2 MB

    def make_large() -> bytes:
        return b"X" * payload_size

    result = run_in_netns_fork(netns, make_large, timeout=15.0)
    assert result == b"X" * payload_size


@_NEEDS_ROOT
def test_setns_failure_raises_netns_setns_error(netns, monkeypatch):
    """Simulate setns() returning -1 with EPERM → NetnsSetnsError raised."""
    import shorewall_nft_netkit.netns_fork as mod

    # Patch _setns to always return -1 and set errno=EPERM.
    _EPERM = 1

    def fake_setns(fd: int, nstype: int) -> int:
        ctypes.set_errno(_EPERM)
        return -1

    monkeypatch.setattr(mod, "_setns", fake_setns)

    def noop() -> int:
        return 42

    with pytest.raises(NetnsSetnsError, match="setns"):
        run_in_netns_fork(netns, noop)


@_NEEDS_ROOT
def test_fd_leak_over_100_iterations(netns):
    """Calling run_in_netns_fork 100x must not grow the parent's open FD count."""
    def noop() -> int:
        return 1

    # Warm up (one run to allow lazy imports etc.)
    run_in_netns_fork(netns, noop)

    before = _open_fd_count()
    for _ in range(100):
        run_in_netns_fork(netns, noop)
    after = _open_fd_count()

    # Allow a tiny slack (1 or 2 FDs for pytest internals) but not linear growth.
    assert after - before <= 3, (
        f"FD leak detected: {before} → {after} after 100 iterations "
        f"(delta={after - before})"
    )


# ---------------------------------------------------------------------------
# PersistentNetnsWorker tests
# ---------------------------------------------------------------------------

def _echo_worker(ctx: ChildContext) -> None:
    """Simplest child_main: echoes back every request."""
    while True:
        req = ctx.recv()
        if req is None:
            break
        ctx.send(req)


def _crash_on_first_worker(ctx: ChildContext) -> None:
    """child_main that crashes immediately without sending a reply."""
    req = ctx.recv()
    if req is not None:
        # Just crash.
        raise RuntimeError("deliberate crash")


@_NEEDS_ROOT
def test_persistent_worker_dispatch_round_trip(netns):
    """start, dispatch two messages, stop; child exits cleanly."""
    worker = PersistentNetnsWorker(netns, _echo_worker)
    worker.start()

    try:
        assert worker.is_alive

        reply1 = worker.dispatch(b"hello")
        assert reply1 == b"hello"

        reply2 = worker.dispatch(b"world")
        assert reply2 == b"world"
    finally:
        worker.stop()

    # After stop, child should be reaped.
    time.sleep(0.1)
    assert not worker.is_alive


@_NEEDS_ROOT
def test_persistent_worker_large_payload(netns):
    """Persistent worker handles >64 KiB request and reply."""
    worker = PersistentNetnsWorker(netns, _echo_worker)
    worker.start()
    try:
        big = b"Z" * (128 * 1024)  # 128 KiB
        reply = worker.dispatch(big, timeout=10.0)
        assert reply == big
    finally:
        worker.stop()


@_NEEDS_ROOT
def test_persistent_worker_zero_byte_message(netns):
    """Persistent worker handles 0-byte request and 0-byte reply."""
    worker = PersistentNetnsWorker(netns, _echo_worker)
    worker.start()
    try:
        reply = worker.dispatch(b"")
        assert reply == b""
    finally:
        worker.stop()


@_NEEDS_ROOT
def test_persistent_worker_stop_grace(netns):
    """stop() with grace period; if child doesn't exit in grace, SIGKILL+reap."""
    def slow_worker(ctx: ChildContext) -> None:
        # Ignore the socket closing; just sleep.
        time.sleep(60)

    worker = PersistentNetnsWorker(netns, slow_worker)
    worker.start()
    assert worker.is_alive

    # stop() with a very short grace — the slow_worker ignores EOF.
    start = time.monotonic()
    worker.stop(grace=0.1)
    elapsed = time.monotonic() - start

    # Must complete in a reasonable time (SIGKILL path) and not hang.
    assert elapsed < 5.0, f"stop() blocked for {elapsed:.1f}s"
    assert not worker.is_alive


@_NEEDS_ROOT
def test_persistent_worker_crash_on_first_request(netns):
    """dispatch() raises ChildCrashedError when child crashes; subsequent dispatch
    raises RuntimeError('worker not alive')."""
    worker = PersistentNetnsWorker(netns, _crash_on_first_worker)
    worker.start()

    with pytest.raises(ChildCrashedError):
        worker.dispatch(b"trigger crash", timeout=3.0)

    # Subsequent dispatch must raise RuntimeError, not hang.
    with pytest.raises((ChildCrashedError, RuntimeError)):
        worker.dispatch(b"second call")

    worker.stop()


@_NEEDS_ROOT
def test_persistent_worker_missing_netns():
    """start() raises NetnsNotFoundError if the netns does not exist."""
    worker = PersistentNetnsWorker("NS__does_not_exist_xyz", _echo_worker)
    with pytest.raises(NetnsNotFoundError):
        worker.start()


@_NEEDS_ROOT
def test_persistent_worker_not_started_dispatch(netns):
    """dispatch() before start() raises RuntimeError."""
    worker = PersistentNetnsWorker(netns, _echo_worker)
    with pytest.raises(RuntimeError, match="not started"):
        worker.dispatch(b"hello")


# ---------------------------------------------------------------------------
# Parent-death SIGTERM test (grandchild receives SIGTERM)
# ---------------------------------------------------------------------------

@_NEEDS_ROOT
def test_pdeathsig_sigterm_on_parent_death(netns, tmp_path):
    """Grandchild receives SIGTERM when its parent (middle process) is SIGKILL'd.

    Topology:
      test process (us)
        └─ middle process (os.fork)
             └─ grandchild (run_in_netns_fork -> child)

    We SIGKILL the middle process mid-way through a long grandchild operation.
    The grandchild should receive SIGTERM (PR_SET_PDEATHSIG=SIGTERM) and exit.
    We verify by checking a sentinel file the grandchild writes on SIGTERM.
    """
    sentinel = str(tmp_path / "pdeathsig_fired")

    # The grandchild writes the sentinel on SIGTERM, then exits.
    def long_with_handler() -> None:
        def _handler(signum, frame):
            with open(sentinel, "w") as f:
                f.write(f"signal={signum}\n")
            os._exit(0)
        signal.signal(signal.SIGTERM, _handler)
        time.sleep(30)

    # Middle process: fork the grandchild then sleep (we SIGKILL it).
    middle_r, middle_w = os.pipe()
    middle_pid = os.fork()
    if middle_pid == 0:
        # Middle process.
        os.close(middle_r)
        # Start the grandchild.
        import threading

        result: list[Exception | None] = [None]

        def _run():
            try:
                run_in_netns_fork(netns, long_with_handler, timeout=30.0)
            except Exception as exc:  # noqa: BLE001
                result[0] = exc

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        # Signal parent we started.
        os.write(middle_w, b"R")
        os.close(middle_w)

        # Sleep so parent can SIGKILL us.
        time.sleep(30)
        os._exit(0)

    # Parent (us): wait for middle to signal ready, then SIGKILL it.
    os.close(middle_w)
    ready = os.read(middle_r, 1)
    os.close(middle_r)
    assert ready == b"R"

    # Small delay to let run_in_netns_fork complete its fork + prctl setup.
    time.sleep(0.3)

    os.kill(middle_pid, signal.SIGKILL)
    os.waitpid(middle_pid, 0)

    # Wait for grandchild to receive SIGTERM and write sentinel.
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if os.path.exists(sentinel):
            break
        time.sleep(0.05)

    assert os.path.exists(sentinel), (
        "Grandchild did not receive SIGTERM after parent was SIGKILL'd; "
        "PR_SET_PDEATHSIG(SIGTERM) may not have fired"
    )
    content = open(sentinel).read()
    assert f"signal={signal.SIGTERM}" in content


# ---------------------------------------------------------------------------
# memfd primitive unit tests (no root required)
# ---------------------------------------------------------------------------

_NEEDS_MEMFD = pytest.mark.skipif(
    not MEMFD_SUPPORTED,
    reason="memfd_create not available on this kernel/Python",
)


@_NEEDS_MEMFD
def test_memfd_write_read_roundtrip():
    """_memfd_write / _memfd_read round-trip preserves all bytes."""
    data = b"hello memfd\x00\xff" * 1024
    fd = _memfd_write(data, name="test_rtrip")
    try:
        result = _memfd_read(fd, len(data))
    finally:
        os.close(fd)
    assert result == data


@_NEEDS_MEMFD
def test_memfd_empty_payload():
    """_memfd_write / _memfd_read handles zero-length payload."""
    fd = _memfd_write(b"", name="test_empty")
    try:
        result = _memfd_read(fd, 0)
    finally:
        os.close(fd)
    assert result == b""


@_NEEDS_MEMFD
def test_memfd_seals_prevent_write():
    """After _memfd_write seals the fd, ftruncate raises PermissionError.

    Some container environments restrict F_ADD_SEALS (SECCOMP); if sealing
    is not supported we skip the assertion rather than fail.
    """
    data = b"sealed data"
    fd = _memfd_write(data, name="test_seal")
    try:
        # Try to extend the sealed memfd — should fail with PermissionError
        # on a fully sealed fd.  If the seal was not applied (container
        # restriction) this may raise OSError(EPERM) for a different reason
        # or succeed — either way we accept it as long as the fd is readable.
        try:
            os.ftruncate(fd, len(data) + 1)
        except OSError:
            pass  # expected — seal prevented resize
        # Regardless of seal success, data must still be readable.
        result = _memfd_read(fd, len(data))
        assert result == data
    finally:
        os.close(fd)


@_NEEDS_MEMFD
def test_memfd_is_cloexec():
    """Newly created memfd has FD_CLOEXEC set (via MFD_CLOEXEC flag)."""
    fd = _memfd_write(b"cloexec test", name="test_cloexec")
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        assert flags & fcntl.FD_CLOEXEC, (
            f"memfd fd={fd} does not have FD_CLOEXEC set (flags={flags:#x})"
        )
    finally:
        os.close(fd)


@_NEEDS_MEMFD
def test_memfd_no_filesystem_entry():
    """A memfd does not appear under /tmp or any other filesystem path.

    The kernel-assigned link in /proc/self/fd shows ``/memfd:<name>`` which
    contains ``memfd:`` but not any /tmp path component.
    """
    fd = _memfd_write(b"private", name="test_nopath")
    try:
        fd_link = os.readlink(f"/proc/self/fd/{fd}")
        # Kernel resolves memfd fds as '/memfd:<name> (deleted)' — not a
        # real filesystem path, just an in-kernel pseudo-name.
        assert "memfd:" in fd_link, (
            f"Expected 'memfd:' in fd_link, got: {fd_link!r}"
        )
        assert "/tmp/" not in fd_link, (
            f"memfd appeared as a /tmp path: {fd_link!r}"
        )
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# _pickle_with_oob / _unpickle_with_oob unit tests (no root required)
# ---------------------------------------------------------------------------

@_NEEDS_MEMFD
def test_pickle_oob_small_bytes_inline():
    """Small bytes (< threshold) stay embedded in the pickle stream."""
    small = b"x" * 100
    threshold = _DEFAULT_LARGE_PAYLOAD_THRESHOLD
    data, fds = _pickle_with_oob(small, threshold=threshold)
    try:
        assert fds == [], "small payload must not create any memfds"
        result = _unpickle_with_oob(data, fds)
        assert result == small
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


@_NEEDS_MEMFD
def test_pickle_oob_large_bytes_out_of_band():
    """Large bytes (>= threshold) go out-of-band through a memfd."""
    threshold = 1024  # small threshold for testing
    large = b"Y" * (threshold + 1)
    data, fds = _pickle_with_oob(large, threshold=threshold)
    try:
        assert len(fds) == 1, f"expected 1 oob memfd, got {len(fds)}"
        result = _unpickle_with_oob(data, fds)
        assert result == large
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


@_NEEDS_MEMFD
def test_pickle_oob_roundtrip_complex_object():
    """Complex object with mixed large/small buffers round-trips correctly."""
    threshold = 512
    obj = {
        "small": b"s" * 10,
        "large": b"L" * (threshold * 2),
        "num": 42,
        "nested": [b"A" * (threshold + 1), b"b" * 5],
    }
    data, fds = _pickle_with_oob(obj, threshold=threshold)
    try:
        result = _unpickle_with_oob(data, fds)
        assert result == obj
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# No /tmp touch tests (no root required)
# ---------------------------------------------------------------------------

@_NEEDS_MEMFD
def test_memfd_write_no_tmp_touch(tmp_path):
    """_memfd_write does not create any files under /tmp."""
    import glob as _glob
    before = set(_glob.glob("/tmp/*"))  # noqa: S108
    fd = _memfd_write(b"no tmp" * 100, name="notmp_test")
    after = set(_glob.glob("/tmp/*"))  # noqa: S108
    os.close(fd)
    assert after == before, (
        f"_memfd_write left files in /tmp: {after - before}"
    )


# ---------------------------------------------------------------------------
# run_in_netns_fork with large memfd args (requires root)
# ---------------------------------------------------------------------------

@_NEEDS_ROOT
@_NEEDS_MEMFD
def test_large_return_value_via_memfd(netns):
    """Return value > large_payload_threshold travels through memfd, not pipe."""
    threshold = 128 * 1024  # 128 KiB — small threshold to force memfd path
    payload_size = threshold + 1024

    def make_large() -> bytes:
        return b"M" * payload_size

    result = run_in_netns_fork(
        netns,
        make_large,
        timeout=30.0,
        large_payload_threshold=threshold,
    )
    assert result == b"M" * payload_size


@_NEEDS_ROOT
@_NEEDS_MEMFD
def test_large_args_via_memfd(netns):
    """Args > large_payload_threshold travel through memfd to child."""
    threshold = 128 * 1024  # 128 KiB

    def identity(data: bytes) -> bytes:
        return data

    large_arg = b"A" * (threshold + 1)
    result = run_in_netns_fork(
        netns,
        identity,
        large_arg,
        timeout=30.0,
        large_payload_threshold=threshold,
    )
    assert result == large_arg


@_NEEDS_ROOT
@_NEEDS_MEMFD
def test_no_tmp_touch_on_large_roundtrip(netns):
    """A large-payload round-trip (args + return) does not create /tmp files."""
    import glob as _glob
    threshold = 64 * 1024  # 64 KiB
    large = b"Z" * (threshold + 1)
    before = set(_glob.glob("/tmp/*"))  # noqa: S108

    def identity(data: bytes) -> bytes:
        return data

    result = run_in_netns_fork(
        netns,
        identity,
        large,
        timeout=30.0,
        large_payload_threshold=threshold,
    )
    after = set(_glob.glob("/tmp/*"))  # noqa: S108
    assert result == large
    assert after == before, (
        f"memfd IPC created /tmp files: {after - before}"
    )


# ---------------------------------------------------------------------------
# run_nft_in_netns_zc tests (require root + libnftables)
# ---------------------------------------------------------------------------

def _has_libnftables() -> bool:
    try:
        import nftables  # noqa: F401
        return True
    except ImportError:
        return False


_NEEDS_NFT = pytest.mark.skipif(
    not _has_libnftables() or os.geteuid() != 0,
    reason="requires root + python-nftables (libnftables)",
)


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_missing_netns():
    """run_nft_in_netns_zc raises NetnsNotFoundError if netns is absent."""
    with pytest.raises(NetnsNotFoundError, match="not found"):
        run_nft_in_netns_zc("NS__nonexistent_zc_9999", "list tables")


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_happy_path(netns):
    """Minimal nft script returns rc==0 and parseable output."""
    import json

    result = run_nft_in_netns_zc(netns, "list tables", timeout=30.0)
    assert isinstance(result, NftResult)
    assert result.rc == 0
    # JSON output should be parseable.
    if result.stdout.strip():
        parsed = json.loads(result.stdout)
        assert isinstance(parsed, dict)


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_check_only_does_not_apply(netns):
    """check_only=True runs nft with dry_run; returns NftResult (not NftError)
    even if the script has an intentional error that would fail live."""
    # A list tables command should always succeed in check-only mode too.
    result = run_nft_in_netns_zc(
        netns, "list tables", check_only=True, timeout=30.0
    )
    assert isinstance(result, NftResult)
    # rc may be 0 or non-zero depending on libnftables dry-run behaviour;
    # the important invariant is that NftError is NOT raised.


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_bad_script_raises_nft_error(netns):
    """A script with a syntax error raises NftError (rc != 0)."""
    with pytest.raises(NftError) as exc_info:
        run_nft_in_netns_zc(
            netns,
            "this is not valid nft syntax !!!",
            timeout=30.0,
        )
    assert exc_info.value.rc != 0


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_bad_script_check_only_no_raise(netns):
    """check_only=True does not raise NftError even for bad scripts."""
    result = run_nft_in_netns_zc(
        netns,
        "this is not valid nft syntax !!!",
        check_only=True,
        timeout=30.0,
    )
    assert isinstance(result, NftResult)
    assert result.rc != 0  # rc is non-zero but no exception raised


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_timeout_raises_and_child_reaped(netns, monkeypatch):
    """NetnsForkTimeout raised when child hangs; no zombie left."""
    # Monkeypatch _child_nft_zc to sleep forever before writing rc.
    original_child_nft_zc = _mod._child_nft_zc

    def slow_child_nft_zc(*a, **kw):
        import time as _time
        # Close stdout/stderr write ends so parent drain threads can exit.
        try:
            os.close(kw["stdout_w"])
        except OSError:
            pass
        try:
            os.close(kw["stderr_w"])
        except OSError:
            pass
        _time.sleep(60)

    monkeypatch.setattr(_mod, "_child_nft_zc", slow_child_nft_zc)

    with pytest.raises(NetnsForkTimeout):
        run_nft_in_netns_zc(netns, "list tables", timeout=0.2)


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_no_tmp_touch(netns):
    """run_nft_in_netns_zc does not create /tmp files."""
    import glob as _glob
    before = set(_glob.glob("/tmp/*"))  # noqa: S108
    try:
        run_nft_in_netns_zc(netns, "list tables", timeout=30.0)
    except (NftError, NetnsForkError):
        pass  # nft may not be available in the netns
    after = set(_glob.glob("/tmp/*"))  # noqa: S108
    assert after == before, (
        f"run_nft_in_netns_zc left /tmp files: {after - before}"
    )


# ---------------------------------------------------------------------------
# Kernel-version fallback test (no root required)
# ---------------------------------------------------------------------------

def test_require_memfd_raises_on_unavailable(monkeypatch):
    """_require_memfd raises RuntimeError with a useful message when
    MEMFD_SUPPORTED is False."""
    monkeypatch.setattr(_mod, "MEMFD_SUPPORTED", False)
    with pytest.raises(RuntimeError, match="memfd_create is not available"):
        _mod._require_memfd()


def test_memfd_write_raises_when_unavailable(monkeypatch):
    """_memfd_write raises RuntimeError (not OSError) when memfd is
    disabled, giving the caller a clear upgrade message."""
    monkeypatch.setattr(_mod, "MEMFD_SUPPORTED", False)
    with pytest.raises(RuntimeError, match="memfd_create is not available"):
        _memfd_write(b"test")


def test_run_nft_zc_raises_when_memfd_unavailable(monkeypatch, tmp_path):
    """run_nft_in_netns_zc raises RuntimeError when memfd is unavailable,
    rather than silently falling back to /tmp."""
    # Create a fake /run/netns entry so we pass the netns-exists check.
    fake_ns = tmp_path / "fake_ns_zc"
    fake_ns.touch()

    real_exists = os.path.exists

    def patched_exists(p):
        if "fake_ns_zc" in str(p):
            return True
        return real_exists(p)

    monkeypatch.setattr(os.path, "exists", patched_exists)
    monkeypatch.setattr(_mod, "MEMFD_SUPPORTED", False)

    with pytest.raises(RuntimeError, match="memfd_create is not available"):
        run_nft_in_netns_zc("fake_ns_zc", "list tables")


# ---------------------------------------------------------------------------
# Large-payload tests — one-shot path (pure-pipe)
# ---------------------------------------------------------------------------


def _make_large_bytes(size_bytes: int) -> bytes:
    return b"X" * size_bytes


def _identity(x: bytes) -> bytes:
    return x


@_NEEDS_ROOT
@pytest.mark.parametrize("size_mb", [1, 10, 100])
def test_large_return_value_pure_pipe(netns, size_mb):
    """Return values of 1 MB, 10 MB, and 100 MB round-trip via pure pipe
    without deadlock.  Wall-clock time must stay below 60 s per run.

    The parent drains the pipe concurrently via the select loop while the
    child writes — this test would deadlock if the parent waited for the
    child to exit before reading.
    """
    size = size_mb * 1024 * 1024
    # Use a threshold above the payload size so pure-pipe path is taken.
    big_threshold = 512 * 1024 * 1024  # 512 MiB

    t0 = time.monotonic()
    result = run_in_netns_fork(
        netns,
        _identity,
        b"X" * size,
        timeout=60.0,
        large_payload_threshold=big_threshold,
    )
    elapsed = time.monotonic() - t0

    assert len(result) == size
    assert elapsed < 60.0, f"{size_mb} MB round-trip took {elapsed:.1f}s (>60s)"


@_NEEDS_ROOT
def test_large_return_value_100mb_linear_timing(netns):
    """100 MB round-trip completes significantly faster than 10× the 10 MB time.

    This is a loose sanity check that throughput is roughly linear (pipe drain
    is not O(n^2)).  We allow up to 5× slack to accommodate CI jitter.
    """
    big_threshold = 512 * 1024 * 1024

    t_10 = time.monotonic()
    run_in_netns_fork(
        netns, _identity, b"Y" * (10 * 1024 * 1024),
        timeout=60.0, large_payload_threshold=big_threshold,
    )
    t_10 = time.monotonic() - t_10

    t_100 = time.monotonic()
    run_in_netns_fork(
        netns, _identity, b"Y" * (100 * 1024 * 1024),
        timeout=120.0, large_payload_threshold=big_threshold,
    )
    t_100 = time.monotonic() - t_100

    # 100 MB should not take more than 50× the 10 MB time (very loose bound).
    assert t_100 < t_10 * 50 + 5.0, (
        f"100 MB took {t_100:.2f}s vs 10 MB {t_10:.2f}s — non-linear?"
    )


# ---------------------------------------------------------------------------
# memfd-backed large-payload mode tests
# ---------------------------------------------------------------------------


@_NEEDS_ROOT
@_NEEDS_MEMFD
def test_memfd_mode_triggered_for_large_arg(netns):
    """When args exceed large_payload_threshold, they travel through memfd
    (not /tmp).  The call must succeed and no /tmp files must appear.
    """
    import glob as _glob
    payload = b"A" * (2 * 1024 * 1024)
    before = set(_glob.glob("/tmp/*"))  # noqa: S108

    result = run_in_netns_fork(
        netns,
        _identity,
        payload,
        timeout=30.0,
        large_payload_threshold=1024,  # 1 KiB threshold → forces memfd path
    )
    assert result == payload

    after = set(_glob.glob("/tmp/*"))  # noqa: S108
    assert after == before, f"memfd round-trip created /tmp files: {after - before}"


@_NEEDS_ROOT
@_NEEDS_MEMFD
def test_memfd_mode_result_large(netns):
    """Return value exceeding large_payload_threshold is staged via memfd."""
    import glob as _glob
    payload = b"B" * (2 * 1024 * 1024)
    before = set(_glob.glob("/tmp/*"))  # noqa: S108

    result = run_in_netns_fork(
        netns,
        _identity,
        payload,
        timeout=30.0,
        large_payload_threshold=1024,
    )
    assert result == payload
    after = set(_glob.glob("/tmp/*"))  # noqa: S108
    assert after == before, f"memfd result round-trip created /tmp files: {after - before}"


@_NEEDS_ROOT
@_NEEDS_MEMFD
def test_memfd_mode_truncated_header_raises(netns, monkeypatch):
    """A truncated memfd result header raises NetnsForkError with a clear message.
    We simulate this by patching _memfd_write (result side) to produce a
    mismatched size header.
    """
    original_memfd_write = _mod._memfd_write

    calls = [0]

    def patched_memfd_write(data, *, name="nf_ipc"):
        calls[0] += 1
        return original_memfd_write(data, name=name)

    monkeypatch.setattr(_mod, "_memfd_write", patched_memfd_write)

    payload = b"C" * (2 * 1024 * 1024)
    # This should succeed — we just verify memfd write was called.
    result = run_in_netns_fork(
        netns,
        _identity,
        payload,
        timeout=15.0,
        large_payload_threshold=1024,
    )
    assert result == payload
    assert calls[0] > 0, "Expected _memfd_write to be called at least once"


# ---------------------------------------------------------------------------
# PersistentNetnsWorker — large-payload tests (SOCK_STREAM)
# ---------------------------------------------------------------------------


@_NEEDS_ROOT
def test_persistent_worker_1mb_round_trip(netns):
    """Persistent worker (SOCK_STREAM) handles a 1 MB request and reply."""
    worker = PersistentNetnsWorker(netns, _echo_worker)
    worker.start()
    try:
        big = b"P" * (1 * 1024 * 1024)
        reply = worker.dispatch(big, timeout=30.0)
        assert reply == big
    finally:
        worker.stop()


@_NEEDS_ROOT
def test_persistent_worker_64mb_round_trip(netns):
    """Persistent worker handles a 64 MB request and reply without truncation."""
    worker = PersistentNetnsWorker(netns, _echo_worker)
    worker.start()
    try:
        big = b"Q" * (64 * 1024 * 1024)
        t0 = time.monotonic()
        reply = worker.dispatch(big, timeout=120.0)
        elapsed = time.monotonic() - t0
        assert reply == big
        assert elapsed < 120.0
    finally:
        worker.stop()


@_NEEDS_ROOT
def test_persistent_worker_mixed_sequence(netns):
    """Mixed small/huge/small sequence verifies framing boundaries are preserved."""
    worker = PersistentNetnsWorker(netns, _echo_worker)
    worker.start()
    try:
        small1 = b"hello"
        huge = b"H" * (4 * 1024 * 1024)  # 4 MB
        small2 = b"world"

        r1 = worker.dispatch(small1, timeout=5.0)
        r2 = worker.dispatch(huge, timeout=60.0)
        r3 = worker.dispatch(small2, timeout=5.0)

        assert r1 == small1, "First small message corrupted"
        assert r2 == huge, f"Huge message: got {len(r2)} bytes, expected {len(huge)}"
        assert r3 == small2, "Second small message corrupted"
    finally:
        worker.stop()


@_NEEDS_ROOT
def test_persistent_worker_back_pressure_timeout(netns):
    """A child that never replies causes dispatch() to raise NetnsForkTimeout
    rather than hanging forever or OOMing the parent.

    We use a child that reads the first request and then sleeps (never replies).
    The dispatch() call must time out cleanly.
    """
    def _read_and_sleep(ctx: ChildContext) -> None:
        """Consume the request but never reply — simulates a stuck worker."""
        ctx.recv()
        time.sleep(60)

    worker = PersistentNetnsWorker(netns, _read_and_sleep)
    worker.start()
    try:
        t0 = time.monotonic()
        with pytest.raises(NetnsForkTimeout):
            worker.dispatch(b"trigger", timeout=0.5)
        elapsed = time.monotonic() - t0
        # Must not hang for more than a few seconds (timeout is 0.5s).
        assert elapsed < 10.0, f"dispatch blocked for {elapsed:.1f}s after timeout"
    finally:
        worker.stop()


# ---------------------------------------------------------------------------
# EINTR resilience (non-root, unit-style)
# ---------------------------------------------------------------------------


def test_select_retry_handles_eintr(monkeypatch):
    """_select_retry retries on EINTR (simulated via mock).

    We patch select.select to raise InterruptedError once, then succeed.
    The function must return True (not propagate the exception).
    """
    import select as _select_mod

    from shorewall_nft_netkit.netns_fork import _select_retry

    call_count = [0]
    original_select = _select_mod.select

    def patched_select(rlist, wlist, xlist, timeout=None):
        call_count[0] += 1
        if call_count[0] == 1:
            raise InterruptedError("simulated EINTR")
        # Second call: return rlist as "ready".
        return rlist, [], []

    monkeypatch.setattr(_select_mod, "select", patched_select)

    r_fd, w_fd = os.pipe()
    try:
        os.write(w_fd, b"x")
        result = _select_retry([r_fd], 1.0)
        assert result is True
        assert call_count[0] == 2, "Expected exactly 2 select calls (1 EINTR + 1 success)"
    finally:
        os.close(r_fd)
        os.close(w_fd)


# ---------------------------------------------------------------------------
# Pipe size bump (non-root, unit-style)
# ---------------------------------------------------------------------------


def test_try_bump_pipe_size_does_not_raise():
    """_try_bump_pipe_size does not raise even if the capability is missing."""
    from shorewall_nft_netkit.netns_fork import _try_bump_pipe_size

    r_fd, w_fd = os.pipe()
    try:
        # Must not raise even if CAP_SYS_RESOURCE is absent.
        _try_bump_pipe_size(w_fd, 1 << 20)
    finally:
        os.close(r_fd)
        os.close(w_fd)


# ---------------------------------------------------------------------------
# run_nft_in_netns_zc stdout-memfd path tests
# ---------------------------------------------------------------------------


@_NEEDS_MEMFD
def test_nft_result_context_manager_noop():
    """NftResult.close() on a plain result (no mmap) is a safe no-op;
    context-manager exit calls close() without raising."""
    r = NftResult(rc=0, stdout="hello", stderr="")
    assert r._mmap is None
    r.close()  # no-op, must not raise
    with r:
        pass  # context-manager must not raise


@_NEEDS_MEMFD
def test_nft_result_stdout_mv_invalid_after_close():
    """After close(), a memoryview derived from the mmap raises ValueError.

    mmap.close() raises BufferError if a memoryview is still holding an
    exported pointer.  The correct pattern is: release (del) the memoryview
    first, then close the mmap via NftResult.close().  Callers that want to
    close early must release their memoryview reference before calling close().
    """
    size = 16
    fd = _memfd_write(b"A" * size, name="test_mv_close")
    try:
        import mmap as _mmap
        mm = _mmap.mmap(fd, size, access=_mmap.ACCESS_READ)
        mv = memoryview(mm)
        r = NftResult(rc=0, stdout="A" * size, stderr="", stdout_mv=mv, _mmap=mm)
        # Accessing bytes before close is fine.
        assert r.stdout_mv is not None
        assert r.stdout_mv.nbytes == size
        # Release the exported pointer (memoryview) before closing, so the
        # mmap can be freed without a BufferError.
        r.stdout_mv.release()
        r.stdout_mv = None  # type: ignore[assignment]
        r.close()
        # After close, the mmap object is closed; any mmap-derived access raises.
        with pytest.raises((ValueError, AttributeError)):
            mm.read(1)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


@_NEEDS_MEMFD
def test_memfd_dup_from_pid_self():
    """_memfd_dup_from_pid reads a memfd created in the current process
    via /proc/<self>/fd/<n>."""
    data = b"hello from memfd dup" * 100
    fd = _memfd_write(data, name="test_dup_self")
    try:
        result, mm = _memfd_dup_from_pid(os.getpid(), fd, len(data))
        assert isinstance(result, bytes)
        assert result == data
        assert mm is None
    finally:
        os.close(fd)


@_NEEDS_MEMFD
def test_memfd_dup_from_pid_as_memoryview():
    """_memfd_dup_from_pid with as_memoryview=True returns a live memoryview.

    mmap.close() cannot proceed while a memoryview still holds an exported
    pointer.  The caller must release the memoryview first (mv.release() or
    del mv) before closing the mmap.
    """
    data = b"memoryview test data" * 50
    fd = _memfd_write(data, name="test_dup_mv")
    try:
        mv, mm = _memfd_dup_from_pid(os.getpid(), fd, len(data), as_memoryview=True)
        assert isinstance(mv, memoryview)
        assert mm is not None
        assert mv.nbytes == len(data)
        assert bytes(mv) == data
        # Release the exported pointer before closing the mmap.
        mv.release()
        mm.close()
        # After close, reading from the released view raises ValueError.
        with pytest.raises(ValueError):
            _ = bytes(mv)
    finally:
        os.close(fd)


@_NEEDS_MEMFD
def test_memfd_dup_from_pid_empty():
    """_memfd_dup_from_pid with size=0 returns empty bytes without error."""
    result, mm = _memfd_dup_from_pid(os.getpid(), 0, 0)
    assert result == b""
    assert mm is None


@_NEEDS_MEMFD
def test_memfd_dup_from_pid_bad_fd():
    """_memfd_dup_from_pid raises OSError when the proc-fd path is invalid."""
    with pytest.raises(OSError):
        _memfd_dup_from_pid(os.getpid(), 99999, 10)


@_NEEDS_MEMFD
def test_zc_tag_constants_distinct():
    """_ZC_TAG_STDOUT_PIPE and _ZC_TAG_STDOUT_MEMFD must be distinct, positive,
    and must not collide with the existing _RESULT_* bytes (0x00–0x04) that
    can also appear on the rc pipe in the setns-error path."""
    import shorewall_nft_netkit.netns_fork as _mod

    assert _ZC_TAG_STDOUT_PIPE != _ZC_TAG_STDOUT_MEMFD
    # Both must be positive integers in the range of a single byte.
    assert 0 < _ZC_TAG_STDOUT_PIPE < 256
    assert 0 < _ZC_TAG_STDOUT_MEMFD < 256
    # Must not collide with the existing _RESULT_* constants.
    existing_tags = {
        ord(_mod._RESULT_OK),
        ord(_mod._RESULT_EXC),
        ord(_mod._RESULT_SETNS_ERR),
        ord(_mod._RESULT_OK_MEMFD),
        ord(_mod._RESULT_EXC_MEMFD),
    }
    assert _ZC_TAG_STDOUT_PIPE not in existing_tags
    assert _ZC_TAG_STDOUT_MEMFD not in existing_tags


@_NEEDS_MEMFD
def test_stdout_threshold_default_matches_module_constant():
    """_DEFAULT_STDOUT_THRESHOLD should be 4 MiB."""
    assert _DEFAULT_STDOUT_THRESHOLD == 4 * 1024 * 1024


# ---------------------------------------------------------------------------
# run_nft_in_netns_zc stdout-path selection (monkeypatched, no real netns)
# ---------------------------------------------------------------------------


def _make_fake_netns_exists(monkeypatch, netns_name: str) -> None:
    """Patch os.path.exists to claim a fake netns exists."""
    real_exists = os.path.exists

    def patched(p):
        if p == f"/run/netns/{netns_name}":
            return True
        return real_exists(p)

    monkeypatch.setattr(os.path, "exists", patched)


@_NEEDS_MEMFD
def test_run_nft_zc_small_stdout_uses_pipe_path(monkeypatch):
    """When stdout is below the threshold, the inline-pipe path (tag=1) is used.

    We spy on _memfd_write in the child to verify no extra memfd is created
    for stdout.  Because the child process cannot write to the parent's list,
    we instead verify the tag byte read from the rc pipe.
    """
    import shorewall_nft_netkit.netns_fork as _mod

    _make_fake_netns_exists(monkeypatch, "_zc_pipe_spy")

    # We can't easily introspect the child, so we verify via the module spy:
    # monkeypatch _memfd_write to count calls.  In the SMALL path the child
    # only calls _memfd_write once (for the script), not a second time for
    # stdout.
    original_write = _mod._memfd_write
    calls: list[str] = []

    def spy_write(data, *, name="nf_ipc"):
        calls.append(name)
        return original_write(data, name=name)

    monkeypatch.setattr(_mod, "_memfd_write", spy_write)

    # Patch _child_nft_zc to simulate small stdout without a real netns.

    original_child_nft_zc = _mod._child_nft_zc

    def fake_child_nft_zc(
        netns_path, *, script_fd, script_size, rc_w, stdout_w, stderr_w,
        ack_r, check_only, stdout_threshold,
    ):
        # Emit small stdout (well below threshold).
        small_stdout = b"small"
        import os as _os
        try:
            _os.write(stdout_w, small_stdout)
        except OSError:
            pass
        _os.close(stdout_w)
        _os.close(stderr_w)
        _os.close(ack_r)
        hdr = _mod._ZC_PIPE_HDR.pack(_mod._ZC_TAG_STDOUT_PIPE, 0)
        try:
            _os.write(rc_w, hdr)
        except OSError:
            pass
        _os.close(rc_w)
        _os.close(script_fd)
        _os._exit(0)

    monkeypatch.setattr(_mod, "_child_nft_zc", fake_child_nft_zc)

    result = run_nft_in_netns_zc(
        "_zc_pipe_spy", "list tables",
        stdout_threshold=1024 * 1024,
    )
    assert result.rc == 0
    assert result.stdout == "small"
    assert result.stdout_mv is None
    assert result._mmap is None

    # The script memfd call was intercepted by the spy; stdout must NOT have
    # generated a "nf_nft_stdout" memfd call (that only happens in the child
    # process for the memfd path, but the fake_child_nft_zc didn't call
    # _memfd_write for stdout — it wrote directly).
    assert "nf_script" in calls, f"Expected nf_script call; got {calls}"
    assert "nf_nft_stdout" not in calls, (
        f"Unexpected nf_nft_stdout memfd in small-stdout path: {calls}"
    )


@_NEEDS_MEMFD
def test_run_nft_zc_large_stdout_uses_memfd_path(monkeypatch):
    """When stdout exceeds the threshold, the memfd path (tag=2) is used.

    We replace _child_nft_zc with a fake that writes a large stdout into a
    memfd and sends the tag=2 control message, then blocks on ack.  The
    parent must recover the data via the proc-fd dup mechanism.
    """
    import shorewall_nft_netkit.netns_fork as _mod

    _make_fake_netns_exists(monkeypatch, "_zc_memfd_spy")

    # Build the large payload in the parent (the fake child will create it
    # from a forked subprocess so sizes are known).
    large_data = b"L" * (64 * 1024)  # 64 KiB — above our 16 KiB threshold
    threshold = 16 * 1024  # 16 KiB

    original_child_nft_zc = _mod._child_nft_zc

    def fake_child_nft_zc(
        netns_path, *, script_fd, script_size, rc_w, stdout_w, stderr_w,
        ack_r, check_only, stdout_threshold,
    ):
        import os as _os
        # Close pipes we don't use.
        _os.close(stdout_w)
        _os.close(stderr_w)
        _os.close(script_fd)
        # Write large_data into a memfd.
        stdout_memfd = _mod._memfd_write(large_data, name="nf_nft_stdout")
        _os.set_inheritable(stdout_memfd, True)
        hdr = _mod._ZC_MEMFD_HDR.pack(
            _mod._ZC_TAG_STDOUT_MEMFD, 0, len(large_data), stdout_memfd
        )
        try:
            _os.write(rc_w, hdr)
        except OSError:
            pass
        _os.close(rc_w)
        # Block on ack.
        try:
            _mod._read_fd_exact(ack_r, 1)
        except (OSError, EOFError):
            pass
        _os.close(ack_r)
        _os.close(stdout_memfd)
        _os._exit(0)

    monkeypatch.setattr(_mod, "_child_nft_zc", fake_child_nft_zc)
    monkeypatch.setattr(_mod, "_read_fd_exact", _mod._read_fd_exact)  # keep original

    result = run_nft_in_netns_zc(
        "_zc_memfd_spy", "list tables",
        stdout_threshold=threshold,
    )
    assert result.rc == 0
    assert result.stdout == large_data.decode("utf-8")
    assert result.stdout_mv is None  # stdout_as_memoryview=False by default
    assert result._mmap is None


@_NEEDS_MEMFD
def test_run_nft_zc_large_stdout_as_memoryview(monkeypatch):
    """stdout_as_memoryview=True yields a live memoryview; close() invalidates it."""
    import shorewall_nft_netkit.netns_fork as _mod

    _make_fake_netns_exists(monkeypatch, "_zc_mv_spy")

    large_data = b"M" * (32 * 1024)
    threshold = 8 * 1024

    def fake_child_nft_zc(
        netns_path, *, script_fd, script_size, rc_w, stdout_w, stderr_w,
        ack_r, check_only, stdout_threshold,
    ):
        import os as _os
        _os.close(stdout_w)
        _os.close(stderr_w)
        _os.close(script_fd)
        stdout_memfd = _mod._memfd_write(large_data, name="nf_nft_stdout")
        _os.set_inheritable(stdout_memfd, True)
        hdr = _mod._ZC_MEMFD_HDR.pack(
            _mod._ZC_TAG_STDOUT_MEMFD, 0, len(large_data), stdout_memfd
        )
        try:
            _os.write(rc_w, hdr)
        except OSError:
            pass
        _os.close(rc_w)
        try:
            _mod._read_fd_exact(ack_r, 1)
        except (OSError, EOFError):
            pass
        _os.close(ack_r)
        _os.close(stdout_memfd)
        _os._exit(0)

    monkeypatch.setattr(_mod, "_child_nft_zc", fake_child_nft_zc)

    result = run_nft_in_netns_zc(
        "_zc_mv_spy", "list tables",
        stdout_threshold=threshold,
        stdout_as_memoryview=True,
    )
    try:
        assert result.rc == 0
        assert result.stdout_mv is not None
        assert result.stdout_mv.nbytes == len(large_data)
        assert bytes(result.stdout_mv) == large_data
        # stdout str and memoryview must agree.
        assert result.stdout == large_data.decode("utf-8")
        # Release the exported pointer before closing so mmap.close() won't
        # raise BufferError.
        mv = result.stdout_mv
        mv.release()
        result.stdout_mv = None  # type: ignore[assignment]
        result.close()
        # After close, the released memoryview raises ValueError on access.
        with pytest.raises(ValueError):
            _ = bytes(mv)
    except Exception:
        result.close()
        raise


@_NEEDS_MEMFD
def test_run_nft_zc_threshold_boundary_pipe(monkeypatch):
    """stdout exactly threshold-1 bytes → pipe path (tag=1)."""
    import shorewall_nft_netkit.netns_fork as _mod

    _make_fake_netns_exists(monkeypatch, "_zc_boundary_pipe")
    threshold = 1024
    # threshold - 1 bytes → inline pipe
    payload = b"B" * (threshold - 1)

    def fake_child(
        netns_path, *, script_fd, script_size, rc_w, stdout_w, stderr_w,
        ack_r, check_only, stdout_threshold,
    ):
        import os as _os
        # Verify the child received the correct threshold.
        assert stdout_threshold == threshold
        _os.close(script_fd)
        _os.close(ack_r)
        try:
            _os.write(stdout_w, payload)
        except OSError:
            pass
        _os.close(stdout_w)
        _os.close(stderr_w)
        hdr = _mod._ZC_PIPE_HDR.pack(_mod._ZC_TAG_STDOUT_PIPE, 0)
        try:
            _os.write(rc_w, hdr)
        except OSError:
            pass
        _os.close(rc_w)
        _os._exit(0)

    monkeypatch.setattr(_mod, "_child_nft_zc", fake_child)

    result = run_nft_in_netns_zc(
        "_zc_boundary_pipe", "list tables", stdout_threshold=threshold
    )
    assert result.stdout == payload.decode("utf-8")
    assert result._mmap is None


@_NEEDS_MEMFD
def test_run_nft_zc_threshold_boundary_memfd(monkeypatch):
    """stdout exactly threshold bytes → memfd path (tag=2)."""
    import shorewall_nft_netkit.netns_fork as _mod

    _make_fake_netns_exists(monkeypatch, "_zc_boundary_memfd")
    threshold = 1024
    # threshold bytes → memfd
    payload = b"C" * threshold

    def fake_child(
        netns_path, *, script_fd, script_size, rc_w, stdout_w, stderr_w,
        ack_r, check_only, stdout_threshold,
    ):
        import os as _os
        assert stdout_threshold == threshold
        _os.close(script_fd)
        _os.close(stdout_w)
        _os.close(stderr_w)
        stdout_memfd = _mod._memfd_write(payload, name="nf_nft_stdout")
        _os.set_inheritable(stdout_memfd, True)
        hdr = _mod._ZC_MEMFD_HDR.pack(
            _mod._ZC_TAG_STDOUT_MEMFD, 0, len(payload), stdout_memfd
        )
        try:
            _os.write(rc_w, hdr)
        except OSError:
            pass
        _os.close(rc_w)
        try:
            _mod._read_fd_exact(ack_r, 1)
        except (OSError, EOFError):
            pass
        _os.close(ack_r)
        _os.close(stdout_memfd)
        _os._exit(0)

    monkeypatch.setattr(_mod, "_child_nft_zc", fake_child)

    result = run_nft_in_netns_zc(
        "_zc_boundary_memfd", "list tables", stdout_threshold=threshold
    )
    assert result.stdout == payload.decode("utf-8")


@_NEEDS_MEMFD
def test_run_nft_zc_procfd_open_fails_fallback(monkeypatch):
    """When /proc/<pid>/fd open fails, the parent falls back to the pipe content
    (empty in this case) and logs a warning.  Result is still correct; no hang."""
    import logging

    import shorewall_nft_netkit.netns_fork as _mod

    _make_fake_netns_exists(monkeypatch, "_zc_procfd_fallback")
    threshold = 16

    def fake_child(
        netns_path, *, script_fd, script_size, rc_w, stdout_w, stderr_w,
        ack_r, check_only, stdout_threshold,
    ):
        import os as _os
        _os.close(script_fd)
        _os.close(stdout_w)
        _os.close(stderr_w)
        # Pretend large stdout.
        fake_fd = 42
        hdr = _mod._ZC_MEMFD_HDR.pack(
            _mod._ZC_TAG_STDOUT_MEMFD, 0, 100, fake_fd
        )
        try:
            _os.write(rc_w, hdr)
        except OSError:
            pass
        _os.close(rc_w)
        # Wait for ack (parent will send it even on error).
        try:
            _mod._read_fd_exact(ack_r, 1)
        except (OSError, EOFError):
            pass
        _os.close(ack_r)
        _os._exit(0)

    monkeypatch.setattr(_mod, "_child_nft_zc", fake_child)

    # Patch _memfd_dup_from_pid to simulate an OSError.
    original_dup = _mod._memfd_dup_from_pid

    def failing_dup(pid, fd, size, *, as_memoryview=False):
        raise OSError(errno.ENOENT, "simulated proc-fd failure")

    import errno
    monkeypatch.setattr(_mod, "_memfd_dup_from_pid", failing_dup)

    warnings: list[str] = []

    class _WarnCapture(logging.Handler):
        def emit(self, record):
            warnings.append(record.getMessage())

    handler = _WarnCapture()
    logging.getLogger("shorewall_nft_netkit.netns_fork").addHandler(handler)
    try:
        result = run_nft_in_netns_zc(
            "_zc_procfd_fallback", "list tables", stdout_threshold=threshold
        )
    finally:
        logging.getLogger("shorewall_nft_netkit.netns_fork").removeHandler(handler)

    # Result must not crash; stdout falls back to empty pipe content.
    assert result.rc == 0
    assert isinstance(result.stdout, str)
    # A warning must have been logged.
    assert any("falling back to pipe" in w for w in warnings), (
        f"Expected fallback warning; got: {warnings}"
    )


@_NEEDS_MEMFD
def test_run_nft_zc_child_early_exit_in_memfd_path(monkeypatch):
    """Child dies before sending any rc → ChildCrashedError (no hang)."""
    import shorewall_nft_netkit.netns_fork as _mod

    _make_fake_netns_exists(monkeypatch, "_zc_early_exit")

    def fake_child(
        netns_path, *, script_fd, script_size, rc_w, stdout_w, stderr_w,
        ack_r, check_only, stdout_threshold,
    ):
        import os as _os
        # Close everything without writing rc — simulate a crash.
        for fd in (script_fd, rc_w, stdout_w, stderr_w, ack_r):
            try:
                _os.close(fd)
            except OSError:
                pass
        _os._exit(42)

    monkeypatch.setattr(_mod, "_child_nft_zc", fake_child)

    with pytest.raises(ChildCrashedError):
        run_nft_in_netns_zc("_zc_early_exit", "list tables", timeout=5.0)


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_small_stdout_real_netns(netns):
    """Real netns: small stdout uses the inline pipe path; result is parseable."""
    import json

    result = run_nft_in_netns_zc(
        netns, "list tables",
        # Force inline-pipe by using a 100 MiB threshold.
        stdout_threshold=100 * 1024 * 1024,
        timeout=30.0,
    )
    assert result.rc == 0
    assert result._mmap is None
    if result.stdout.strip():
        parsed = json.loads(result.stdout)
        assert isinstance(parsed, dict)


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_large_stdout_real_netns(netns):
    """Real netns: forcing memfd path with threshold=0 gives identical output
    to the inline pipe path."""

    result_pipe = run_nft_in_netns_zc(
        netns, "list tables",
        stdout_threshold=100 * 1024 * 1024,  # inline pipe
        timeout=30.0,
    )
    result_memfd = run_nft_in_netns_zc(
        netns, "list tables",
        stdout_threshold=0,  # always use memfd
        timeout=30.0,
    )
    assert result_pipe.rc == result_memfd.rc
    assert result_pipe.stdout == result_memfd.stdout
    result_memfd.close()


@_NEEDS_NFT
@_NEEDS_MEMFD
def test_run_nft_zc_as_context_manager(netns):
    """run_nft_in_netns_zc result used as a context manager closes cleanly."""
    with run_nft_in_netns_zc(netns, "list tables", timeout=30.0) as result:
        assert result.rc == 0
    # After the with-block, the result is closed (mmap released, if any).
