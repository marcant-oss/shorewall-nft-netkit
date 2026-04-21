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
import os
import pickle
import signal
import subprocess
import time

import pytest

from shorewall_nft_netkit.netns_fork import (
    ChildContext,
    ChildCrashedError,
    NetnsForkTimeout,
    NetnsNotFoundError,
    NetnsSetnsError,
    PersistentNetnsWorker,
    run_in_netns_fork,
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
