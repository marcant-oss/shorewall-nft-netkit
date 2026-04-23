"""Synchronous shell-in-netns helper.

A small wrapper around :func:`subprocess.run` that uses a
``preexec_fn`` to enter the target network namespace via
``setns(CLONE_NEWNET)`` right after fork and before exec. This is
the canonical replacement for the ``ip netns exec NS sh -c CMD``
double-fork pattern when only a single shell command needs to run
inside a netns.

Compared with :mod:`shorewall_nft_netkit.netns_fork`'s
:func:`run_in_netns_fork`, this function is intentionally simpler:
no IPC, no callable serialisation, no persistent worker — just
``subprocess.run`` with the right pre-exec hook. Use this when:

* The work in the netns is a single ``sh -c`` command
* You want stdout/stderr/returncode as a regular CompletedProcess
* You don't need to share Python objects between caller and child

For richer netns work (running Python callables, holding netlink
sockets across many invocations, zero-copy script loading) reach
for the fork-based primitives in :mod:`netns_fork` instead.
"""

from __future__ import annotations

import ctypes
import os
import subprocess

_CLONE_NEWNET = 0x40000000


def run_shell_in_netns(
    ns: str,
    cmd: str,
    *,
    timeout: int = 10,
) -> subprocess.CompletedProcess:
    """Run ``sh -c <cmd>`` inside the named network namespace.

    Args:
        ns: Network namespace name. Must exist as ``/run/netns/<ns>``.
        cmd: Shell command string passed to ``sh -c``.
        timeout: Subprocess timeout in seconds (default 10).

    Returns:
        ``subprocess.CompletedProcess`` with stdout, stderr, and
        returncode captured as text.

    Raises:
        OSError: if ``setns(2)`` fails inside the child (propagated
            via ``preexec_fn`` and re-raised by ``subprocess.run``).
        subprocess.TimeoutExpired: if the command does not complete
            within *timeout* seconds.

    The child opens ``/run/netns/<ns>`` and ``setns()`` into the
    target namespace before ``exec()``. The parent process's
    namespace is unaffected.
    """
    ns_path = f"/run/netns/{ns}"

    def _enter_ns() -> None:  # runs in child, post-fork, pre-exec
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fd = os.open(ns_path, os.O_RDONLY)
        try:
            if libc.setns(fd, _CLONE_NEWNET) != 0:
                raise OSError(ctypes.get_errno(), "setns failed")
        finally:
            os.close(fd)

    return subprocess.run(
        ["sh", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        preexec_fn=_enter_ns,
    )
