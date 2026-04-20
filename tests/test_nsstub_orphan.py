"""Unit test for spawn_nsstub orphan-cleanup (stale bind-mount recovery).

Requires root to create a bind-mount. Skipped when euid != 0.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from shorewall_nft_netkit.nsstub import spawn_nsstub, stop_nsstub

_NETNS_NAME = "NS_TEST_orphan"
_NETNS_PATH = f"/run/netns/{_NETNS_NAME}"


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root")
def test_spawn_nsstub_recovers_from_orphan_bind_mount():
    """spawn_nsstub must succeed even when /run/netns/<name> is a live bind-mount
    left by a previous SIGKILL'd run (orphan pattern).

    Setup:
    1. Ensure /run/netns/ exists.
    2. Create the target path as an empty file.
    3. Bind-mount /proc/self/ns/net onto it (simulates what _stub_main does,
       then left behind after a SIGKILL).
    4. Call spawn_nsstub — must NOT raise.
    5. Verify /run/netns/<name> still exists (new stub owns it).
    6. call stop_nsstub — must clean up.
    7. Verify /run/netns/<name> is gone.
    """
    # --- Arrange: create orphan bind-mount ---
    os.makedirs("/run/netns", exist_ok=True)

    # Clean up any leftover from a previous failed test run before we start.
    subprocess.run(["umount", _NETNS_PATH], check=False, capture_output=True)
    try:
        os.unlink(_NETNS_PATH)
    except FileNotFoundError:
        pass
    subprocess.run(["ip", "netns", "del", _NETNS_NAME], check=False, capture_output=True)

    # Create the target file and bind-mount /proc/self/ns/net onto it.
    fd = os.open(_NETNS_PATH, os.O_CREAT | os.O_WRONLY, 0o644)
    os.close(fd)
    result = subprocess.run(
        ["mount", "--bind", "/proc/self/ns/net", _NETNS_PATH],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"Could not create orphan bind-mount for test setup: {result.stderr}"
    )

    # --- Act: spawn_nsstub must recover and succeed ---
    pid = spawn_nsstub(_NETNS_NAME)

    # --- Assert: the netns path exists (new stub owns it) ---
    assert os.path.exists(_NETNS_PATH), (
        f"Expected {_NETNS_PATH} to exist after spawn_nsstub"
    )

    # --- Cleanup: stop the stub and verify the path is gone ---
    stop_nsstub(_NETNS_NAME, pid)

    assert not os.path.exists(_NETNS_PATH), (
        f"Expected {_NETNS_PATH} to be removed after stop_nsstub"
    )
