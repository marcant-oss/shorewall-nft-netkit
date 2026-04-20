"""Thin TUN/TAP creation helper.

Opens ``/dev/net/tun``, issues ``TUNSETIFF`` to create a named TUN or
TAP interface in the **calling** process's network namespace, and
returns ``(fd, ifname)``. The interface can then be moved to a
target namespace via pyroute2 (``net_ns_fd``) — the fd stays valid
in the owning process regardless.

No dependency on ``python-pytun`` or scapy; all we need are a
handful of ioctls and constants.
"""

from __future__ import annotations

import fcntl
import os
import struct
from typing import Literal

# /usr/include/linux/if.h — IFF_* flags
IFF_TUN      = 0x0001
IFF_TAP      = 0x0002
IFF_NO_PI    = 0x1000  # no packet info prefix
IFF_VNET_HDR = 0x4000  # not used

# /usr/include/linux/if_tun.h
_TUNSETIFF = 0x400454ca       # int on 32-bit, long on 64-bit — see struct pack below
_TUNSETOWNER = 0x400454cc
_TUNSETPERSIST = 0x400454cb


def create_tuntap(name: str, mode: Literal["tun", "tap"] = "tap",
                  no_pi: bool = True) -> tuple[int, str]:
    """Create a TUN or TAP device in the current netns.

    Returns (fd, actual_name). ``no_pi=True`` omits the 4-byte
    TUN header from the fd I/O, which matches what scapy expects
    when you hand it raw L2 or L3 bytes.
    """
    fd = os.open("/dev/net/tun", os.O_RDWR)
    try:
        flags = (IFF_TUN if mode == "tun" else IFF_TAP)
        if no_pi:
            flags |= IFF_NO_PI
        # struct ifreq: char ifr_name[IFNAMSIZ(16)]; short ifr_flags;
        req = struct.pack("16sH", name.encode()[:15] + b"\x00", flags)
        res = fcntl.ioctl(fd, _TUNSETIFF, req)
        actual = res[:16].rstrip(b"\x00").decode()
        return fd, actual
    except Exception:
        os.close(fd)
        raise


def close_tuntap(fd: int) -> None:
    """Close the TUN/TAP fd — the interface disappears unless persistent."""
    try:
        os.close(fd)
    except OSError:
        pass
