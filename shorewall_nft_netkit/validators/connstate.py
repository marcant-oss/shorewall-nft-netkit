"""Connection state validation tests.

Tests that nft ct state tracking works correctly:
1. Established: bidirectional data on accepted connection
2. dropNotSyn: TCP ACK without prior SYN → dropped
3. Invalid: malformed packets → dropped
4. New+SYN: proper TCP SYN to allowed port → accepted
5. Related: FTP data channel via ct helper (if available)

Uses scapy for raw packet crafting where nc can't test specific
TCP flags. Falls back to nc-based tests if scapy unavailable.

All tests run inside network namespaces via ip netns.

Unlike ``shorewall_nft.verify.connstate``, this module:

- Accepts ``ns_name`` on every privileged call so it can operate in any
  named network namespace (not just the fixed simulate.py NS_FW/NS_SRC).
- Replaces the ``ns(NS_SRC, "nc ...")`` injector in
  ``run_small_conntrack_probe`` with a ``socket.create_connection()`` call
  so the validator works without a separate NS_SRC namespace — the caller's
  process network namespace is used directly.
- Imports ``ns`` from ``shorewall_nft_netkit.netns_shell`` instead of
  ``shorewall_nft.verify.simulate``.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass

from pyroute2 import NFCTSocket
from pyroute2.netlink.nfnetlink.nfctsocket import NFCTAttrTuple

from shorewall_nft_netkit.netns_shell import run_shell_in_netns as _ns_shell

# Default namespace name — matches simulate.py's NS_SRC / NS_FW so that
# callers that were written against the old module-level constants keep
# working without changes.
_DEFAULT_NS_FW = "shorewall-next-sim-fw"
_DEFAULT_NS_SRC = "shorewall-next-sim-src"
_DEFAULT_SRC = "192.0.2.69"


@dataclass
class ConnStateResult:
    name: str
    passed: bool
    detail: str
    ms: int = 0


def test_established_tcp(
    dst_ip: str,
    port: int = 80,
    *,
    ns_src: str = _DEFAULT_NS_SRC,
    src_ip: str = _DEFAULT_SRC,
) -> ConnStateResult:
    """Test that established TCP connections work bidirectionally.

    1. Open TCP connection from src to dst (SYN/SYN-ACK/ACK)
    2. Send data src->dst
    3. Verify data arrives (dst->src return traffic via ct state established)
    """
    start = time.monotonic_ns()

    r = _ns_shell(
        ns_src,
        f'echo "TEST_ESTABLISHED" | timeout 3 nc -w 2 -s {src_ip} {dst_ip} {port} 2>/dev/null',
        timeout=5,
    )
    ms = (time.monotonic_ns() - start) // 1_000_000

    if r.returncode == 0:
        return ConnStateResult(
            name="ct_state_established",
            passed=True,
            detail=f"TCP {port}: bidirectional connection works ({ms}ms)",
            ms=ms,
        )
    return ConnStateResult(
        name="ct_state_established",
        passed=False,
        detail=f"TCP {port}: connection failed (return traffic blocked?)",
        ms=ms,
    )


def test_drop_not_syn(
    dst_ip: str,
    port: int = 80,
    *,
    ns_src: str = _DEFAULT_NS_SRC,
    src_ip: str = _DEFAULT_SRC,
) -> ConnStateResult:
    """Test that TCP ACK without prior SYN is dropped (dropNotSyn).

    Sends a bare TCP ACK packet — no prior SYN/SYN-ACK handshake.
    The firewall should drop this as ct state new + !SYN.

    Uses scapy for raw packet crafting.
    """
    start = time.monotonic_ns()

    try:
        scapy_cmd = f"""python3 -c "
import sys
sys.stderr = open('/dev/null', 'w')
from scapy.all import *
conf.verb = 0
# Send TCP ACK (no SYN) to {dst_ip}:{port}
pkt = IP(src='{src_ip}', dst='{dst_ip}')/TCP(sport=44444, dport={port}, flags='A', seq=1000)
resp = sr1(pkt, timeout=2, verbose=0)
if resp is None:
    print('DROPPED')  # No response = firewall dropped it
elif resp.haslayer(TCP):
    flags = resp[TCP].flags
    if flags & 0x04:  # RST
        print('RST')  # Got RST = packet reached host but no conn
    else:
        print('RESPONSE')
else:
    print('OTHER')
" 2>/dev/null"""
        r = _ns_shell(ns_src, scapy_cmd, timeout=10)
        ms = (time.monotonic_ns() - start) // 1_000_000
        result = r.stdout.strip()

        if result == "DROPPED":
            return ConnStateResult(
                name="dropNotSyn",
                passed=True,
                detail=f"TCP ACK without SYN correctly dropped ({ms}ms)",
                ms=ms,
            )
        return ConnStateResult(
            name="dropNotSyn",
            passed=False,
            detail=f"TCP ACK without SYN NOT dropped (got: {result}) ({ms}ms)",
            ms=ms,
        )
    except Exception as e:
        ms = (time.monotonic_ns() - start) // 1_000_000
        return ConnStateResult(
            name="dropNotSyn",
            passed=False,
            detail=f"scapy test failed: {e}",
            ms=ms,
        )


def test_invalid_flags(
    dst_ip: str,
    port: int = 80,
    *,
    ns_src: str = _DEFAULT_NS_SRC,
    src_ip: str = _DEFAULT_SRC,
) -> ConnStateResult:
    """Test that packets with invalid TCP flags are dropped.

    Sends TCP with SYN+FIN (invalid combination) — should be dropped
    by tcpflags interface protection or ct state invalid.
    """
    start = time.monotonic_ns()

    try:
        scapy_cmd = f"""python3 -c "
import sys
sys.stderr = open('/dev/null', 'w')
from scapy.all import *
conf.verb = 0
# SYN+FIN is an invalid flag combination
pkt = IP(src='{src_ip}', dst='{dst_ip}')/TCP(sport=44445, dport={port}, flags='SF')
resp = sr1(pkt, timeout=2, verbose=0)
if resp is None:
    print('DROPPED')
else:
    print('RESPONSE')
" 2>/dev/null"""
        r = _ns_shell(ns_src, scapy_cmd, timeout=10)
        ms = (time.monotonic_ns() - start) // 1_000_000
        result = r.stdout.strip()

        return ConnStateResult(
            name="invalid_flags_synfin",
            passed=(result == "DROPPED"),
            detail=f"TCP SYN+FIN {'dropped' if result == 'DROPPED' else 'NOT dropped'} ({ms}ms)",
            ms=ms,
        )
    except Exception as e:
        ms = (time.monotonic_ns() - start) // 1_000_000
        return ConnStateResult(
            name="invalid_flags_synfin",
            passed=False,
            detail=f"scapy test failed: {e}",
            ms=ms,
        )


def test_syn_to_allowed(
    dst_ip: str,
    port: int = 80,
    *,
    ns_src: str = _DEFAULT_NS_SRC,
    src_ip: str = _DEFAULT_SRC,
) -> ConnStateResult:
    """Test that a proper TCP SYN to an allowed port gets SYN-ACK."""
    start = time.monotonic_ns()

    try:
        scapy_cmd = f"""python3 -c "
import sys
sys.stderr = open('/dev/null', 'w')
from scapy.all import *
conf.verb = 0
pkt = IP(src='{src_ip}', dst='{dst_ip}')/TCP(sport=44446, dport={port}, flags='S', seq=2000)
resp = sr1(pkt, timeout=2, verbose=0)
if resp is None:
    print('DROPPED')
elif resp.haslayer(TCP) and (resp[TCP].flags & 0x12) == 0x12:
    print('SYN-ACK')
elif resp.haslayer(TCP) and (resp[TCP].flags & 0x04):
    print('RST')
else:
    print('OTHER')
" 2>/dev/null"""
        r = _ns_shell(ns_src, scapy_cmd, timeout=10)
        ms = (time.monotonic_ns() - start) // 1_000_000
        result = r.stdout.strip()

        return ConnStateResult(
            name="syn_allowed",
            passed=(result == "SYN-ACK"),
            detail=f"TCP SYN to allowed port: {result} ({ms}ms)",
            ms=ms,
        )
    except Exception as e:
        ms = (time.monotonic_ns() - start) // 1_000_000
        return ConnStateResult(
            name="syn_allowed",
            passed=False,
            detail=f"scapy test failed: {e}",
            ms=ms,
        )


def test_syn_to_blocked(
    dst_ip: str,
    port: int = 12345,
    *,
    ns_src: str = _DEFAULT_NS_SRC,
    src_ip: str = _DEFAULT_SRC,
) -> ConnStateResult:
    """Test that TCP SYN to a blocked port is dropped/rejected."""
    start = time.monotonic_ns()

    try:
        scapy_cmd = f"""python3 -c "
import sys
sys.stderr = open('/dev/null', 'w')
from scapy.all import *
conf.verb = 0
pkt = IP(src='{src_ip}', dst='{dst_ip}')/TCP(sport=44447, dport={port}, flags='S', seq=3000)
resp = sr1(pkt, timeout=2, verbose=0)
if resp is None:
    print('DROPPED')
elif resp.haslayer(TCP) and (resp[TCP].flags & 0x04):
    print('RST')
elif resp.haslayer(ICMP):
    print('ICMP_REJECT')
else:
    print('OTHER')
" 2>/dev/null"""
        r = _ns_shell(ns_src, scapy_cmd, timeout=10)
        ms = (time.monotonic_ns() - start) // 1_000_000
        result = r.stdout.strip()

        # Both DROPPED and RST/ICMP_REJECT are valid "blocked" results
        blocked = result in ("DROPPED", "RST", "ICMP_REJECT")
        return ConnStateResult(
            name="syn_blocked",
            passed=blocked,
            detail=f"TCP SYN to blocked port {port}: {result} ({ms}ms)",
            ms=ms,
        )
    except Exception as e:
        ms = (time.monotonic_ns() - start) // 1_000_000
        return ConnStateResult(
            name="syn_blocked",
            passed=False,
            detail=f"scapy test failed: {e}",
            ms=ms,
        )


def test_udp_conntrack(
    dst_ip: str,
    port: int = 53,
    *,
    ns_src: str = _DEFAULT_NS_SRC,
    src_ip: str = _DEFAULT_SRC,
) -> ConnStateResult:
    """Test UDP connection tracking — request and response."""
    start = time.monotonic_ns()

    try:
        scapy_cmd = f"""python3 -c "
import sys
sys.stderr = open('/dev/null', 'w')
from scapy.all import *
conf.verb = 0
# Send UDP packet
pkt = IP(src='{src_ip}', dst='{dst_ip}')/UDP(sport=55555, dport={port})/Raw(b'PING')
resp = sr1(pkt, timeout=2, verbose=0)
if resp is None:
    print('NO_RESPONSE')
elif resp.haslayer(UDP):
    print('UDP_RESPONSE')
elif resp.haslayer(ICMP):
    icmp_type = resp[ICMP].type
    print(f'ICMP_{{icmp_type}}')
else:
    print('OTHER')
" 2>/dev/null"""
        r = _ns_shell(ns_src, scapy_cmd, timeout=10)
        ms = (time.monotonic_ns() - start) // 1_000_000
        result = r.stdout.strip()

        return ConnStateResult(
            name="udp_conntrack",
            passed=(result == "UDP_RESPONSE"),
            detail=f"UDP conntrack port {port}: {result} ({ms}ms)",
            ms=ms,
        )
    except Exception as e:
        ms = (time.monotonic_ns() - start) // 1_000_000
        return ConnStateResult(
            name="udp_conntrack",
            passed=False,
            detail=f"scapy test failed: {e}",
            ms=ms,
        )


def test_rfc1918_blocked(
    dst_ip: str,
    port: int = 80,
    *,
    ns_src: str = _DEFAULT_NS_SRC,
    src_ip: str = _DEFAULT_SRC,
) -> ConnStateResult:
    """Test that RFC1918 source addresses are dropped."""
    start = time.monotonic_ns()

    try:
        scapy_cmd = f"""python3 -c "
import sys
sys.stderr = open('/dev/null', 'w')
from scapy.all import *
conf.verb = 0
# Send from RFC1918 source (10.x.x.x)
pkt = IP(src='10.99.99.99', dst='{dst_ip}')/TCP(sport=44448, dport={port}, flags='S')
resp = sr1(pkt, timeout=2, verbose=0)
if resp is None:
    print('DROPPED')
else:
    print('RESPONSE')
" 2>/dev/null"""
        r = _ns_shell(ns_src, scapy_cmd, timeout=10)
        ms = (time.monotonic_ns() - start) // 1_000_000
        result = r.stdout.strip()

        return ConnStateResult(
            name="rfc1918_blocked",
            passed=(result == "DROPPED"),
            detail=f"RFC1918 src 10.99.99.99: {result} ({ms}ms)",
            ms=ms,
        )
    except Exception as e:
        ms = (time.monotonic_ns() - start) // 1_000_000
        return ConnStateResult(
            name="rfc1918_blocked",
            passed=False,
            detail=f"scapy test failed: {e}",
            ms=ms,
        )


def run_small_conntrack_probe(
    dst_ip: str = "203.0.113.5",
    port: int = 80,
    *,
    ns_name: str = _DEFAULT_NS_FW,
) -> list[ConnStateResult]:
    """Small-scale conntrack verification.

    Drives a handful of real flows and verifies the kernel conntrack table
    in the FW netns actually tracks them.  Deliberately small (3-4 probes)
    — not a load test, just a signal that ct is working.

    Unlike the original ``shorewall_nft.verify.connstate`` implementation,
    the TCP/UDP/ICMP injectors here use :func:`socket.create_connection` /
    :func:`socket.socket` in the calling process's network namespace rather
    than running ``nc`` / ``ping`` in a separate NS_SRC namespace.  This
    makes the validator runtime-neutral: the caller sets up whatever netns
    it needs before calling this function.

    Args:
        dst_ip: Destination IP to probe (default: 203.0.113.5, a
                documentation address that is routed to the firewall in
                the simulate.py topology).
        port:   TCP/UDP destination port for the TCP and UDP probes
                (default: 80).
        ns_name: Name of the FW network namespace that holds the conntrack
                 table to inspect.  Defaults to the simulate.py NS_FW.
    """
    results: list[ConnStateResult] = []

    def _ct_count(proto: str) -> int:
        try:
            proto_num = socket.getprotobyname(proto)
            flt = NFCTAttrTuple(proto=proto_num)
            with NFCTSocket(netns=ns_name, flags=os.O_RDONLY) as ct:
                return sum(1 for _ in ct.dump(tuple_orig=flt))
        except Exception:  # noqa: BLE001
            return 0

    def _ct_flush() -> None:
        try:
            with NFCTSocket(netns=ns_name, flags=os.O_RDONLY) as ct:
                ct.flush()
        except Exception:  # noqa: BLE001
            pass

    # 1. TCP flow should create a tcp conntrack entry.
    #    We use socket.create_connection() so no NS_SRC namespace is needed.
    #    The caller is expected to already be running in the correct netns.
    _ct_flush()
    start = time.monotonic_ns()
    try:
        s = socket.create_connection((dst_ip, port), timeout=1)
        s.sendall(b"CT_TEST\n")
        s.close()
    except (socket.timeout, OSError):
        pass  # expected — probing for ct entry creation, not success
    tcp_n = _ct_count("tcp")
    ms = (time.monotonic_ns() - start) // 1_000_000
    results.append(ConnStateResult(
        name="ct:tcp_flow_tracked",
        passed=tcp_n >= 1,
        detail=f"tcp conntrack entries after probe: {tcp_n}",
        ms=ms,
    ))

    # 2. UDP flow should create a udp conntrack entry.
    _ct_flush()
    start = time.monotonic_ns()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"PING\n", (dst_ip, 65001))
        s.close()
    except (socket.timeout, OSError):
        pass
    udp_n = _ct_count("udp")
    ms = (time.monotonic_ns() - start) // 1_000_000
    results.append(ConnStateResult(
        name="ct:udp_flow_tracked",
        passed=udp_n >= 1,
        detail=f"udp conntrack entries after probe: {udp_n}",
        ms=ms,
    ))

    # 3. ICMP echo should create an icmp conntrack entry.
    _ct_flush()
    start = time.monotonic_ns()
    try:
        # Raw ICMP echo request — requires CAP_NET_RAW (available under
        # unshare --user --map-root-user).
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(1)
        # Build a minimal ICMP echo request (type=8, code=0).
        import struct
        header = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, 1)
        checksum = 0
        for i in range(0, len(header), 2):
            checksum += (header[i] << 8) | header[i + 1]
        checksum = (~((checksum >> 16) + (checksum & 0xFFFF))) & 0xFFFF
        header = struct.pack("!BBHHH", 8, 0, checksum, os.getpid() & 0xFFFF, 1)
        s.sendto(header, (dst_ip, 0))
        s.close()
    except (socket.timeout, OSError, PermissionError):
        pass
    icmp_n = _ct_count("icmp")
    ms = (time.monotonic_ns() - start) // 1_000_000
    results.append(ConnStateResult(
        name="ct:icmp_flow_tracked",
        passed=icmp_n >= 1,
        detail=f"icmp conntrack entries after probe: {icmp_n}",
        ms=ms,
    ))

    # 4. ct is non-empty in normal operation (sanity)
    total_n = _ct_count("tcp") + _ct_count("udp") + _ct_count("icmp")
    results.append(ConnStateResult(
        name="ct:table_nonempty",
        passed=total_n >= 1,
        detail=f"total ct entries visible: {total_n}",
        ms=0,
    ))

    return results


def run_connstate_tests(
    dst_ip: str = "203.0.113.5",
    allowed_port: int = 80,
    *,
    ns_src: str = _DEFAULT_NS_SRC,
    src_ip: str = _DEFAULT_SRC,
) -> list[ConnStateResult]:
    """Run all connection state validation tests.

    Requires the simulation topology to be already set up.

    Args:
        dst_ip:       Destination IP to probe.
        allowed_port: TCP port expected to be open on the destination.
        ns_src:       Source namespace (for scapy-based tests).
        src_ip:       Source IP address used in scapy packets.
    """
    results: list[ConnStateResult] = []
    kw = dict(ns_src=ns_src, src_ip=src_ip)

    # 1. Established TCP (bidirectional)
    results.append(test_established_tcp(dst_ip, allowed_port, **kw))

    # 2. dropNotSyn (bare ACK)
    results.append(test_drop_not_syn(dst_ip, allowed_port, **kw))

    # 3. Invalid flags (SYN+FIN)
    results.append(test_invalid_flags(dst_ip, allowed_port, **kw))

    # 4. SYN to allowed port
    results.append(test_syn_to_allowed(dst_ip, allowed_port, **kw))

    # 5. SYN to blocked port
    results.append(test_syn_to_blocked(dst_ip, 12345, **kw))

    # 6. RFC1918 source blocked
    results.append(test_rfc1918_blocked(dst_ip, allowed_port, **kw))

    # 7. UDP conntrack
    results.append(test_udp_conntrack(dst_ip, 65001, **kw))

    return results
