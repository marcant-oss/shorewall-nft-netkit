"""Scapy-based packet construction + classification helpers.

Centralises the protocol-specific code so the worker and controller
stay protocol-agnostic. Every ``build_*`` returns the raw ``bytes``
that can be written directly to a TAP (with Ethernet header) or TUN
(bare IP packet) file descriptor. Every ``parse_*`` takes raw bytes
off the fd and returns a lightweight summary dict for the trace
buffer and the observed-probe correlation.

Supported protocols:
    TCP, UDP, ICMP, ICMPv6, ARP, NDP (NS/NA/RS/RA), ESP, GRE

Scapy lazy-imports: the top-level import cost is ~100ms. We defer
the import to first call so ``simlab.packets`` is cheap to import
from modules that only need type/constant definitions.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
from dataclasses import dataclass
from typing import Any

# Random ephemeral source port seed (reused across builds)
_eph_counter = 32768 + (os.getpid() & 0xffff) % 28000


def fast_probe_id(raw: bytes, is_tap: bool) -> int | None:
    """Extract the probe_id from an observed frame without scapy.

    simlab stashes every probe's id in IPv4 ``id`` (16-bit) or the
    IPv6 flow label (20-bit). IPv6 probe IDs start at 0x10000 so
    they never collide with 16-bit IPv4 IDs.

    On the hot path (~thousands of probes per second) running scapy
    parse for each observation dominates CPU and — thanks to the
    GIL — prevents the reader threads from scaling across cores.
    This helper reads the exact bytes we need in pure Python
    without touching scapy:

    - TAP mode: skip the 14-byte Ethernet header (ethertype is
      verified to be 0x0800 v4 or 0x86dd v6).
    - TUN mode: no header, IP version is in the first nibble.

    Returns the probe id (16-bit for IPv4, 20-bit for IPv6) or
    ``None`` when the frame is not a recognisable v4/v6 packet
    (caller should fall back to the slow path, ARP/NDP handling,
    etc.).
    """
    off = 14 if is_tap else 0
    if is_tap:
        if len(raw) < 14:
            return None
        etype = (raw[12] << 8) | raw[13]
        if etype == 0x0800:  # IPv4
            pass
        elif etype == 0x86dd:  # IPv6
            pass
        else:
            return None
    if len(raw) < off + 4:
        return None
    version = raw[off] >> 4
    if version == 4:
        if len(raw) < off + 6:
            return None
        return (raw[off + 4] << 8) | raw[off + 5]
    if version == 6:
        if len(raw) < off + 4:
            return None
        return (((raw[off + 1] & 0x0f) << 16)
                | (raw[off + 2] << 8) | raw[off + 3])
    return None


def fast_is_arp_or_ndp_ns(raw: bytes, is_tap: bool) -> bool:
    """Cheap check — is the frame an ARP who-has or IPv6 NDP NS?

    These need full scapy parse + reply construction so the
    reader thread has to take the slow path for them. Everything
    else is observed IP traffic that can use ``fast_probe_id``.
    """
    if is_tap:
        if len(raw) < 14:
            return False
        etype = (raw[12] << 8) | raw[13]
        if etype == 0x0806:  # ARP
            return True
        if etype == 0x86dd:
            if len(raw) < 14 + 40 + 1:
                return False
            if raw[14 + 6] != 58:  # next-header != ICMPv6
                return False
            return raw[14 + 40] == 135  # NS
        return False
    # TUN — bare IP
    if len(raw) < 40 + 1:
        return False
    if raw[0] >> 4 != 6:
        return False
    if raw[6] != 58:
        return False
    return raw[40] == 135


# ── Fast (scapy-free) NDP / ARP helpers ─────────────────────────────
#
# The reader thread's asyncio event loop must never block on scapy
# parsing.  These helpers extract fields and build reply frames from
# raw bytes so ARP and NDP Neighbor Solicitation handling stays on
# the fast path (~µs instead of ~10 ms per scapy parse).


def _mac_bytes(mac_str: str) -> bytes:
    """'02:00:00:5e:00:01' → 6 bytes."""
    return bytes(int(b, 16) for b in mac_str.split(":"))


def _mac_str(raw: bytes) -> str:
    """6 bytes → '02:00:00:5e:00:01'."""
    return ":".join(f"{b:02x}" for b in raw)


def fast_extract_ndp_ns(raw: bytes, is_tap: bool) -> tuple[str, str, str] | None:
    """Extract (src_mac, src_ip, target_ip) from an NDP NS frame.

    Returns ``None`` if the frame is too short or not a valid NS.
    Caller must have already verified ``fast_is_arp_or_ndp_ns()``.

    Layout (TAP / Ethernet):
        [0:6]   dst_mac
        [6:12]  src_mac
        [12:14] ethertype 0x86dd
        --- IPv6 header (40 bytes) at offset 14 ---
        [14+8 : 14+24]  src IPv6  (16 bytes)
        --- ICMPv6 NS at offset 14+40 ---
        [54]    type=135  [55] code=0  [56:58] cksum  [58:62] reserved
        [62:78] target IPv6 (16 bytes)
    """
    if is_tap:
        # Need at least: 14 (eth) + 40 (ipv6) + 24 (NS hdr+target)
        if len(raw) < 78:
            return None
        src_mac = _mac_str(raw[6:12])
        src_ip = str(ipaddress.IPv6Address(raw[22:38]))
        target_ip = str(ipaddress.IPv6Address(raw[62:78]))
        return src_mac, src_ip, target_ip
    else:
        # TUN: no ethernet header
        if len(raw) < 64:
            return None
        src_mac = "00:00:00:00:00:00"  # no L2 in TUN mode
        src_ip = str(ipaddress.IPv6Address(raw[8:24]))
        target_ip = str(ipaddress.IPv6Address(raw[48:64]))
        return src_mac, src_ip, target_ip


def fast_extract_arp_request(raw: bytes, is_tap: bool) -> tuple[str, str, str, str] | None:
    """Extract (src_mac, src_ip, dst_mac_ignored, dst_ip) from an ARP who-has.

    Returns ``None`` if the frame is too short or not op=1 (request).

    Layout (TAP / Ethernet):
        [14]    hw-type(2) proto-type(2) hw-size(1) proto-size(1) opcode(2)
        [22:28] sender MAC  [28:32] sender IP
        [32:38] target MAC  [38:42] target IP
    """
    if not is_tap:
        return None  # ARP is L2-only, no TUN
    if len(raw) < 42:
        return None
    # opcode at offset 20-21 (big-endian), must be 1 (request)
    op = (raw[20] << 8) | raw[21]
    if op != 1:
        return None
    src_mac = _mac_str(raw[22:28])
    src_ip = socket.inet_ntoa(raw[28:32])
    dst_ip = socket.inet_ntoa(raw[38:42])
    return src_mac, src_ip, "00:00:00:00:00:00", dst_ip


def _icmpv6_checksum(src_ip: bytes, dst_ip: bytes, payload: bytes) -> int:
    """Compute ICMPv6 checksum over the IPv6 pseudo-header + payload."""
    # Pseudo-header: src(16) + dst(16) + upper-layer-length(4) + zeros(3) + next-header(1)
    ph = src_ip + dst_ip + struct.pack("!I", len(payload)) + b"\x00\x00\x00\x3a"
    data = ph + payload
    # Standard ones-complement checksum
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def fast_build_ndp_na(
    src_mac: str, src_ip: str,
    dst_mac: str, dst_ip: str, target_ip: str,
) -> bytes:
    """Build an NDP Neighbor Advertisement without scapy.

    Constructs the full Ethernet + IPv6 + ICMPv6 NA + target-LL-addr
    option frame and computes the ICMPv6 checksum inline.
    """
    src_mac_b = _mac_bytes(src_mac)
    dst_mac_b = _mac_bytes(dst_mac)
    src_ip_b = ipaddress.IPv6Address(src_ip).packed
    dst_ip_b = ipaddress.IPv6Address(dst_ip).packed
    target_ip_b = ipaddress.IPv6Address(target_ip).packed

    # Flags: R=0, S=solicited(1 for unicast, 0 for multicast), O=1
    is_multicast = dst_ip.startswith("ff02::")
    flags = 0x20000000 if is_multicast else 0x60000000  # S=0,O=1 vs S=1,O=1

    # ICMPv6 NA body: type(1) code(1) cksum(2) flags(4) target(16)
    # + option: type=2(target-LL-addr) len=1(8 bytes) lladdr(6)
    icmp_payload = struct.pack("!BBH I 16s BB 6s",
                               136, 0, 0,   # type=NA, code=0, cksum=0 (placeholder)
                               flags,
                               target_ip_b,
                               2, 1,         # opt type=target-LL-addr, opt len=1 (8 bytes)
                               src_mac_b)
    # Compute checksum and patch it in
    cksum = _icmpv6_checksum(src_ip_b, dst_ip_b, icmp_payload)
    icmp_payload = icmp_payload[:2] + struct.pack("!H", cksum) + icmp_payload[4:]

    # IPv6 header: version=6, traffic-class=0, flow-label=0,
    # payload-length, next-header=58 (ICMPv6), hop-limit=255
    ipv6_hdr = struct.pack("!I HBB 16s 16s",
                           0x60000000,           # ver=6, tc=0, fl=0
                           len(icmp_payload),    # payload length
                           58,                   # next header = ICMPv6
                           255,                  # hop limit
                           src_ip_b,
                           dst_ip_b)

    # Ethernet header
    eth_hdr = dst_mac_b + src_mac_b + b"\x86\xdd"

    return eth_hdr + ipv6_hdr + icmp_payload


def fast_build_arp_reply(
    src_mac: str, src_ip: str,
    dst_mac: str, dst_ip: str,
) -> bytes:
    """Build an ARP reply without scapy.

    Fixed 42-byte Ethernet + ARP frame.
    """
    src_mac_b = _mac_bytes(src_mac)
    dst_mac_b = _mac_bytes(dst_mac)
    src_ip_b = socket.inet_aton(src_ip)
    dst_ip_b = socket.inet_aton(dst_ip)

    eth_hdr = dst_mac_b + src_mac_b + b"\x08\x06"
    # ARP: hw=Ethernet(1), proto=IPv4(0x0800), hw-size=6, proto-size=4,
    #      op=2(reply), sender-MAC, sender-IP, target-MAC, target-IP
    arp_body = struct.pack("!HHBBH 6s 4s 6s 4s",
                           1, 0x0800, 6, 4, 2,
                           src_mac_b, src_ip_b,
                           dst_mac_b, dst_ip_b)
    return eth_hdr + arp_body


def _next_sport() -> int:
    global _eph_counter
    _eph_counter = 32768 + ((_eph_counter - 32768 + 1) % 28000)
    return _eph_counter


# ── Lazy scapy import ────────────────────────────────────────────────

_scapy: Any = None


def _sc() -> Any:
    """Return the scapy.all module, loading on first call."""
    global _scapy
    if _scapy is None:
        import scapy.all as _m  # noqa: F401
        from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: F401
        from scapy.layers.inet6 import (  # noqa: F401
            ICMPv6EchoRequest,
            ICMPv6ND_NA,
            ICMPv6ND_NS,
            ICMPv6ND_RA,
            ICMPv6ND_RS,
            IPv6,
        )
        from scapy.layers.l2 import ARP, Ether  # noqa: F401
        _scapy = _m
    return _scapy


@dataclass
class PacketSummary:
    """Condensed description of a captured packet for correlation/trace."""
    family: int                 # 4 or 6, 0 for ARP/NDP
    proto: str                  # 'tcp' | 'udp' | 'icmp' | 'icmpv6'
                                # | 'arp' | 'ndp' | 'esp' | 'gre' | 'other'
    src: str | None = None      # source address (IP or MAC for ARP)
    dst: str | None = None      # destination address
    sport: int | None = None
    dport: int | None = None
    flags: str | None = None    # TCP flags like 'S', 'SA'
    arp_op: int | None = None   # ARP opcode (1=req, 2=reply)
    ndp_type: int | None = None # ICMPv6 NDP subtype (NS=135, NA=136, …)
    length: int = 0
    raw: bytes = b""            # original bytes (for re-injection/debug)
    # Probe-id stash: encoded into IPv4 ``id`` (16 bits) or IPv6 flow
    # label (20 bits). The controller uses this to correlate an
    # observed packet to the probe that sourced it without relying on
    # fragile src/dst/port matching.
    probe_id: int | None = None


# ── Builders (host → wire) ───────────────────────────────────────────


def _ipv4(src: str, dst: str, proto: int | None = None,
          probe_id: int | None = None) -> Any:
    """Build an IPv4 layer with optional probe_id stashed in the id field."""
    s = _sc()
    kwargs: dict[str, Any] = {"src": src, "dst": dst}
    if proto is not None:
        kwargs["proto"] = proto
    if probe_id is not None:
        kwargs["id"] = probe_id & 0xffff
    return s.IP(**kwargs)


def _ipv6(src: str, dst: str, nh: int | None = None,
          probe_id: int | None = None) -> Any:
    """Build an IPv6 layer with optional probe_id stashed in fl."""
    s = _sc()
    kwargs: dict[str, Any] = {"src": src, "dst": dst}
    if nh is not None:
        kwargs["nh"] = nh
    if probe_id is not None:
        kwargs["fl"] = probe_id & 0xfffff
    return s.IPv6(**kwargs)


def build_tcp(src_ip: str, dst_ip: str, dport: int, *,
              sport: int | None = None, flags: str = "S",
              family: int = 4, payload: bytes = b"",
              probe_id: int | None = None,
              src_mac: str | None = None, dst_mac: str | None = None,
              wrap_ether: bool = True) -> bytes:
    """Build a TCP probe packet (default SYN). Returns raw bytes."""
    s = _sc()
    sport = sport or _next_sport()
    ip = _ipv6(src_ip, dst_ip, probe_id=probe_id) if family == 6 \
        else _ipv4(src_ip, dst_ip, probe_id=probe_id)
    layer = ip / s.TCP(sport=sport, dport=dport, flags=flags) / payload
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_udp(src_ip: str, dst_ip: str, dport: int, *,
              sport: int | None = None, family: int = 4,
              payload: bytes = b"PING",
              probe_id: int | None = None,
              src_mac: str | None = None, dst_mac: str | None = None,
              wrap_ether: bool = True) -> bytes:
    s = _sc()
    sport = sport or _next_sport()
    ip = _ipv6(src_ip, dst_ip, probe_id=probe_id) if family == 6 \
        else _ipv4(src_ip, dst_ip, probe_id=probe_id)
    layer = ip / s.UDP(sport=sport, dport=dport) / payload
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_icmp(src_ip: str, dst_ip: str, *,
               type: int = 8, code: int = 0, family: int = 4,
               payload: bytes = b"simlab",
               probe_id: int | None = None,
               src_mac: str | None = None, dst_mac: str | None = None,
               wrap_ether: bool = True) -> bytes:
    """Build an ICMP echo request (v4)."""
    s = _sc()
    ip = _ipv4(src_ip, dst_ip, probe_id=probe_id)
    layer = ip / s.ICMP(type=type, code=code) / payload
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_icmpv6(src_ip: str, dst_ip: str, *,
                 type: int = 128, code: int = 0,
                 payload: bytes = b"simlab",
                 probe_id: int | None = None,
                 src_mac: str | None = None, dst_mac: str | None = None,
                 wrap_ether: bool = True) -> bytes:
    """Build an ICMPv6 echo request (type 128)."""
    s = _sc()
    ip = _ipv6(src_ip, dst_ip, probe_id=probe_id)
    if type == 128:
        layer = ip / s.ICMPv6EchoRequest(data=payload)
    else:
        from scapy.layers.inet6 import ICMPv6Unknown
        layer = ip / ICMPv6Unknown(type=type, code=code)
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_raw_ip(src_ip: str, dst_ip: str, proto: int, *,
                 family: int = 4, payload: bytes = b"",
                 probe_id: int | None = None,
                 src_mac: str | None = None, dst_mac: str | None = None,
                 wrap_ether: bool = True) -> bytes:
    """Catch-all for arbitrary IP protocols (SCTP, AH, PIM, …).

    When scapy has a dedicated layer for the protocol use the
    specific builder instead — this helper's only role is to
    exercise chains whose rule says ``-p <unknown number>``.
    """
    s = _sc()
    ip = (
        _ipv6(src_ip, dst_ip, nh=proto, probe_id=probe_id)
        if family == 6 else
        _ipv4(src_ip, dst_ip, proto=proto, probe_id=probe_id)
    )
    layer = ip / s.Raw(load=payload)
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


# IANA assigned IP protocol numbers — the subset that might appear
# in shorewall ``rules`` files. Anything not listed here can still
# be used as a numeric string ("89") or via the small fallback table
# in ``proto_number()``. We deliberately keep this hand-curated
# rather than parsing /etc/protocols at runtime so the simlab works
# in chroots that don't ship that file (e.g. distroless / busybox).
_PROTO_NUMBERS: dict[str, int] = {
    "icmp": 1, "igmp": 2, "ipv4": 4, "tcp": 6, "egp": 8, "udp": 17,
    "rdp": 27, "dccp": 33, "ipv6": 41, "rsvp": 46, "gre": 47,
    "esp": 50, "ah": 51, "ipv6-icmp": 58, "icmpv6": 58, "ipv6-nonxt": 59,
    "ipv6-opts": 60, "ospf": 89, "ipip": 94, "etherip": 97, "encap": 98,
    "pim": 103, "vrrp": 112, "l2tp": 115, "sctp": 132, "fc": 133,
    "mh": 135, "udplite": 136, "mpls-in-ip": 137,
}


def proto_number(name_or_num: str | int | None) -> int | None:
    """Resolve a protocol token to its IANA number, or ``None``.

    Accepts ``None``, an empty string, a numeric string ("112"),
    an int (112), or a well-known name from ``_PROTO_NUMBERS``
    ("vrrp"). Used by the simlab dispatch fallback so any rule
    with ``-p <proto>`` — even one we have no dedicated builder
    for — gets a probe.
    """
    if name_or_num is None:
        return None
    if isinstance(name_or_num, int):
        return name_or_num if 0 <= name_or_num <= 255 else None
    s = name_or_num.strip().lower()
    if not s:
        return None
    if s.isdigit():
        n = int(s)
        return n if 0 <= n <= 255 else None
    return _PROTO_NUMBERS.get(s)


def build_unknown_proto(
    src_ip: str, dst_ip: str, proto: str | int, *,
    family: int = 4,
    payload_byte: int = 0xfe, payload_len: int = 16,
    probe_id: int | None = None,
    src_mac: str | None = None, dst_mac: str | None = None,
    wrap_ether: bool = True,
) -> bytes | None:
    """Build a minimal IPv4/IPv6 packet for an arbitrary IP protocol.

    Used by the simlab dispatch as a generic fallback for any
    protocol we don't have a dedicated builder for (or where the
    dedicated builder isn't worth the maintenance burden — esp/
    ah/gre/vrrp/ospf/igmp/sctp/pim all fall into this bucket).

    The packet is minimal by design:

      * IPv4 / IPv6 header with ``protocol`` / ``next-header`` set
        to the requested number
      * ``probe_id`` tunnelled through the IP id field (v4) or
        flow label (v6) so the simlab observer can correlate
      * payload = ``payload_byte`` repeated ``payload_len`` times
        (default 16 × 0xfe — distinctive enough to spot in pcap
        diffs but small enough to dodge MTU issues on tagged VLANs)

    Returns ``None`` if the proto token cannot be resolved to a
    number — caller's responsibility to handle that case.
    """
    n = proto_number(proto)
    if n is None:
        return None
    return build_raw_ip(
        src_ip, dst_ip, n,
        family=family,
        payload=bytes([payload_byte]) * payload_len,
        probe_id=probe_id,
        src_mac=src_mac, dst_mac=dst_mac,
        wrap_ether=wrap_ether,
    )


def build_arp_request(src_mac: str, src_ip: str, dst_ip: str) -> bytes:
    """Build an ARP who-has request (L2, broadcast)."""
    s = _sc()
    frame = (
        s.Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        s.ARP(op=1, hwsrc=src_mac, psrc=src_ip, pdst=dst_ip)
    )
    return bytes(frame)


def build_arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    """Build an ARP reply (L2)."""
    s = _sc()
    frame = (
        s.Ether(src=src_mac, dst=dst_mac) /
        s.ARP(op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    )
    return bytes(frame)


def build_ndp_ns(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    """Build an IPv6 Neighbor Solicitation (NS) for ``target_ip``."""
    s = _sc()
    from scapy.layers.inet6 import ICMPv6NDOptSrcLLAddr
    # Solicited-node multicast for the target
    suffix = target_ip.split(":")[-1]
    solicited = f"ff02::1:ff00:{suffix}" if ":" in target_ip else "ff02::1"
    frame = (
        s.Ether(src=src_mac, dst="33:33:ff:00:00:01") /
        s.IPv6(src=src_ip, dst=solicited) /
        s.ICMPv6ND_NS(tgt=target_ip) /
        ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    )
    return bytes(frame)


def build_ndp_na(src_mac: str, src_ip: str,
                 dst_mac: str, dst_ip: str, target_ip: str) -> bytes:
    """Build an IPv6 Neighbor Advertisement (NA).

    For unicast NA (dst is specific IPv6 address), S=1 (solicited).
    For multicast NA (dst=ff02::1), S=0 (unsolicited) per RFC 4861.
    """
    s = _sc()
    from scapy.layers.inet6 import ICMPv6NDOptDstLLAddr
    # Multicast NA must have S=0, unicast NA has S=1
    is_multicast = dst_ip.startswith("ff02::") or dst_ip == "ff02::1"
    frame = (
        s.Ether(src=src_mac, dst=dst_mac) /
        s.IPv6(src=src_ip, dst=dst_ip) /
        s.ICMPv6ND_NA(tgt=target_ip, R=0, S=0 if is_multicast else 1, O=1) /
        ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    )
    return bytes(frame)


def build_esp(src_ip: str, dst_ip: str, *, spi: int = 0x1000, seq: int = 1,
              family: int = 4, payload: bytes = b"\x00" * 16,
              src_mac: str | None = None, dst_mac: str | None = None,
              wrap_ether: bool = True,
              probe_id: int | None = None) -> bytes:
    """Build an ESP packet (IP proto 50, bare).

    ``probe_id`` is tunnelled through the IP id field (v4) or the
    flow-label field (v6) so the simlab observer can correlate
    the inject with the observed frame on the expect side.
    """
    s = _sc()
    from scapy.layers.ipsec import ESP
    if family == 6:
        ip6_kwargs: dict = {"src": src_ip, "dst": dst_ip, "nh": 50}
        if probe_id is not None:
            ip6_kwargs["fl"] = probe_id & 0xfffff
        layer = s.IPv6(**ip6_kwargs) / ESP(spi=spi, seq=seq, data=payload)
    else:
        ip_kwargs: dict = {"src": src_ip, "dst": dst_ip, "proto": 50}
        if probe_id is not None:
            ip_kwargs["id"] = probe_id & 0xffff
        layer = s.IP(**ip_kwargs) / ESP(spi=spi, seq=seq, data=payload)
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_ah(src_ip: str, dst_ip: str, *, spi: int = 0x1000, seq: int = 1,
             family: int = 4,
             src_mac: str | None = None, dst_mac: str | None = None,
             wrap_ether: bool = True,
             probe_id: int | None = None) -> bytes:
    """Build an AH packet (IP proto 51, no inner payload).

    AH is the IPsec authentication header. We emit a minimal
    24-byte AH (no integrity data) just to exercise rules with
    ``-p ah`` / ``-p 51`` — production peers will reject the
    packet but the firewall's match decision is what we care
    about.

    ``probe_id`` is tunnelled through the IP id field (v4) or
    the flow-label field (v6).
    """
    s = _sc()
    from scapy.layers.ipsec import AH
    ah = AH(spi=spi, seq=seq, icv=b"\x00" * 12)
    if family == 6:
        ip6_kwargs: dict = {"src": src_ip, "dst": dst_ip, "nh": 51}
        if probe_id is not None:
            ip6_kwargs["fl"] = probe_id & 0xfffff
        layer = s.IPv6(**ip6_kwargs) / ah
    else:
        ip_kwargs: dict = {"src": src_ip, "dst": dst_ip, "proto": 51}
        if probe_id is not None:
            ip_kwargs["id"] = probe_id & 0xffff
        layer = s.IP(**ip_kwargs) / ah
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_gre(src_ip: str, dst_ip: str, *,
              inner: Any = None, family: int = 4,
              src_mac: str | None = None, dst_mac: str | None = None,
              wrap_ether: bool = True,
              probe_id: int | None = None) -> bytes:
    """Build a GRE packet (IP proto 47), carrying the given inner payload.

    ``probe_id`` is tunnelled through the IP id field (v4) or the
    flow-label field (v6) so the simlab observer can correlate
    the inject with the observed frame on the expect side.
    """
    s = _sc()
    from scapy.layers.inet import GRE
    gre = GRE()
    if inner is not None:
        gre = gre / inner
    if family == 6:
        ip6_kwargs: dict = {"src": src_ip, "dst": dst_ip, "nh": 47}
        if probe_id is not None:
            ip6_kwargs["fl"] = probe_id & 0xfffff
        layer = s.IPv6(**ip6_kwargs) / gre
    else:
        ip_kwargs: dict = {"src": src_ip, "dst": dst_ip, "proto": 47}
        if probe_id is not None:
            ip_kwargs["id"] = probe_id & 0xffff
        layer = s.IP(**ip_kwargs) / gre
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_vrrp(src_ip: str, vrid: int = 1, prio: int = 100, *,
               vips: list[str] | None = None,
               src_mac: str | None = None, dst_mac: str | None = None,
               wrap_ether: bool = True,
               probe_id: int | None = None) -> bytes:
    """Build a VRRPv2 advertisement (proto 112 → multicast 224.0.0.18).

    ``probe_id`` is tunnelled through the IP id field so the
    simlab observer can correlate the inject with the observed
    frame on the expect side. Only the low 16 bits are used.
    """
    s = _sc()
    from scapy.layers.vrrp import VRRP
    vrrp = VRRP(version=2, type=1, vrid=vrid, priority=prio,
                addrlist=vips or [src_ip])
    ip_kwargs: dict = {"src": src_ip, "dst": "224.0.0.18",
                       "proto": 112, "ttl": 255}
    if probe_id is not None:
        ip_kwargs["id"] = probe_id & 0xffff
    layer = s.IP(**ip_kwargs) / vrrp
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_ospf_hello(src_ip: str, area: str = "0.0.0.0",
                     router_id: str | None = None, *,
                     src_mac: str | None = None, dst_mac: str | None = None,
                     wrap_ether: bool = True) -> bytes:
    """Build an OSPFv2 HELLO (proto 89, multicast 224.0.0.5)."""
    s = _sc()
    try:
        from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
    except ImportError:
        return build_tcp(src_ip, "224.0.0.5", 0, flags="S",
                         src_mac=src_mac, dst_mac=dst_mac, wrap_ether=wrap_ether)
    ospf = OSPF_Hdr(version=2, type=1, src=router_id or src_ip, area=area) / \
           OSPF_Hello(mask="255.255.255.0", helloint=10, deadint=40,
                      router=router_id or src_ip)
    layer = s.IP(src=src_ip, dst="224.0.0.5", proto=89, ttl=1) / ospf
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_dns_query(src_ip: str, dst_ip: str, qname: str, *,
                    qtype: str = "A", sport: int | None = None,
                    src_mac: str | None = None, dst_mac: str | None = None,
                    wrap_ether: bool = True) -> bytes:
    """Build a DNS query (UDP/53) for a given name."""
    s = _sc()
    from scapy.layers.dns import DNS, DNSQR
    sport = sport or _next_sport()
    dns = DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    layer = s.IP(src=src_ip, dst=dst_ip) / s.UDP(sport=sport, dport=53) / dns
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_dhcp_discover(src_mac: str, *,
                        dst_mac: str = "ff:ff:ff:ff:ff:ff",
                        xid: int = 0x12345678) -> bytes:
    """Build a DHCP DISCOVER broadcast (udp 67/68)."""
    s = _sc()
    from scapy.layers.dhcp import BOOTP, DHCP
    layer = (
        s.IP(src="0.0.0.0", dst="255.255.255.255") /
        s.UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(src_mac.replace(":", "")),
              xid=xid, flags=0x8000) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    frame = s.Ether(src=src_mac, dst=dst_mac) / layer
    return bytes(frame)


# ── pcap export helper ──────────────────────────────────────────────


def export_trace_pcap(
    trace: list[dict],
    raw_by_iface: dict[str, list[bytes]] | None,
    path: str,
) -> None:
    """Write a trace-buffer dump to a pcap file.

    ``raw_by_iface`` maps interface name → list of raw bytes (the
    worker's ring buffer). The trace list is used for metadata only.
    """
    s = _sc()
    from scapy.utils import wrpcap
    pkts: list = []
    if raw_by_iface:
        for iface, raws in raw_by_iface.items():
            for raw in raws:
                try:
                    pkts.append(s.Ether(raw))
                except Exception:
                    pass
    wrpcap(path, pkts)


def _finalize(layer: Any, src_mac: str | None, dst_mac: str | None,
              wrap_ether: bool) -> bytes:
    """Wrap an IP/IPv6 scapy layer in Ethernet and return raw bytes.

    If ``wrap_ether=False`` (TUN mode) return the bare IP packet.

    ``src_mac`` defaults to the controller's synthetic worker MAC
    (``02:00:00:5e:00:01``). The simlab controller answers every
    ARP who-has on every TAP with that MAC, so using the same
    address on the inject side keeps the kernel's neighbour table
    consistent: when the kernel receives our injected frame it
    registers ``src_ip → src_mac`` in its neighbour cache, and the
    later ARP reply for that IP returns the same MAC. A mismatch
    between the injected Ethernet src and the controller's ARP
    reply causes Linux to silently drop the forwarded packet as a
    stale/ambiguous neighbour-table update, which used to produce
    thousands of spurious ``fail_drop`` in the simlab report.
    """
    s = _sc()
    if not wrap_ether:
        return bytes(layer)
    if not src_mac:
        src_mac = "02:00:00:5e:00:01"  # same as controller._WORKER_MAC
    if not dst_mac:
        dst_mac = "ff:ff:ff:ff:ff:ff"
    etype = 0x86dd if layer.__class__.__name__ == "IPv6" else 0x0800
    frame = s.Ether(src=src_mac, dst=dst_mac, type=etype) / layer
    return bytes(frame)


# ── Parser (wire → summary) ─────────────────────────────────────────


def parse(raw: bytes, *, is_tap: bool = True) -> PacketSummary:
    """Parse raw bytes from a TUN/TAP fd into a PacketSummary.

    Returns ``proto='other'`` if the packet doesn't match any known
    shape. Never raises on malformed input — always returns a summary.
    """
    s = _sc()
    summary = PacketSummary(family=0, proto="other",
                            length=len(raw), raw=raw)
    try:
        if is_tap:
            pkt = s.Ether(raw)
        else:
            first = raw[0] >> 4 if raw else 0
            if first == 6:
                pkt = s.IPv6(raw)
            else:
                pkt = s.IP(raw)
    except Exception:
        return summary

    # ARP (TAP only)
    if is_tap and pkt.haslayer(s.ARP):
        arp = pkt[s.ARP]
        summary.family = 0
        summary.proto = "arp"
        summary.src = arp.psrc
        summary.dst = arp.pdst
        summary.arp_op = int(arp.op)
        return summary

    # IPv4
    if pkt.haslayer(s.IP):
        ip = pkt[s.IP]
        summary.family = 4
        summary.src = ip.src
        summary.dst = ip.dst
        try:
            summary.probe_id = int(ip.id)
        except Exception:
            pass
        if pkt.haslayer(s.TCP):
            tcp = pkt[s.TCP]
            summary.proto = "tcp"
            summary.sport = int(tcp.sport)
            summary.dport = int(tcp.dport)
            summary.flags = str(tcp.flags)
        elif pkt.haslayer(s.UDP):
            udp = pkt[s.UDP]
            summary.proto = "udp"
            summary.sport = int(udp.sport)
            summary.dport = int(udp.dport)
        elif pkt.haslayer(s.ICMP):
            summary.proto = "icmp"
        elif ip.proto == 50:
            summary.proto = "esp"
        elif ip.proto == 51:
            summary.proto = "ah"
        elif ip.proto == 47:
            summary.proto = "gre"
        elif ip.proto == 112:
            summary.proto = "vrrp"
        return summary

    # IPv6
    try:
        from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, IPv6
        if pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            summary.family = 6
            summary.src = ip6.src
            summary.dst = ip6.dst
            try:
                summary.probe_id = int(ip6.fl)
            except Exception:
                pass
            if pkt.haslayer(ICMPv6ND_NS):
                summary.proto = "ndp"
                summary.ndp_type = 135
                return summary
            if pkt.haslayer(ICMPv6ND_NA):
                summary.proto = "ndp"
                summary.ndp_type = 136
                return summary
            if pkt.haslayer(s.TCP):
                tcp = pkt[s.TCP]
                summary.proto = "tcp"
                summary.sport = int(tcp.sport)
                summary.dport = int(tcp.dport)
                summary.flags = str(tcp.flags)
                return summary
            if pkt.haslayer(s.UDP):
                udp = pkt[s.UDP]
                summary.proto = "udp"
                summary.sport = int(udp.sport)
                summary.dport = int(udp.dport)
                return summary
            # ICMPv6 / ESP / GRE
            nh = ip6.nh
            if nh == 58:
                summary.proto = "icmpv6"
            elif nh == 50:
                summary.proto = "esp"
            elif nh == 47:
                summary.proto = "gre"
    except ImportError:
        pass
    return summary
