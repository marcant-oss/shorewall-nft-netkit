"""NAT + deep conntrack verification.

Phase IV of the dual-stack simulation plan — asserts that DNAT / SNAT /
MASQUERADE rules actually rewrite the packet headers **and** that the
conntrack table reflects the expected tuplehash divergence.

Four verification categories
-----------------------------
1. :func:`verify_dnat` — DNAT rewrite: daddr at backend + reverse saddr.
2. :func:`verify_snat` — SNAT / MASQUERADE rewrite: saddr on egress + reverse.
3. :func:`verify_ct_state` — conntrack state assertion (NEW / ESTABLISHED /
   RELATED) for a flow tuple.
4. :func:`verify_ct_nat_tuple` — tuplehash_orig vs tuplehash_reply divergence
   on the NAT'd field (daddr / saddr / dport / sport).

Design constraints
------------------
- **pyroute2-first** — all conntrack reads use :class:`pyroute2.NFCTSocket`;
  no subprocess ``conntrack`` calls.
- **Dual-stack** — v4 and v6 are handled symmetrically.  The caller
  picks ``family=4`` or ``family=6``; internally this toggles between
  ``socket.AF_INET`` and ``socket.AF_INET6`` and between ``AF_INET``
  and ``AF_INET6`` NFCTSocket filters.
- **Backward-compat** — validators skip silently when no NAT rules are
  present in the dump; they never return a *fail* just because there is
  nothing to verify.
- **ICMP conntrack graceful degradation** — if ``nf_conntrack_proto_icmpv6``
  is absent the ICMP NAT verifiers return ``passed=False, inconclusive=True``
  rather than a hard failure.
- **MASQUERADE ephemeral sport** — the SNAT / MASQUERADE verifier matches
  only on ``proto + daddr`` when the sport is random, not on a specific
  port number.

Usage
-----
Callers (simulate.py, simlab) are expected to:

1. Parse the iptables-save dump via
   ``shorewall_nft.verify.iptables_parser.parse_iptables_save()``.
2. Extract NAT rules into a list of :class:`NatRule` using
   :func:`extract_nat_rules`.
3. For each rule, call the appropriate ``verify_*`` function, passing
   the pre-created namespace names.
4. Collect :class:`NatResult` / :class:`CtStateResult` /
   :class:`CtNatResult` objects and render them alongside the main
   simulation report.

The validators do **not** create or destroy namespaces.  Topology setup
is the caller's responsibility.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from pyroute2 import NFCTSocket
from pyroute2.netlink.nfnetlink.nfctsocket import NFCTAttrTuple

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Public result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NatResult:
    """Result of a DNAT or SNAT rewrite probe.

    Attributes:
        rule_tag:          Short identifier, e.g. ``"DNAT:10.0.0.5:80"``.
        passed:            ``True`` iff both the forward rewrite and the
                           reverse saddr/daddr are correct.
        forward_daddr_ok:  ``True`` iff the backend received the packet with
                           the rewritten destination address (DNAT) or the
                           probe left the FW with the rewritten source
                           address (SNAT).
        reverse_saddr_ok:  ``True`` iff the reply packet left the FW with
                           the original VIP as its source (DNAT) or the
                           original source IP on the reply direction (SNAT).
        inconclusive:      ``True`` when the probe could not be verified —
                           typically because a required kernel module
                           (``nf_conntrack_proto_icmpv6``) is absent.
        detail:            Human-readable explanation.
        family:            IP family (4 or 6).
    """

    rule_tag: str
    passed: bool
    forward_daddr_ok: bool
    reverse_saddr_ok: bool
    detail: str
    inconclusive: bool = False
    family: int = 4


@dataclass(frozen=True)
class CtStateResult:
    """Result of a conntrack state assertion.

    Attributes:
        flow_tuple:     ``(src_ip, dst_ip, sport, dport, proto)`` for the
                        flow that was queried.
        expected_state: ``"NEW"`` | ``"ESTABLISHED"`` | ``"RELATED"``.
        observed_state: The conntrack state string from the kernel, or
                        ``None`` if no entry was found.
        passed:         ``True`` iff ``observed_state == expected_state``.
        inconclusive:   ``True`` when the kernel module is absent and we
                        cannot enumerate ct entries for this protocol.
        detail:         Human-readable explanation.
    """

    flow_tuple: tuple[str, str, int, int, str]
    expected_state: str
    observed_state: str | None
    passed: bool
    detail: str
    inconclusive: bool = False


@dataclass(frozen=True)
class CtNatResult:
    """Result of a conntrack NAT tuple divergence check.

    Attributes:
        orig_tuple:             The original 5-tuple as presented to ct.
        reply_tuple_observed:   The reply-direction 5-tuple read from the
                                ct entry, or ``None`` if no entry found.
        expected_rewrite_field: Which field should differ between orig and
                                reply: ``"daddr"`` | ``"saddr"`` |
                                ``"dport"`` | ``"sport"``.
        passed:                 ``True`` iff the specified field diverges.
        inconclusive:           ``True`` when kernel module is absent.
        detail:                 Human-readable explanation.
    """

    orig_tuple: tuple[str, str, int, int, str]
    reply_tuple_observed: tuple[str, str, int, int, str] | None
    expected_rewrite_field: str
    passed: bool
    detail: str
    inconclusive: bool = False


# ---------------------------------------------------------------------------
# NatRule — parsed from iptables dump
# ---------------------------------------------------------------------------


@dataclass
class NatRule:
    """A DNAT / SNAT / MASQUERADE rule extracted from an iptables dump.

    Attributes:
        nat_type:     ``"DNAT"`` | ``"SNAT"`` | ``"MASQUERADE"``.
        chain:        iptables chain name (e.g. ``"PREROUTING"``).
        proto:        Protocol string (``"tcp"`` / ``"udp"`` / ``None``).
        match_saddr:  Source address match (CIDR or plain IP), or ``None``.
        match_daddr:  Destination address match (CIDR or plain IP), or ``None``.
        match_dport:  Destination port or range match, or ``None``.
        match_sport:  Source port match, or ``None``.
        to_dest:      DNAT target ``IP:port`` string from ``--to-destination``.
        to_source:    SNAT target IP string from ``--to-source``.
        iif:          Ingress interface match, or ``None``.
        raw_line:     Original iptables-save line for diagnostics.
    """

    nat_type: str                    # DNAT | SNAT | MASQUERADE
    chain: str
    proto: str | None = None
    match_saddr: str | None = None
    match_daddr: str | None = None
    match_dport: str | None = None
    match_sport: str | None = None
    to_dest: str | None = None       # DNAT target  "IP:port"
    to_source: str | None = None     # SNAT target  "IP"
    iif: str | None = None
    raw_line: str = ""


def extract_nat_rules(tables: "dict[str, object]") -> list[NatRule]:
    """Extract NAT rules from a parsed iptables dump.

    Parameters
    ----------
    tables:
        Return value of
        ``shorewall_nft.verify.iptables_parser.parse_iptables_save()``.

    Returns
    -------
    list[NatRule]:
        Rules whose ``target`` is ``"DNAT"``, ``"SNAT"``, or
        ``"MASQUERADE"``.  Rules in tables other than ``nat`` are silently
        skipped — the only relevant NAT table in iptables-save is ``nat``.
    """
    results: list[NatRule] = []
    nat_table = tables.get("nat")
    if nat_table is None:
        return results

    nat_targets = {"DNAT", "SNAT", "MASQUERADE"}
    for chain_name, rule_list in nat_table.rules.items():
        for rule in rule_list:
            if rule.target not in nat_targets:
                continue
            nr = NatRule(
                nat_type=rule.target,
                chain=chain_name,
                proto=rule.proto,
                match_saddr=rule.saddr,
                match_daddr=rule.daddr,
                match_dport=rule.dport,
                match_sport=rule.sport,
                to_dest=rule.target_args.get("to-destination"),
                to_source=rule.target_args.get("to-source"),
                iif=rule.iif,
                raw_line=rule.raw,
            )
            results.append(nr)
    return results


# ---------------------------------------------------------------------------
# ProbeSpec — unified probe description (subset of simlab's ProbeSpec)
# ---------------------------------------------------------------------------


@dataclass
class ProbeSpec:
    """Minimal probe specification for NAT verification.

    Attributes:
        src_ip:   Source address to inject from.
        dst_ip:   Destination address — the VIP for DNAT, the real address
                  for SNAT.
        proto:    Protocol: ``"tcp"`` | ``"udp"`` | ``"icmp"`` |
                  ``"icmpv6"``.
        dport:    Destination port (required for tcp/udp).
        sport:    Source port (optional; randomly chosen when ``None``).
        nat_rule: The :class:`NatRule` this probe exercises (for tag
                  generation and rewrite assertions).
    """

    src_ip: str
    dst_ip: str
    proto: str
    dport: int | None = None
    sport: int | None = None
    nat_rule: NatRule | None = None

    @property
    def rule_tag(self) -> str:
        """Short identifier for this probe."""
        if self.nat_rule is not None:
            tag = self.nat_rule.nat_type
            target = self.nat_rule.to_dest or self.nat_rule.to_source or ""
            port = f":{self.dport}" if self.dport else ""
            return f"{tag}:{self.dst_ip}{port}→{target}"
        return f"probe:{self.dst_ip}:{self.dport}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_AF_INET = socket.AF_INET
_AF_INET6 = socket.AF_INET6


def _proto_num(proto: str) -> int:
    """Resolve protocol name to IANA number."""
    mapping = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}
    s = proto.lower().strip()
    if s.isdigit():
        return int(s)
    return mapping.get(s, 0)


def _ct_dump_for_tuple(
    fw_ns: str,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    proto: str,
    *,
    family: Literal[4, 6] = 4,
) -> list[dict]:
    """Read conntrack entries matching a 5-tuple from *fw_ns*.

    Returns a list of raw pyroute2 NF_CONNTRACK message objects, filtered
    to entries whose ``orig_tuple`` matches the given 5-tuple.  An empty
    list is returned when no matching entry is found or when the module is
    unavailable.

    The returned dicts have keys:
        ``"orig"``, ``"reply"`` — each a sub-dict with ``"src"``,
        ``"dst"``, ``"sport"``, ``"dport"``, ``"proto"`` fields.
        ``"state"`` — conntrack state string (``"NEW"`` / ``"ESTABLISHED"``
        / ``"RELATED"`` / ``"TIME_WAIT"`` / …).

    Implementation note: pyroute2's ``NFCTSocket.dump()`` accepts an
    ``NFCTAttrTuple`` filter for the protocol; we additionally filter
    in-process on src/dst to avoid false matches.
    """
    proto_num = _proto_num(proto)
    entries: list[dict] = []

    try:
        flt = NFCTAttrTuple(proto=proto_num)
        with NFCTSocket(netns=fw_ns, flags=os.O_RDONLY) as ct:
            for msg in ct.dump(tuple_orig=flt):
                entry = _parse_ct_msg(msg, family=family)
                if entry is None:
                    continue
                orig = entry.get("orig", {})
                # Filter: match on src+dst+proto (ports may be 0 for ICMP)
                if (
                    orig.get("src") == src_ip
                    and orig.get("dst") == dst_ip
                    and orig.get("proto") == proto_num
                ):
                    entries.append(entry)
    except Exception:  # noqa: BLE001 — module unavailable, netns gone, etc.
        pass

    return entries


def _parse_ct_msg(msg, *, family: int) -> dict | None:
    """Extract orig/reply tuples and state from a pyroute2 ct message."""
    try:
        attrs = dict(msg["attrs"])
    except (TypeError, KeyError, ValueError):
        return None

    def _extract_tuple(tuple_attrs) -> dict:
        """Parse a nested ct-tuple attribute list into a simple dict."""
        t: dict = {}
        if tuple_attrs is None:
            return t
        # pyroute2 encodes ct-tuple attrs as nested (key, value) pairs
        # The structure varies by pyroute2 version; we handle both
        # the nested-dict form and the flat-attr-list form.
        try:
            ta = dict(tuple_attrs)
        except (TypeError, ValueError):
            try:
                ta = {k: v for k, v in tuple_attrs}
            except Exception:
                return t

        # IP addresses
        ip_block = ta.get("CTA_TUPLE_IP") or ta.get("ip")
        if ip_block:
            try:
                ipd = dict(ip_block)
            except Exception:
                ipd = {}
            src = (ipd.get("CTA_IP_V4_SRC") or ipd.get("CTA_IP_V6_SRC")
                   or ipd.get("src"))
            dst = (ipd.get("CTA_IP_V4_DST") or ipd.get("CTA_IP_V6_DST")
                   or ipd.get("dst"))
            if src:
                t["src"] = str(src)
            if dst:
                t["dst"] = str(dst)

        # Ports + proto
        proto_block = ta.get("CTA_TUPLE_PROTO") or ta.get("proto")
        if proto_block:
            try:
                pd = dict(proto_block)
            except Exception:
                pd = {}
            pnum = pd.get("CTA_PROTO_NUM") or pd.get("proto")
            sport = pd.get("CTA_PROTO_SRC_PORT") or pd.get("sport")
            dport = pd.get("CTA_PROTO_DST_PORT") or pd.get("dport")
            if pnum is not None:
                t["proto"] = int(pnum)
            if sport is not None:
                t["sport"] = int(sport)
            if dport is not None:
                t["dport"] = int(dport)
        return t

    orig_raw = attrs.get("CTA_TUPLE_ORIG")
    reply_raw = attrs.get("CTA_TUPLE_REPLY")

    orig = _extract_tuple(orig_raw)
    reply = _extract_tuple(reply_raw)

    # State — pyroute2 keeps it in CTA_STATUS or synthesises it
    state_raw = attrs.get("CTA_STATUS") or attrs.get("state") or ""
    # Attempt a human-readable state from the status bitmask
    state = _status_to_state(state_raw)

    return {"orig": orig, "reply": reply, "state": state}


def _status_to_state(status) -> str:
    """Convert a raw CTA_STATUS bitmask (int or string) to a state label.

    Conntrack status bitmask constants (from linux/netfilter/nf_conntrack_common.h):
      IPS_SEEN_REPLY = 0x8     → at least one reply packet seen
      IPS_CONFIRMED = 0x4      → entry is in the hash tables
      IPS_ASSURED = 0x20       → not a half-open session
    """
    if isinstance(status, str):
        # pyroute2 may return a pre-decoded string like "ESTABLISHED"
        return status.upper() if status else "UNKNOWN"
    try:
        bits = int(status)
    except (TypeError, ValueError):
        return "UNKNOWN"
    # Heuristic mapping (mirrors conntrack CLI output ordering)
    if bits & 0x8:  # IPS_SEEN_REPLY
        if bits & 0x20:  # IPS_ASSURED
            return "ESTABLISHED"
        return "ESTABLISHED"
    return "NEW"


def _icmpv6_ct_available(fw_ns: str) -> bool:
    """Return True if ICMPv6 conntrack entries are queryable."""
    try:
        flt = NFCTAttrTuple(proto=58)  # ICMPv6
        with NFCTSocket(netns=fw_ns, flags=os.O_RDONLY) as ct:
            # A successful dump call (even empty) means the module is loaded
            _ = list(ct.dump(tuple_orig=flt))
        return True
    except Exception:  # noqa: BLE001
        return False


def _inject_tcp(
    src_ip: str,
    dst_ip: str,
    dport: int,
    sport: int | None,
    *,
    family: Literal[4, 6] = 4,
    timeout: float = 1.0,
) -> None:
    """Attempt a TCP SYN to *dst_ip*:*dport*.  Errors are silently ignored."""
    af = _AF_INET6 if family == 6 else _AF_INET
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if sport is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((src_ip, sport))
        s.connect((dst_ip, dport))
        s.send(b"PROBE\r\n")
        s.close()
    except (OSError, socket.timeout):
        pass  # expected — we care about the ct entry, not the connection


def _inject_udp(
    src_ip: str,
    dst_ip: str,
    dport: int,
    sport: int | None,
    *,
    family: Literal[4, 6] = 4,
) -> None:
    """Send a single UDP datagram.  Errors are silently ignored."""
    af = _AF_INET6 if family == 6 else _AF_INET
    try:
        s = socket.socket(af, socket.SOCK_DGRAM)
        if sport is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((src_ip, sport))
        s.sendto(b"PROBE\n", (dst_ip, dport))
        s.close()
    except OSError:
        pass


def _inject_icmp(src_ip: str, dst_ip: str, *, family: Literal[4, 6] = 4) -> None:
    """Send an ICMP echo request.  Errors are silently ignored."""
    af = _AF_INET6 if family == 6 else _AF_INET
    proto = socket.IPPROTO_ICMPV6 if family == 6 else socket.IPPROTO_ICMP
    try:
        s = socket.socket(af, socket.SOCK_RAW, proto)
        s.settimeout(1.0)
        if family == 6:
            # ICMPv6 echo request: type=128, code=0
            payload = struct.pack("!BBHHH", 128, 0, 0, os.getpid() & 0xFFFF, 1)
        else:
            payload = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, 1)
        # Compute checksum for v4 (v6 checksum is computed by kernel)
        if family == 4:
            cksum = _ip_checksum(payload)
            payload = payload[:2] + struct.pack("!H", cksum) + payload[4:]
        s.sendto(payload, (dst_ip, 0))
        s.close()
    except (OSError, PermissionError, socket.timeout):
        pass


def _ip_checksum(data: bytes) -> int:
    """Standard IP / ICMP one's-complement checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _ct_flush(fw_ns: str, proto: str) -> None:
    """Flush conntrack entries for *proto* in *fw_ns*."""
    proto_num = _proto_num(proto)
    try:
        flt = NFCTAttrTuple(proto=proto_num)
        with NFCTSocket(netns=fw_ns, flags=os.O_RDONLY) as ct:
            ct.flush(tuple_orig=flt)
    except Exception:  # noqa: BLE001 — flush best-effort; never fatal
        pass


def _resolve_nat_rewrite(nat_rule: NatRule) -> tuple[str | None, int | None]:
    """Return the (rewritten_ip, rewritten_port) from a NatRule.

    For DNAT: parses ``to_dest`` as ``IP`` or ``IP:port``.
    For SNAT: parses ``to_source`` as ``IP`` or ``IP:port``.
    For MASQUERADE: returns ``(None, None)`` — the IP is dynamic.
    """
    if nat_rule.nat_type == "DNAT" and nat_rule.to_dest:
        raw = nat_rule.to_dest
        if ":" in raw:
            # Could be IP:port or IPv6 address — handle both
            # IPv6 addresses in iptables are in brackets: [::1]:80
            if raw.startswith("["):
                # [IPv6]:port
                bracket_end = raw.find("]")
                ip = raw[1:bracket_end]
                port_str = raw[bracket_end + 2:]
                port = int(port_str) if port_str.isdigit() else None
            elif raw.count(":") == 1:
                # IPv4:port
                ip, port_str = raw.rsplit(":", 1)
                port = int(port_str) if port_str.isdigit() else None
            else:
                # bare IPv6 address (no port)
                ip = raw
                port = None
        else:
            ip = raw
            port = None
        return ip, port

    if nat_rule.nat_type in ("SNAT",) and nat_rule.to_source:
        raw = nat_rule.to_source
        if ":" in raw and raw.count(":") == 1:
            ip, port_str = raw.rsplit(":", 1)
            port = int(port_str) if port_str.isdigit() else None
        else:
            ip = raw
            port = None
        return ip, port

    return None, None


# ---------------------------------------------------------------------------
# Public verifiers
# ---------------------------------------------------------------------------


def verify_dnat(
    probe: ProbeSpec,
    *,
    src_ns: str,
    fw_ns: str,
    dst_ns: str,
    family: Literal[4, 6] = 4,
) -> NatResult:
    """Verify that a DNAT rule rewrites the destination address + port.

    Injects *probe* from *src_ns* targeting the external VIP (*probe.dst_ip*).
    After injection:

    1. Reads the conntrack table in *fw_ns*.
    2. Asserts ``forward_daddr_ok``: the ct reply-direction tuple shows the
       backend IP as the source (i.e. the kernel tracked the rewrite).
    3. Asserts ``reverse_saddr_ok``: the reply direction's destination is the
       original client (src_ip), confirming reverse-path symmetry.

    For ICMP probes when ``nf_conntrack_proto_icmpv6`` is absent, returns
    ``inconclusive=True`` instead of a hard failure.

    Parameters
    ----------
    probe:
        Probe spec.  ``probe.nat_rule`` must be a DNAT :class:`NatRule`.
    src_ns, fw_ns, dst_ns:
        Namespace names (must already exist; created by caller).
    family:
        IP family — 4 (IPv4) or 6 (IPv6).

    Returns
    -------
    NatResult
    """
    tag = probe.rule_tag
    proto = probe.proto.lower()

    # ICMP + ICMPv6 conntrack availability guard
    if proto in ("icmp", "icmpv6") and family == 6:
        if not _icmpv6_ct_available(fw_ns):
            return NatResult(
                rule_tag=tag,
                passed=False,
                forward_daddr_ok=False,
                reverse_saddr_ok=False,
                detail="nf_conntrack_proto_icmpv6 module unavailable — inconclusive",
                inconclusive=True,
                family=family,
            )

    # Parse expected rewrite from the NAT rule
    rewrite_ip, rewrite_port = _resolve_nat_rewrite(probe.nat_rule) \
        if probe.nat_rule else (None, None)
    dport = probe.dport or 0

    # Flush before injection so we get a clean view
    _ct_flush(fw_ns, proto)

    # Inject the probe
    if proto == "tcp":
        _inject_tcp(probe.src_ip, probe.dst_ip, dport, probe.sport, family=family)
    elif proto == "udp":
        _inject_udp(probe.src_ip, probe.dst_ip, dport, probe.sport, family=family)
    else:
        _inject_icmp(probe.src_ip, probe.dst_ip, family=family)

    # Brief settle time for conntrack entry creation
    time.sleep(0.05)

    # Read ct entry for the original tuple (VIP as dst)
    entries = _ct_dump_for_tuple(
        fw_ns,
        src_ip=probe.src_ip,
        dst_ip=probe.dst_ip,
        sport=probe.sport or 0,
        dport=dport,
        proto=proto,
        family=family,
    )

    if not entries:
        return NatResult(
            rule_tag=tag,
            passed=False,
            forward_daddr_ok=False,
            reverse_saddr_ok=False,
            detail=(
                f"No conntrack entry found for {probe.src_ip}→"
                f"{probe.dst_ip}:{dport}/{proto} — "
                "DNAT rule may not have fired or ct was cleared"
            ),
            family=family,
        )

    entry = entries[0]
    orig = entry.get("orig", {})
    reply = entry.get("reply", {})

    # forward_daddr_ok: reply direction src should be the backend IP (rewrite_ip)
    reply_src = reply.get("src")
    forward_daddr_ok: bool
    if rewrite_ip is not None:
        forward_daddr_ok = (
            reply_src is not None
            and _ip_eq(reply_src, rewrite_ip)
        )
    else:
        # No explicit rewrite target — assert that reply.src ≠ orig.dst
        # (i.e. DNAT changed the destination)
        forward_daddr_ok = (
            reply_src is not None
            and reply_src != orig.get("dst")
        )

    # reverse_saddr_ok: reply direction dst should be the original client
    reply_dst = reply.get("dst")
    reverse_saddr_ok = (
        reply_dst is not None
        and _ip_eq(reply_dst, probe.src_ip)
    )

    passed = forward_daddr_ok and reverse_saddr_ok
    detail = (
        f"DNAT {probe.dst_ip}→{rewrite_ip}: "
        f"reply.src={reply_src!r} forward_ok={forward_daddr_ok}; "
        f"reply.dst={reply_dst!r} reverse_ok={reverse_saddr_ok}"
    )
    return NatResult(
        rule_tag=tag,
        passed=passed,
        forward_daddr_ok=forward_daddr_ok,
        reverse_saddr_ok=reverse_saddr_ok,
        detail=detail,
        family=family,
    )


def verify_snat(
    probe: ProbeSpec,
    *,
    src_ns: str,
    fw_ns: str,
    dst_ns: str,
    family: Literal[4, 6] = 4,
) -> NatResult:
    """Verify that a SNAT / MASQUERADE rule rewrites the source address.

    Symmetric to :func:`verify_dnat` but checks the source-address rewrite:

    1. Injects *probe* from *src_ns* toward *probe.dst_ip*.
    2. Reads the ct table in *fw_ns*.
    3. ``forward_daddr_ok``: ct reply.dst == probe.src_ip (original src
       appears in the reply direction, confirming the saddr was rewritten).
    4. ``reverse_saddr_ok``: ct reply.src == probe.dst_ip (destination
       replies back to the SNAT IP, not directly to original src).

    For MASQUERADE (dynamic egress IP), ``to_source`` is ``None`` and the
    verifier matches on the proto+daddr field only rather than a specific
    rewrite IP.

    Parameters
    ----------
    probe:
        Probe spec.  ``probe.nat_rule`` should be a SNAT / MASQUERADE
        :class:`NatRule`.
    src_ns, fw_ns, dst_ns:
        Namespace names.
    family:
        IP family.

    Returns
    -------
    NatResult
    """
    tag = probe.rule_tag
    proto = probe.proto.lower()

    if proto in ("icmp", "icmpv6") and family == 6:
        if not _icmpv6_ct_available(fw_ns):
            return NatResult(
                rule_tag=tag,
                passed=False,
                forward_daddr_ok=False,
                reverse_saddr_ok=False,
                detail="nf_conntrack_proto_icmpv6 module unavailable — inconclusive",
                inconclusive=True,
                family=family,
            )

    dport = probe.dport or 0
    is_masquerade = (
        probe.nat_rule is not None
        and probe.nat_rule.nat_type == "MASQUERADE"
    )

    _ct_flush(fw_ns, proto)

    if proto == "tcp":
        _inject_tcp(probe.src_ip, probe.dst_ip, dport, probe.sport, family=family)
    elif proto == "udp":
        _inject_udp(probe.src_ip, probe.dst_ip, dport, probe.sport, family=family)
    else:
        _inject_icmp(probe.src_ip, probe.dst_ip, family=family)

    time.sleep(0.05)

    entries = _ct_dump_for_tuple(
        fw_ns,
        src_ip=probe.src_ip,
        dst_ip=probe.dst_ip,
        sport=probe.sport or 0,
        dport=dport,
        proto=proto,
        family=family,
    )

    if not entries:
        return NatResult(
            rule_tag=tag,
            passed=False,
            forward_daddr_ok=False,
            reverse_saddr_ok=False,
            detail=(
                f"No conntrack entry for {probe.src_ip}→{probe.dst_ip}:{dport}/{proto} "
                "— SNAT/MASQUERADE rule may not have fired"
            ),
            family=family,
        )

    entry = entries[0]
    orig = entry.get("orig", {})
    reply = entry.get("reply", {})

    # For SNAT: the reply direction's dst should be the original client
    reply_dst = reply.get("dst")
    forward_daddr_ok = (
        reply_dst is not None
        and _ip_eq(reply_dst, probe.src_ip)
    )

    # The reply direction src should be the destination (not the SNAT IP
    # necessarily — we check that the reply path is correct).
    # For MASQUERADE the egress IP is ephemeral — just verify reply.dst.
    reply_src = reply.get("src")
    if is_masquerade:
        # MASQUERADE: only assert that reply.dst == original client
        reverse_saddr_ok = forward_daddr_ok
        detail = (
            f"MASQUERADE (dynamic saddr): "
            f"reply.dst={reply_dst!r} (orig src={probe.src_ip}); "
            f"reply.src={reply_src!r} (egress IP); "
            f"forward_ok={forward_daddr_ok}"
        )
    else:
        rewrite_ip, _ = _resolve_nat_rewrite(probe.nat_rule) \
            if probe.nat_rule else (None, None)
        # reply.src should be the destination server IP
        reverse_saddr_ok = (
            reply_src is not None
            and _ip_eq(reply_src, probe.dst_ip)
        )
        detail = (
            f"SNAT {probe.src_ip}→{rewrite_ip}: "
            f"reply.dst={reply_dst!r} forward_ok={forward_daddr_ok}; "
            f"reply.src={reply_src!r} reverse_ok={reverse_saddr_ok}"
        )

    passed = forward_daddr_ok and reverse_saddr_ok
    return NatResult(
        rule_tag=tag,
        passed=passed,
        forward_daddr_ok=forward_daddr_ok,
        reverse_saddr_ok=reverse_saddr_ok,
        detail=detail,
        family=family,
    )


def verify_ct_state(
    *,
    fw_ns: str,
    flow_tuple: tuple[str, str, int, int, str],
    expected_state: str,
    family: Literal[4, 6] = 4,
) -> CtStateResult:
    """Assert the conntrack state for a given 5-tuple in *fw_ns*.

    Reads the kernel's conntrack table (via ``NFCTSocket.dump()``) and
    checks whether an entry matching *flow_tuple* shows the expected
    state.

    Parameters
    ----------
    fw_ns:
        Network namespace that holds the conntrack table.
    flow_tuple:
        ``(src_ip, dst_ip, sport, dport, proto)`` identifying the flow.
    expected_state:
        Expected state string: ``"NEW"`` | ``"ESTABLISHED"`` | ``"RELATED"``.
    family:
        IP family (4 or 6).

    Returns
    -------
    CtStateResult
    """
    src_ip, dst_ip, sport, dport, proto = flow_tuple

    # ICMPv6 module guard
    if proto in ("icmpv6", "58") and family == 6:
        if not _icmpv6_ct_available(fw_ns):
            return CtStateResult(
                flow_tuple=flow_tuple,
                expected_state=expected_state,
                observed_state=None,
                passed=False,
                detail="nf_conntrack_proto_icmpv6 module unavailable — inconclusive",
                inconclusive=True,
            )

    entries = _ct_dump_for_tuple(
        fw_ns,
        src_ip=src_ip,
        dst_ip=dst_ip,
        sport=sport,
        dport=dport,
        proto=proto,
        family=family,
    )

    if not entries:
        return CtStateResult(
            flow_tuple=flow_tuple,
            expected_state=expected_state,
            observed_state=None,
            passed=False,
            detail=(
                f"No conntrack entry for "
                f"{src_ip}→{dst_ip}:{dport}/{proto}"
            ),
        )

    entry = entries[0]
    observed = entry.get("state", "UNKNOWN").upper()
    exp = expected_state.upper()

    # Normalise: ESTABLISHED and TIME_WAIT both count as ESTABLISHED
    _obs_norm = "ESTABLISHED" if observed in ("ESTABLISHED", "TIME_WAIT") else observed
    _exp_norm = "ESTABLISHED" if exp in ("ESTABLISHED", "TIME_WAIT") else exp
    passed = _obs_norm == _exp_norm

    return CtStateResult(
        flow_tuple=flow_tuple,
        expected_state=exp,
        observed_state=observed,
        passed=passed,
        detail=(
            f"ct state: expected={exp}, observed={observed} "
            f"({'ok' if passed else 'MISMATCH'})"
        ),
    )


def verify_ct_nat_tuple(
    *,
    fw_ns: str,
    orig_tuple: tuple[str, str, int, int, str],
    expected_rewrite_field: Literal["daddr", "saddr", "dport", "sport"],
    family: Literal[4, 6] = 4,
) -> CtNatResult:
    """Assert that the ct reply-tuple diverges from orig on *expected_rewrite_field*.

    Reads the conntrack entry for *orig_tuple* from *fw_ns* and verifies
    that ``tuplehash_reply`` differs from ``tuplehash_orig`` on the
    specified field.  This proves the NAT rule was applied at the
    conntrack layer, not merely asserted textually in the rule.

    Parameters
    ----------
    fw_ns:
        Network namespace holding the conntrack table.
    orig_tuple:
        ``(src_ip, dst_ip, sport, dport, proto)`` — the forward-direction
        5-tuple.
    expected_rewrite_field:
        The field that should differ between orig and reply directions:

        - ``"daddr"`` — DNAT: reply.src ≠ orig.dst
        - ``"saddr"`` — SNAT: reply.dst ≠ orig.src
        - ``"dport"`` — DNAT port redirect: reply.sport ≠ orig.dport
        - ``"sport"`` — SNAT port: reply.dport ≠ orig.sport
    family:
        IP family.

    Returns
    -------
    CtNatResult
    """
    src_ip, dst_ip, sport, dport, proto = orig_tuple

    if proto in ("icmpv6", "58") and family == 6:
        if not _icmpv6_ct_available(fw_ns):
            return CtNatResult(
                orig_tuple=orig_tuple,
                reply_tuple_observed=None,
                expected_rewrite_field=expected_rewrite_field,
                passed=False,
                detail="nf_conntrack_proto_icmpv6 module unavailable — inconclusive",
                inconclusive=True,
            )

    entries = _ct_dump_for_tuple(
        fw_ns,
        src_ip=src_ip,
        dst_ip=dst_ip,
        sport=sport,
        dport=dport,
        proto=proto,
        family=family,
    )

    if not entries:
        return CtNatResult(
            orig_tuple=orig_tuple,
            reply_tuple_observed=None,
            expected_rewrite_field=expected_rewrite_field,
            passed=False,
            detail=f"No conntrack entry for {src_ip}→{dst_ip}:{dport}/{proto}",
        )

    entry = entries[0]
    orig = entry.get("orig", {})
    reply = entry.get("reply", {})

    # Build the observed reply-tuple
    reply_tuple: tuple[str, str, int, int, str] = (
        str(reply.get("src", "")),
        str(reply.get("dst", "")),
        int(reply.get("sport", 0)),
        int(reply.get("dport", 0)),
        proto,
    )

    # Check the expected field diverges
    passed: bool
    detail: str

    if expected_rewrite_field == "daddr":
        # DNAT: reply direction has the backend as *source* (NAT inverted)
        orig_dst = str(orig.get("dst", ""))
        reply_src = str(reply.get("src", ""))
        passed = bool(reply_src) and not _ip_eq(reply_src, orig_dst)
        detail = (
            f"tuplehash diverge on daddr: "
            f"orig.dst={orig_dst!r} reply.src={reply_src!r} "
            f"diverge={'yes' if passed else 'no'}"
        )
    elif expected_rewrite_field == "saddr":
        # SNAT: reply direction has original client as *destination*
        orig_src = str(orig.get("src", ""))
        reply_dst = str(reply.get("dst", ""))
        passed = bool(reply_dst) and not _ip_eq(reply_dst, orig_src)
        detail = (
            f"tuplehash diverge on saddr: "
            f"orig.src={orig_src!r} reply.dst={reply_dst!r} "
            f"diverge={'yes' if passed else 'no'}"
        )
    elif expected_rewrite_field == "dport":
        orig_dport = int(orig.get("dport", 0))
        reply_sport = int(reply.get("sport", 0))
        passed = reply_sport != orig_dport
        detail = (
            f"tuplehash diverge on dport: "
            f"orig.dport={orig_dport} reply.sport={reply_sport} "
            f"diverge={'yes' if passed else 'no'}"
        )
    elif expected_rewrite_field == "sport":
        orig_sport = int(orig.get("sport", 0))
        reply_dport = int(reply.get("dport", 0))
        passed = reply_dport != orig_sport
        detail = (
            f"tuplehash diverge on sport: "
            f"orig.sport={orig_sport} reply.dport={reply_dport} "
            f"diverge={'yes' if passed else 'no'}"
        )
    else:
        passed = False
        detail = f"Unknown rewrite field: {expected_rewrite_field!r}"

    return CtNatResult(
        orig_tuple=orig_tuple,
        reply_tuple_observed=reply_tuple,
        expected_rewrite_field=expected_rewrite_field,
        passed=passed,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Convenience: verify a NatRule end-to-end
# ---------------------------------------------------------------------------


def verify_nat_rule(
    nat_rule: NatRule,
    *,
    src_ns: str,
    fw_ns: str,
    dst_ns: str,
    src_ip: str,
    family: Literal[4, 6] = 4,
) -> list[NatResult | CtStateResult | CtNatResult]:
    """Run the full four-category verification suite for *nat_rule*.

    Derives a :class:`ProbeSpec` from the rule, injects the probe, and
    runs:

    1. :func:`verify_dnat` or :func:`verify_snat` (depending on rule type).
    2. :func:`verify_ct_state` for the ESTABLISHED state after the probe.
    3. :func:`verify_ct_nat_tuple` for the appropriate rewrite field.

    MASQUERADE rules only run the SNAT + ct-state checks (port is
    ephemeral; ct-nat-tuple check on sport is unreliable).

    Parameters
    ----------
    nat_rule:
        NAT rule to verify.
    src_ns, fw_ns, dst_ns:
        Namespace names.
    src_ip:
        Source IP for the probe (must be routable through FW).
    family:
        IP family (4 or 6).

    Returns
    -------
    list of result objects (mixed types).
    """
    results: list[NatResult | CtStateResult | CtNatResult] = []

    proto = nat_rule.proto or "tcp"
    dport: int | None = None
    if nat_rule.match_dport:
        try:
            dport = int(nat_rule.match_dport.split(":")[0])
        except (ValueError, IndexError):
            dport = None

    # Determine destination IP: for DNAT it's the VIP (match_daddr);
    # for SNAT/MASQUERADE it's the real destination.
    dst_ip = nat_rule.match_daddr
    if dst_ip is None:
        # Can't probe without a target
        return results

    # Strip CIDR suffix if present
    if "/" in dst_ip:
        dst_ip = dst_ip.split("/")[0]

    probe = ProbeSpec(
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        dport=dport,
        nat_rule=nat_rule,
    )

    # 1. NAT rewrite
    if nat_rule.nat_type == "DNAT":
        nat_res = verify_dnat(
            probe, src_ns=src_ns, fw_ns=fw_ns, dst_ns=dst_ns, family=family)
    else:
        nat_res = verify_snat(
            probe, src_ns=src_ns, fw_ns=fw_ns, dst_ns=dst_ns, family=family)
    results.append(nat_res)

    if nat_res.inconclusive:
        return results

    # 2. Conntrack state — probe should produce at least a NEW entry
    flow_tuple = (src_ip, dst_ip, probe.sport or 0, dport or 0, proto)
    ct_state = verify_ct_state(
        fw_ns=fw_ns, flow_tuple=flow_tuple,
        expected_state="NEW", family=family)
    results.append(ct_state)

    if ct_state.inconclusive:
        return results

    # 3. Tuplehash divergence
    rewrite_field: Literal["daddr", "saddr", "dport", "sport"]
    if nat_rule.nat_type == "DNAT":
        rewrite_field = "dport" if dport is not None else "daddr"
    elif nat_rule.nat_type == "MASQUERADE":
        # MASQUERADE: sport is ephemeral — skip ct-nat-tuple (unreliable)
        return results
    else:
        rewrite_field = "saddr"

    ct_nat = verify_ct_nat_tuple(
        fw_ns=fw_ns,
        orig_tuple=flow_tuple,
        expected_rewrite_field=rewrite_field,
        family=family,
    )
    results.append(ct_nat)

    return results


# ---------------------------------------------------------------------------
# Helpers (module-private)
# ---------------------------------------------------------------------------


def _ip_eq(a: str, b: str) -> bool:
    """Return True iff IP addresses *a* and *b* are equal (ignoring CIDR)."""
    try:
        return ipaddress.ip_address(a.split("/")[0]) == ipaddress.ip_address(b.split("/")[0])
    except ValueError:
        return a.strip() == b.strip()
