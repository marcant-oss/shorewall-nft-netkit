"""Unit tests for shorewall_nft_netkit.validators.nat_verify.

All tests are pure-logic: no network namespaces, no root, no real sockets.
``NFCTSocket`` and socket injection functions are mocked throughout.

Coverage:
    - :class:`NatResult`, :class:`CtStateResult`, :class:`CtNatResult`
      dataclasses.
    - :class:`NatRule` + :func:`extract_nat_rules` from a mocked parsed dump.
    - :class:`ProbeSpec` rule_tag property.
    - :func:`verify_dnat` — happy path, no-entry, missing rewrite_ip.
    - :func:`verify_snat` / MASQUERADE — happy path, no-entry.
    - :func:`verify_ct_state` — state match, mismatch, missing entry.
    - :func:`verify_ct_nat_tuple` — all four rewrite-field variants.
    - Edge: ``nf_conntrack_proto_icmpv6`` absent → ``inconclusive=True``,
      not a hard fail.
    - Edge: MASQUERADE with ephemeral sport → match on proto+daddr only.
    - Dual-stack: every relevant test is parametrised over ``family=4``
      and ``family=6``.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from shorewall_nft_netkit.validators.nat_verify import (
    CtNatResult,
    CtStateResult,
    NatResult,
    NatRule,
    ProbeSpec,
    _ct_dump_for_tuple,
    _ip_eq,
    _resolve_nat_rewrite,
    _status_to_state,
    extract_nat_rules,
    verify_ct_nat_tuple,
    verify_ct_state,
    verify_dnat,
    verify_snat,
)

# ---------------------------------------------------------------------------
# Patch targets
# ---------------------------------------------------------------------------

_NFCT_PATCH = "shorewall_nft_netkit.validators.nat_verify.NFCTSocket"
_NFCTATTR_PATCH = "shorewall_nft_netkit.validators.nat_verify.NFCTAttrTuple"
_ICMPV6_PATCH = "shorewall_nft_netkit.validators.nat_verify._icmpv6_ct_available"
_CT_DUMP_PATCH = "shorewall_nft_netkit.validators.nat_verify._ct_dump_for_tuple"
_CT_FLUSH_PATCH = "shorewall_nft_netkit.validators.nat_verify._ct_flush"
_INJECT_TCP_PATCH = "shorewall_nft_netkit.validators.nat_verify._inject_tcp"
_INJECT_UDP_PATCH = "shorewall_nft_netkit.validators.nat_verify._inject_udp"
_INJECT_ICMP_PATCH = "shorewall_nft_netkit.validators.nat_verify._inject_icmp"
_SLEEP_PATCH = "shorewall_nft_netkit.validators.nat_verify.time.sleep"


# ---------------------------------------------------------------------------
# Minimal fake parsed iptables dump
# ---------------------------------------------------------------------------

@dataclass
class _FakeRule:
    target: str
    chain: str
    raw: str = ""
    proto: str | None = None
    saddr: str | None = None
    daddr: str | None = None
    dport: str | None = None
    sport: str | None = None
    iif: str | None = None
    target_args: dict = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.target_args is None:
            self.target_args = {}


@dataclass
class _FakeTable:
    name: str
    chains: dict = None  # type: ignore[assignment]
    rules: dict = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.chains is None:
            self.chains = {}
        if self.rules is None:
            self.rules = {}


def _make_dnat_table() -> dict:
    """Return a minimal parsed dump with one DNAT + one SNAT + one MASQUERADE."""
    nat_table = _FakeTable(name="nat")
    nat_table.rules["PREROUTING"] = [
        _FakeRule(
            target="DNAT",
            chain="PREROUTING",
            proto="tcp",
            daddr="203.0.113.10",
            dport="80",
            raw="-A PREROUTING -d 203.0.113.10/32 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.5:8080",
            target_args={"to-destination": "10.0.0.5:8080"},
        )
    ]
    nat_table.rules["POSTROUTING"] = [
        _FakeRule(
            target="SNAT",
            chain="POSTROUTING",
            proto="tcp",
            saddr="10.0.0.0/24",
            raw="-A POSTROUTING -s 10.0.0.0/24 -p tcp -j SNAT --to-source 198.51.100.5",
            target_args={"to-source": "198.51.100.5"},
        ),
        _FakeRule(
            target="MASQUERADE",
            chain="POSTROUTING",
            proto="tcp",
            saddr="192.168.1.0/24",
            raw="-A POSTROUTING -s 192.168.1.0/24 -p tcp -j MASQUERADE",
            target_args={},
        ),
    ]
    filter_table = _FakeTable(name="filter")
    filter_table.rules["FORWARD"] = [
        _FakeRule(target="ACCEPT", chain="FORWARD", raw="-A FORWARD -j ACCEPT"),
    ]
    return {"nat": nat_table, "filter": filter_table}


def _make_nfct_mock_entries(entries: list[dict]) -> MagicMock:
    """Return a mock NFCTSocket class that yields *entries* from dump()."""
    ct_instance = MagicMock()
    ct_instance.flush.return_value = None

    def _dump(*args, **kwargs):
        # Yield fake message objects parsed by _parse_ct_msg
        # We mock _ct_dump_for_tuple directly in most tests, but provide
        # a real NFCTSocket mock for lower-level tests.
        return iter(entries)

    ct_instance.dump.side_effect = _dump
    ct_instance.__enter__ = MagicMock(return_value=ct_instance)
    ct_instance.__exit__ = MagicMock(return_value=False)
    return MagicMock(return_value=ct_instance)


def _make_ct_entry(
    *,
    src: str = "10.0.0.2",
    dst: str = "203.0.113.10",
    sport: int = 54321,
    dport: int = 80,
    proto: int = 6,
    reply_src: str = "10.0.0.5",
    reply_dst: str = "10.0.0.2",
    reply_sport: int = 8080,
    reply_dport: int = 54321,
    state: str = "NEW",
) -> dict:
    """Return a parsed ct entry dict in the format _parse_ct_msg returns."""
    return {
        "orig": {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto},
        "reply": {"src": reply_src, "dst": reply_dst, "sport": reply_sport, "dport": reply_dport, "proto": proto},
        "state": state,
    }


# ---------------------------------------------------------------------------
# Helper to suppress side effects in all verifiers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _noop_injectors():
    """Context manager that patches all injectors + sleep + ct_flush to no-ops."""
    with (
        patch(_INJECT_TCP_PATCH),
        patch(_INJECT_UDP_PATCH),
        patch(_INJECT_ICMP_PATCH),
        patch(_CT_FLUSH_PATCH),
        patch(_SLEEP_PATCH),
    ):
        yield


# ---------------------------------------------------------------------------
# NatResult dataclass
# ---------------------------------------------------------------------------

class TestNatResult:
    def test_frozen_and_accessible(self):
        r = NatResult(
            rule_tag="DNAT:10.0.0.5:80",
            passed=True,
            forward_daddr_ok=True,
            reverse_saddr_ok=True,
            detail="ok",
        )
        assert r.rule_tag == "DNAT:10.0.0.5:80"
        assert r.passed is True
        assert r.forward_daddr_ok is True
        assert r.reverse_saddr_ok is True
        assert r.inconclusive is False
        assert r.family == 4

    def test_inconclusive_default_false(self):
        r = NatResult(rule_tag="x", passed=False,
                      forward_daddr_ok=False, reverse_saddr_ok=False, detail="")
        assert r.inconclusive is False

    def test_explicit_inconclusive(self):
        r = NatResult(rule_tag="x", passed=False,
                      forward_daddr_ok=False, reverse_saddr_ok=False,
                      detail="module missing", inconclusive=True, family=6)
        assert r.inconclusive is True
        assert r.family == 6

    def test_immutable(self):
        r = NatResult(rule_tag="x", passed=True,
                      forward_daddr_ok=True, reverse_saddr_ok=True, detail="")
        with pytest.raises((AttributeError, TypeError)):
            r.passed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CtStateResult dataclass
# ---------------------------------------------------------------------------

class TestCtStateResult:
    def test_fields(self):
        ft = ("1.2.3.4", "5.6.7.8", 1024, 80, "tcp")
        r = CtStateResult(
            flow_tuple=ft,
            expected_state="NEW",
            observed_state="NEW",
            passed=True,
            detail="ok",
        )
        assert r.flow_tuple == ft
        assert r.passed is True
        assert r.inconclusive is False

    def test_none_observed_state(self):
        r = CtStateResult(
            flow_tuple=("a", "b", 0, 0, "tcp"),
            expected_state="ESTABLISHED",
            observed_state=None,
            passed=False,
            detail="not found",
        )
        assert r.observed_state is None


# ---------------------------------------------------------------------------
# CtNatResult dataclass
# ---------------------------------------------------------------------------

class TestCtNatResult:
    def test_fields(self):
        orig = ("10.0.0.1", "1.2.3.4", 1024, 80, "tcp")
        reply = ("1.2.3.4", "10.0.0.1", 80, 1024, "tcp")
        r = CtNatResult(
            orig_tuple=orig,
            reply_tuple_observed=reply,
            expected_rewrite_field="daddr",
            passed=True,
            detail="ok",
        )
        assert r.orig_tuple == orig
        assert r.reply_tuple_observed == reply
        assert r.passed is True

    def test_none_reply_tuple(self):
        r = CtNatResult(
            orig_tuple=("a", "b", 0, 0, "tcp"),
            reply_tuple_observed=None,
            expected_rewrite_field="daddr",
            passed=False,
            detail="no entry",
        )
        assert r.reply_tuple_observed is None


# ---------------------------------------------------------------------------
# NatRule + extract_nat_rules
# ---------------------------------------------------------------------------

class TestNatRule:
    def test_fields(self):
        nr = NatRule(nat_type="DNAT", chain="PREROUTING", proto="tcp",
                     match_daddr="203.0.113.10", match_dport="80",
                     to_dest="10.0.0.5:8080")
        assert nr.nat_type == "DNAT"
        assert nr.to_dest == "10.0.0.5:8080"


class TestExtractNatRules:
    def test_extracts_dnat_snat_masquerade(self):
        tables = _make_dnat_table()
        rules = extract_nat_rules(tables)
        types = {r.nat_type for r in rules}
        assert "DNAT" in types
        assert "SNAT" in types
        assert "MASQUERADE" in types

    def test_skips_non_nat_targets(self):
        tables = _make_dnat_table()
        rules = extract_nat_rules(tables)
        for r in rules:
            assert r.nat_type in ("DNAT", "SNAT", "MASQUERADE")

    def test_empty_when_no_nat_table(self):
        assert extract_nat_rules({}) == []
        assert extract_nat_rules({"filter": _FakeTable("filter")}) == []

    def test_dnat_rule_fields(self):
        tables = _make_dnat_table()
        rules = extract_nat_rules(tables)
        dnat = next(r for r in rules if r.nat_type == "DNAT")
        assert dnat.proto == "tcp"
        assert dnat.match_daddr == "203.0.113.10"
        assert dnat.match_dport == "80"
        assert dnat.to_dest == "10.0.0.5:8080"

    def test_snat_rule_fields(self):
        tables = _make_dnat_table()
        rules = extract_nat_rules(tables)
        snat = next(r for r in rules if r.nat_type == "SNAT")
        assert snat.to_source == "198.51.100.5"


# ---------------------------------------------------------------------------
# ProbeSpec
# ---------------------------------------------------------------------------

class TestProbeSpec:
    def test_rule_tag_with_dnat(self):
        nr = NatRule(nat_type="DNAT", chain="PREROUTING",
                     to_dest="10.0.0.5:8080")
        p = ProbeSpec(src_ip="10.0.0.2", dst_ip="203.0.113.10",
                      proto="tcp", dport=80, nat_rule=nr)
        tag = p.rule_tag
        assert "DNAT" in tag
        assert "203.0.113.10" in tag

    def test_rule_tag_without_nat_rule(self):
        p = ProbeSpec(src_ip="10.0.0.2", dst_ip="1.2.3.4",
                      proto="udp", dport=53)
        assert "probe:" in p.rule_tag


# ---------------------------------------------------------------------------
# _resolve_nat_rewrite
# ---------------------------------------------------------------------------

class TestResolveNatRewrite:
    def test_dnat_ip_only(self):
        nr = NatRule(nat_type="DNAT", chain="PRE", to_dest="10.0.0.5")
        ip, port = _resolve_nat_rewrite(nr)
        assert ip == "10.0.0.5"
        assert port is None

    def test_dnat_ip_port(self):
        nr = NatRule(nat_type="DNAT", chain="PRE", to_dest="10.0.0.5:8080")
        ip, port = _resolve_nat_rewrite(nr)
        assert ip == "10.0.0.5"
        assert port == 8080

    def test_dnat_ipv6_no_port(self):
        nr = NatRule(nat_type="DNAT", chain="PRE", to_dest="2001:db8::5")
        ip, port = _resolve_nat_rewrite(nr)
        assert ip == "2001:db8::5"
        assert port is None

    def test_dnat_ipv6_with_port(self):
        nr = NatRule(nat_type="DNAT", chain="PRE", to_dest="[2001:db8::5]:8080")
        ip, port = _resolve_nat_rewrite(nr)
        assert ip == "2001:db8::5"
        assert port == 8080

    def test_snat(self):
        nr = NatRule(nat_type="SNAT", chain="POST", to_source="198.51.100.5")
        ip, port = _resolve_nat_rewrite(nr)
        assert ip == "198.51.100.5"

    def test_masquerade_returns_none(self):
        nr = NatRule(nat_type="MASQUERADE", chain="POST")
        ip, port = _resolve_nat_rewrite(nr)
        assert ip is None
        assert port is None


# ---------------------------------------------------------------------------
# _status_to_state
# ---------------------------------------------------------------------------

class TestStatusToState:
    def test_seen_reply_bit_set(self):
        # IPS_SEEN_REPLY = 0x8 + IPS_CONFIRMED = 0x4 → ESTABLISHED
        assert _status_to_state(0x8 | 0x4) == "ESTABLISHED"

    def test_zero_is_new(self):
        assert _status_to_state(0) == "NEW"

    def test_string_passthrough(self):
        assert _status_to_state("ESTABLISHED") == "ESTABLISHED"
        assert _status_to_state("new") == "NEW"

    def test_invalid_type(self):
        state = _status_to_state(None)
        assert state == "UNKNOWN"


# ---------------------------------------------------------------------------
# _ip_eq
# ---------------------------------------------------------------------------

class TestIpEq:
    def test_equal_ipv4(self):
        assert _ip_eq("10.0.0.1", "10.0.0.1") is True

    def test_not_equal_ipv4(self):
        assert _ip_eq("10.0.0.1", "10.0.0.2") is False

    def test_cidr_stripped(self):
        assert _ip_eq("10.0.0.1/32", "10.0.0.1") is True

    def test_ipv6_equal(self):
        assert _ip_eq("2001:db8::1", "2001:db8::1") is True

    def test_ipv6_canonical_form(self):
        # pyexpanded vs compressed form — both resolve to same
        assert _ip_eq("::1", "0:0:0:0:0:0:0:1") is True

    def test_ipv6_not_equal(self):
        assert _ip_eq("2001:db8::1", "2001:db8::2") is False


# ---------------------------------------------------------------------------
# verify_dnat
# ---------------------------------------------------------------------------

class TestVerifyDnat:
    """Tests for verify_dnat — mocks _ct_dump_for_tuple directly."""

    def _make_probe(self) -> ProbeSpec:
        nr = NatRule(nat_type="DNAT", chain="PREROUTING",
                     proto="tcp", match_daddr="203.0.113.10", match_dport="80",
                     to_dest="10.0.0.5:8080")
        return ProbeSpec(src_ip="10.0.0.2", dst_ip="203.0.113.10",
                         proto="tcp", dport=80, nat_rule=nr)

    @pytest.mark.parametrize("family", [4, 6])
    def test_happy_path_dnat(self, family):
        """DNAT probe with correct ct entry → passed=True."""
        entry = _make_ct_entry(
            src="10.0.0.2" if family == 4 else "fd00::2",
            dst="203.0.113.10" if family == 4 else "2001:db8:100::1",
            reply_src="10.0.0.5" if family == 4 else "fd00::5",
            reply_dst="10.0.0.2" if family == 4 else "fd00::2",
        )
        probe = ProbeSpec(
            src_ip="10.0.0.2" if family == 4 else "fd00::2",
            dst_ip="203.0.113.10" if family == 4 else "2001:db8:100::1",
            proto="tcp",
            dport=80,
            nat_rule=NatRule(
                nat_type="DNAT",
                chain="PREROUTING",
                to_dest=("10.0.0.5:8080" if family == 4 else "[fd00::5]:8080"),
            ),
        )
        with patch(_CT_DUMP_PATCH, return_value=[entry]), _noop_injectors():
            result = verify_dnat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=family)
        assert result.passed is True
        assert result.forward_daddr_ok is True
        assert result.reverse_saddr_ok is True
        assert result.family == family

    @pytest.mark.parametrize("family", [4, 6])
    def test_no_ct_entry_fails(self, family):
        """No conntrack entry → passed=False, both flags False."""
        probe = self._make_probe()
        with patch(_CT_DUMP_PATCH, return_value=[]), _noop_injectors():
            result = verify_dnat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=family)
        assert result.passed is False
        assert result.forward_daddr_ok is False
        assert result.reverse_saddr_ok is False
        assert result.inconclusive is False

    @pytest.mark.parametrize("family", [4, 6])
    def test_wrong_reply_src_forward_daddr_fail(self, family):
        """reply.src doesn't match to_dest → forward_daddr_ok=False."""
        entry = _make_ct_entry(
            reply_src="192.0.2.99",  # wrong backend IP
            reply_dst="10.0.0.2",
        )
        probe = self._make_probe()
        with patch(_CT_DUMP_PATCH, return_value=[entry]), _noop_injectors():
            result = verify_dnat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=family)
        assert result.forward_daddr_ok is False
        assert result.passed is False

    @pytest.mark.parametrize("family", [4, 6])
    def test_icmpv6_module_absent_inconclusive(self, family):
        """When nf_conntrack_proto_icmpv6 is absent, v6 ICMP → inconclusive."""
        nr = NatRule(nat_type="DNAT", chain="PREROUTING",
                     to_dest="fd00::5")
        probe = ProbeSpec(src_ip="fd00::2", dst_ip="2001:db8::1",
                          proto="icmpv6", nat_rule=nr)
        with patch(_ICMPV6_PATCH, return_value=False):
            result = verify_dnat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=6)
        assert result.inconclusive is True
        assert result.passed is False

    def test_icmpv6_inconclusive_only_for_v6(self):
        """ICMPv6 module check is v6-only; v4 ICMP never triggers it."""
        nr = NatRule(nat_type="DNAT", chain="PRE", to_dest="10.0.0.5")
        probe = ProbeSpec(src_ip="10.0.0.2", dst_ip="203.0.113.10",
                          proto="icmp", nat_rule=nr)
        # _icmpv6_ct_available should never be called for family=4
        with (
            patch(_CT_DUMP_PATCH, return_value=[]),
            patch(_ICMPV6_PATCH, return_value=False) as mock_check,
            _noop_injectors(),
        ):
            result = verify_dnat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=4)
        mock_check.assert_not_called()
        assert result.inconclusive is False


# ---------------------------------------------------------------------------
# verify_snat
# ---------------------------------------------------------------------------

class TestVerifySnat:
    @pytest.mark.parametrize("family", [4, 6])
    def test_happy_path_snat(self, family):
        """SNAT probe with correct ct entry → passed=True."""
        entry = _make_ct_entry(
            src="10.0.0.2",
            dst="8.8.8.8",
            reply_src="8.8.8.8",
            reply_dst="10.0.0.2",   # original client in reply.dst
        )
        nr = NatRule(nat_type="SNAT", chain="POSTROUTING",
                     proto="tcp", to_source="198.51.100.5")
        probe = ProbeSpec(src_ip="10.0.0.2", dst_ip="8.8.8.8",
                          proto="tcp", dport=443, nat_rule=nr)
        with patch(_CT_DUMP_PATCH, return_value=[entry]), _noop_injectors():
            result = verify_snat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=family)
        assert result.passed is True
        assert result.forward_daddr_ok is True
        assert result.family == family

    @pytest.mark.parametrize("family", [4, 6])
    def test_masquerade_ephemeral_sport(self, family):
        """MASQUERADE: only reply.dst must match — sport is ephemeral."""
        entry = _make_ct_entry(
            src="192.168.1.2",
            dst="8.8.8.8",
            reply_src="8.8.8.8",
            reply_dst="192.168.1.2",   # original source in reply.dst
            reply_sport=54321,          # ephemeral — we don't assert specific value
        )
        nr = NatRule(nat_type="MASQUERADE", chain="POSTROUTING", proto="tcp")
        probe = ProbeSpec(src_ip="192.168.1.2", dst_ip="8.8.8.8",
                          proto="tcp", dport=80, nat_rule=nr)
        with patch(_CT_DUMP_PATCH, return_value=[entry]), _noop_injectors():
            result = verify_snat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=family)
        # MASQUERADE only checks reply.dst == original src
        assert result.forward_daddr_ok is True
        assert result.passed is True
        # Detail mentions MASQUERADE
        assert "MASQUERADE" in result.detail

    @pytest.mark.parametrize("family", [4, 6])
    def test_no_ct_entry_fails(self, family):
        nr = NatRule(nat_type="SNAT", chain="POSTROUTING",
                     to_source="198.51.100.5")
        probe = ProbeSpec(src_ip="10.0.0.2", dst_ip="8.8.8.8",
                          proto="tcp", dport=80, nat_rule=nr)
        with patch(_CT_DUMP_PATCH, return_value=[]), _noop_injectors():
            result = verify_snat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=family)
        assert result.passed is False

    @pytest.mark.parametrize("family", [4, 6])
    def test_icmpv6_module_absent_inconclusive(self, family):
        nr = NatRule(nat_type="MASQUERADE", chain="POSTROUTING")
        probe = ProbeSpec(src_ip="fd00::1", dst_ip="2001:db8::1",
                          proto="icmpv6", nat_rule=nr)
        with patch(_ICMPV6_PATCH, return_value=False):
            result = verify_snat(
                probe, src_ns="ns-src", fw_ns="ns-fw", dst_ns="ns-dst",
                family=6)
        assert result.inconclusive is True


# ---------------------------------------------------------------------------
# verify_ct_state
# ---------------------------------------------------------------------------

class TestVerifyCtState:
    @pytest.mark.parametrize("family", [4, 6])
    def test_state_match(self, family):
        """Observed state matches expected → passed=True."""
        flow = ("10.0.0.2", "203.0.113.10", 54321, 80, "tcp")
        entry = _make_ct_entry(state="NEW")
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_state(fw_ns="ns-fw", flow_tuple=flow,
                                expected_state="NEW", family=family)
        assert r.passed is True
        assert r.observed_state == "NEW"

    @pytest.mark.parametrize("family", [4, 6])
    def test_state_mismatch(self, family):
        """Observed state differs from expected → passed=False."""
        flow = ("10.0.0.2", "203.0.113.10", 54321, 80, "tcp")
        entry = _make_ct_entry(state="ESTABLISHED")
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_state(fw_ns="ns-fw", flow_tuple=flow,
                                expected_state="NEW", family=family)
        assert r.passed is False
        assert r.expected_state == "NEW"

    @pytest.mark.parametrize("family", [4, 6])
    def test_no_entry_fails(self, family):
        """Missing entry → passed=False, observed_state=None."""
        flow = ("10.0.0.2", "203.0.113.10", 0, 80, "tcp")
        with patch(_CT_DUMP_PATCH, return_value=[]):
            r = verify_ct_state(fw_ns="ns-fw", flow_tuple=flow,
                                expected_state="ESTABLISHED", family=family)
        assert r.passed is False
        assert r.observed_state is None

    @pytest.mark.parametrize("family", [4, 6])
    def test_established_and_time_wait_normalised(self, family):
        """TIME_WAIT should count as ESTABLISHED."""
        flow = ("10.0.0.2", "1.2.3.4", 1024, 80, "tcp")
        entry = _make_ct_entry(state="TIME_WAIT")
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_state(fw_ns="ns-fw", flow_tuple=flow,
                                expected_state="ESTABLISHED", family=family)
        assert r.passed is True

    def test_icmpv6_module_absent_inconclusive(self):
        """ICMPv6 module absent → inconclusive for v6 ICMP."""
        flow = ("fd00::1", "2001:db8::1", 0, 0, "icmpv6")
        with patch(_ICMPV6_PATCH, return_value=False):
            r = verify_ct_state(fw_ns="ns-fw", flow_tuple=flow,
                                expected_state="NEW", family=6)
        assert r.inconclusive is True
        assert r.passed is False

    def test_icmpv6_module_absent_v4_not_inconclusive(self):
        """v4 ICMP probes never trigger the icmpv6 module check."""
        flow = ("10.0.0.1", "10.0.0.2", 0, 0, "icmp")
        entry = _make_ct_entry(state="NEW")
        with (
            patch(_CT_DUMP_PATCH, return_value=[entry]),
            patch(_ICMPV6_PATCH, return_value=False) as mock_check,
        ):
            r = verify_ct_state(fw_ns="ns-fw", flow_tuple=flow,
                                expected_state="NEW", family=4)
        mock_check.assert_not_called()
        assert r.inconclusive is False


# ---------------------------------------------------------------------------
# verify_ct_nat_tuple
# ---------------------------------------------------------------------------

class TestVerifyCtNatTuple:
    @pytest.mark.parametrize("family", [4, 6])
    def test_daddr_diverges(self, family):
        """DNAT: reply.src ≠ orig.dst → passed=True."""
        orig = ("10.0.0.2", "203.0.113.10", 54321, 80, "tcp")
        entry = _make_ct_entry(
            src="10.0.0.2",
            dst="203.0.113.10",
            reply_src="10.0.0.5",   # backend, ≠ orig dst
            reply_dst="10.0.0.2",
        )
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="daddr", family=family)
        assert r.passed is True
        assert "yes" in r.detail

    @pytest.mark.parametrize("family", [4, 6])
    def test_daddr_no_diverge_fails(self, family):
        """DNAT: reply.src == orig.dst → passed=False (no rewrite)."""
        orig = ("10.0.0.2", "203.0.113.10", 54321, 80, "tcp")
        entry = _make_ct_entry(
            src="10.0.0.2",
            dst="203.0.113.10",
            reply_src="203.0.113.10",  # SAME as orig.dst → no DNAT
            reply_dst="10.0.0.2",
        )
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="daddr", family=family)
        assert r.passed is False
        assert "no" in r.detail

    @pytest.mark.parametrize("family", [4, 6])
    def test_saddr_diverges(self, family):
        """SNAT: reply.dst ≠ orig.src → passed=True."""
        orig = ("10.0.0.2", "8.8.8.8", 54321, 443, "tcp")
        entry = _make_ct_entry(
            src="10.0.0.2",
            dst="8.8.8.8",
            reply_src="8.8.8.8",
            reply_dst="198.51.100.5",  # SNAT IP, ≠ orig src
        )
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="saddr", family=family)
        assert r.passed is True

    @pytest.mark.parametrize("family", [4, 6])
    def test_dport_diverges(self, family):
        """DNAT port: reply.sport ≠ orig.dport → passed=True."""
        orig = ("10.0.0.2", "203.0.113.10", 54321, 80, "tcp")
        entry = _make_ct_entry(
            dport=80,
            reply_sport=8080,  # rewritten backend port, ≠ orig dport
        )
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="dport", family=family)
        assert r.passed is True

    @pytest.mark.parametrize("family", [4, 6])
    def test_sport_diverges(self, family):
        """SNAT port: reply.dport ≠ orig.sport → passed=True."""
        orig = ("10.0.0.2", "8.8.8.8", 54321, 443, "tcp")
        entry = _make_ct_entry(
            sport=54321,
            reply_dport=60000,  # different from orig sport
        )
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="sport", family=family)
        assert r.passed is True

    @pytest.mark.parametrize("family", [4, 6])
    def test_no_entry_fails(self, family):
        """Missing ct entry → passed=False, reply_tuple_observed=None."""
        orig = ("10.0.0.2", "203.0.113.10", 54321, 80, "tcp")
        with patch(_CT_DUMP_PATCH, return_value=[]):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="daddr", family=family)
        assert r.passed is False
        assert r.reply_tuple_observed is None

    def test_icmpv6_module_absent_inconclusive(self):
        """ICMPv6 module absent → inconclusive for v6 ICMP."""
        orig = ("fd00::1", "2001:db8::1", 0, 0, "icmpv6")
        with patch(_ICMPV6_PATCH, return_value=False):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="daddr", family=6)
        assert r.inconclusive is True

    def test_unknown_rewrite_field(self):
        """Unknown rewrite_field → passed=False, no exception."""
        orig = ("10.0.0.2", "1.2.3.4", 1024, 80, "tcp")
        entry = _make_ct_entry()
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="unknown_field",  # type: ignore[arg-type]
                family=4)
        assert r.passed is False

    def test_reply_tuple_populated_on_success(self):
        """reply_tuple_observed should be a 5-tuple on success."""
        orig = ("10.0.0.2", "203.0.113.10", 54321, 80, "tcp")
        entry = _make_ct_entry(
            reply_src="10.0.0.5",
            reply_dst="10.0.0.2",
            reply_sport=8080,
            reply_dport=54321,
        )
        with patch(_CT_DUMP_PATCH, return_value=[entry]):
            r = verify_ct_nat_tuple(
                fw_ns="ns-fw", orig_tuple=orig,
                expected_rewrite_field="daddr", family=4)
        assert r.reply_tuple_observed is not None
        assert len(r.reply_tuple_observed) == 5


# ---------------------------------------------------------------------------
# Integration: NFCTSocket mock (lower-level; validates _ct_dump_for_tuple)
# ---------------------------------------------------------------------------

class TestCtDumpForTuple:
    """Validate _ct_dump_for_tuple with a real NFCTSocket mock."""

    def test_empty_when_no_entries(self):
        ct_instance = MagicMock()
        ct_instance.dump.return_value = iter([])
        ct_instance.flush.return_value = None
        ct_instance.__enter__ = MagicMock(return_value=ct_instance)
        ct_instance.__exit__ = MagicMock(return_value=False)
        nfct_cls = MagicMock(return_value=ct_instance)

        with patch(_NFCT_PATCH, nfct_cls), patch(_NFCTATTR_PATCH):
            entries = _ct_dump_for_tuple(
                "ns-fw", "10.0.0.2", "203.0.113.10", 54321, 80, "tcp")
        assert entries == []

    def test_exception_returns_empty(self):
        """Any exception from NFCTSocket → empty list, never raises."""
        nfct_cls = MagicMock(side_effect=OSError("netns gone"))

        with patch(_NFCT_PATCH, nfct_cls), patch(_NFCTATTR_PATCH):
            entries = _ct_dump_for_tuple(
                "ns-fw", "10.0.0.2", "203.0.113.10", 0, 80, "tcp")
        assert entries == []


# ---------------------------------------------------------------------------
# Injection side-effect: verify injector selection by protocol
# ---------------------------------------------------------------------------

class TestInjectorSelection:
    """verify_dnat / verify_snat must use the right injector per proto."""

    @pytest.mark.parametrize("family", [4, 6])
    def test_tcp_probe_calls_inject_tcp(self, family):
        nr = NatRule(nat_type="DNAT", chain="PREROUTING",
                     to_dest="10.0.0.5:8080")
        probe = ProbeSpec(src_ip="10.0.0.2", dst_ip="203.0.113.10",
                          proto="tcp", dport=80, nat_rule=nr)
        with (
            patch(_CT_DUMP_PATCH, return_value=[]),
            patch(_CT_FLUSH_PATCH),
            patch(_SLEEP_PATCH),
            patch(_INJECT_TCP_PATCH) as mock_tcp,
            patch(_INJECT_UDP_PATCH) as mock_udp,
            patch(_INJECT_ICMP_PATCH) as mock_icmp,
        ):
            verify_dnat(probe, src_ns="s", fw_ns="fw", dst_ns="d", family=family)
        mock_tcp.assert_called_once()
        mock_udp.assert_not_called()
        mock_icmp.assert_not_called()

    @pytest.mark.parametrize("family", [4, 6])
    def test_udp_probe_calls_inject_udp(self, family):
        nr = NatRule(nat_type="SNAT", chain="POSTROUTING",
                     to_source="198.51.100.5")
        probe = ProbeSpec(src_ip="10.0.0.2", dst_ip="8.8.8.8",
                          proto="udp", dport=53, nat_rule=nr)
        with (
            patch(_CT_DUMP_PATCH, return_value=[]),
            patch(_CT_FLUSH_PATCH),
            patch(_SLEEP_PATCH),
            patch(_INJECT_TCP_PATCH) as mock_tcp,
            patch(_INJECT_UDP_PATCH) as mock_udp,
            patch(_INJECT_ICMP_PATCH) as mock_icmp,
        ):
            verify_snat(probe, src_ns="s", fw_ns="fw", dst_ns="d", family=family)
        mock_udp.assert_called_once()
        mock_tcp.assert_not_called()
        mock_icmp.assert_not_called()


# ---------------------------------------------------------------------------
# Backward-compat: skip silently when no NAT rules (no error returned)
# ---------------------------------------------------------------------------

class TestBackwardCompat:
    def test_extract_nat_rules_no_nat_table(self):
        """No 'nat' table in dump → empty list, no exception."""
        rules = extract_nat_rules({})
        assert rules == []

    def test_extract_nat_rules_empty_nat_table(self):
        table = _FakeTable(name="nat")
        rules = extract_nat_rules({"nat": table})
        assert rules == []
