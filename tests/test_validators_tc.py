"""Unit tests for shorewall_nft_netkit.validators.tc_validate.

All tests are pure-logic: no network namespaces, no root, no real tc binary.
Functions that touch netns (validate_sysctl, validate_routing,
validate_nft_loaded) are covered by patching ``_ns`` where needed.

These tests verify:
1. ``ns_name`` is correctly threaded to every ``_ns()`` call.
2. All public functions accept ``ns_name`` as a keyword argument.
3. Results maintain the same semantics as the original implementation.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shorewall_nft_netkit.validators.tc_validate import (
    ValidationResult,
    run_all_validations,
    validate_nft_loaded,
    validate_routing,
    validate_sysctl,
    validate_tc,
)

# Some tests below exercise the lazy imports inside ``validate_sysctl``
# and ``validate_tc`` (which pull in ``shorewall_nft.compiler.sysctl`` /
# ``shorewall_nft.config.parser`` / ``shorewall_nft.compiler.tc``).
# Skip those classes when the shorewall-nft core package isn't
# installed — the netkit CI runs without it.
_HAS_SHOREWALL_NFT = importlib.util.find_spec("shorewall_nft") is not None
_requires_shorewall_nft = pytest.mark.skipif(
    not _HAS_SHOREWALL_NFT,
    reason="shorewall-nft core not installed (netkit CI); skipping "
           "integration tests that exercise the lazy shorewall_nft "
           "imports inside validate_sysctl / validate_tc.",
)

# Canonical patch target for _ns inside the validators module.
_NS_PATCH = "shorewall_nft_netkit.validators.tc_validate._ns"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _make_stub_config(
    *,
    tcdevices=None,
    tcclasses=None,
    tcfilters=None,
):
    """Build a minimal ShorewalConfig-like object with only TC fields.

    Uses a local duck-typed ConfigLine rather than
    ``shorewall_nft.config.parser.ConfigLine`` so this test can run
    without the shorewall-nft core package installed (the lazy
    imports inside ``validate_tc`` / ``validate_sysctl`` are mocked
    out by the tests that use them).
    """
    class _StubConfigLine:
        def __init__(self, columns, file="test", lineno=1):
            self.columns = columns
            self.file = file
            self.lineno = lineno

    cfg = MagicMock()
    cfg.tcdevices = [_StubConfigLine(cols) for cols in (tcdevices or [])]
    cfg.tcclasses = [_StubConfigLine(cols) for cols in (tcclasses or [])]
    cfg.tcfilters = [_StubConfigLine(cols) for cols in (tcfilters or [])]
    return cfg


# ---------------------------------------------------------------------------
# ValidationResult dataclass
# ---------------------------------------------------------------------------

class TestValidationResult:
    def test_fields_accessible(self):
        r = ValidationResult(name="tc:generate", passed=True, detail="ok")
        assert r.name == "tc:generate"
        assert r.passed is True
        assert r.detail == "ok"

    def test_failed_variant(self):
        r = ValidationResult(name="sysctl:foo", passed=False, detail="mismatch")
        assert not r.passed

    def test_equality(self):
        a = ValidationResult(name="x", passed=True, detail="d")
        b = ValidationResult(name="x", passed=True, detail="d")
        assert a == b


# ---------------------------------------------------------------------------
# validate_routing — ns_name threading
# ---------------------------------------------------------------------------

class TestValidateRoutingNsName:
    """Verify that every _ns() call inside validate_routing receives the
    correct ns_name argument."""

    def _capture_ns_calls(self, ns_value, monkeypatch):
        """Return a list that accumulates the first positional arg of each _ns call."""
        calls = []

        def _ns_spy(ns_name, cmd, **kw):
            calls.append(ns_name)
            # Return something realistic so the function doesn't crash.
            if "ip_forward" in cmd:
                return _completed(0, stdout="1")
            if "ip -o link show" in cmd:
                return _completed(0, stdout="lo bond1 bond0.20")
            return _completed(0, stdout="0")

        monkeypatch.setattr(
            "shorewall_nft_netkit.validators.tc_validate._ns", _ns_spy
        )
        validate_routing(None, ns_name=ns_value)
        return calls

    def test_default_ns_name_used(self, monkeypatch):
        calls = self._capture_ns_calls("shorewall-next-sim-fw", monkeypatch)
        assert all(c == "shorewall-next-sim-fw" for c in calls), (
            f"Expected all calls to use default ns; got: {set(calls)}"
        )

    def test_custom_ns_name_threaded(self, monkeypatch):
        custom_ns = "my-custom-netns"
        calls = self._capture_ns_calls(custom_ns, monkeypatch)
        assert all(c == custom_ns for c in calls), (
            f"Expected all calls to use {custom_ns!r}; got: {set(calls)}"
        )

    def test_ip_forward_enabled_passes(self):
        def _ns_stub(ns_name, cmd, **kw):
            if "ip_forward" in cmd:
                return _completed(0, stdout="1")
            if "ip -o link show" in cmd:
                return _completed(0, stdout="lo bond1 bond0.20")
            return _completed(0, stdout="0")

        with patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_routing(None)

        named = {r.name: r for r in results}
        assert named["ip_forward"].passed is True

    def test_ip_forward_disabled_fails(self):
        def _ns_stub(ns_name, cmd, **kw):
            if "ip_forward" in cmd:
                return _completed(0, stdout="0")
            if "ip -o link show" in cmd:
                return _completed(0, stdout="lo bond1 bond0.20")
            return _completed(0, stdout="0")

        with patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_routing(None, ns_name="test-ns")

        named = {r.name: r for r in results}
        assert named["ip_forward"].passed is False

    def test_missing_interface_fails(self):
        def _ns_stub(ns_name, cmd, **kw):
            if "ip_forward" in cmd:
                return _completed(0, stdout="1")
            if "ip -o link show" in cmd:
                return _completed(0, stdout="lo bond0.20")  # bond1 absent
            return _completed(0, stdout="0")

        with patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_routing(None)

        named = {r.name: r for r in results}
        assert named["iface:bond1"].passed is False
        assert named["iface:lo"].passed is True

    @pytest.mark.parametrize("ns_name", [
        "shorewall-next-sim-fw",
        "my-simlab-fw",
        "netns-test-42",
    ])
    def test_ns_name_parameter_accepted(self, ns_name):
        """validate_routing must accept any ns_name without raising."""
        def _ns_stub(ns, cmd, **kw):
            if "ip_forward" in cmd:
                return _completed(0, stdout="1")
            if "ip -o link show" in cmd:
                return _completed(0, stdout="lo bond1 bond0.20")
            return _completed(0, stdout="0")

        with patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_routing(None, ns_name=ns_name)

        assert isinstance(results, list)
        assert all(isinstance(r, ValidationResult) for r in results)


# ---------------------------------------------------------------------------
# validate_sysctl — ns_name threading
# ---------------------------------------------------------------------------

@_requires_shorewall_nft
class TestValidateSysctlNsName:
    def test_ns_name_threaded_to_each_sysctl_read(self, monkeypatch):
        calls = []

        def _ns_spy(ns_name, cmd, **kw):
            calls.append(ns_name)
            return _completed(0, stdout="1")

        monkeypatch.setattr("shorewall_nft_netkit.validators.tc_validate._ns", _ns_spy)

        stub_cfg = MagicMock()
        sysctl_script = "sysctl -w net.ipv4.ip_forward=1\n"

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.sysctl.generate_sysctl_script", return_value=sysctl_script):
            validate_sysctl(Path("/fake"), ns_name="sysctl-ns-test")

        assert calls == ["sysctl-ns-test"]

    def test_matching_value_passes(self):
        stub_cfg = MagicMock()
        sysctl_script = "sysctl -w net.ipv4.ip_forward=1\n"

        def _ns_stub(ns_name, cmd, **kw):
            return _completed(0, stdout="1")

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.sysctl.generate_sysctl_script", return_value=sysctl_script), \
             patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_sysctl(Path("/fake/config"))

        assert len(results) == 1
        assert results[0].passed is True

    def test_mismatched_value_fails(self):
        stub_cfg = MagicMock()
        sysctl_script = "sysctl -w net.ipv4.ip_forward=1\n"

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.sysctl.generate_sysctl_script", return_value=sysctl_script), \
             patch(_NS_PATCH, return_value=_completed(0, stdout="0")):
            results = validate_sysctl(Path("/fake/config"), ns_name="custom-ns")

        assert results[0].passed is False


# ---------------------------------------------------------------------------
# validate_tc — ns_name accepted (pure generation, no netns reads)
# ---------------------------------------------------------------------------

@_requires_shorewall_nft
class TestValidateTcNsName:
    def test_empty_tc_config_passes(self):
        from shorewall_nft.compiler.tc import TcConfig

        stub_cfg = _make_stub_config()
        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.tc.parse_tc_config", return_value=TcConfig()):
            results = validate_tc(Path("/fake/config"), ns_name="any-ns")

        assert len(results) == 1
        assert results[0].passed is True

    def test_ns_name_parameter_accepted_silently(self):
        """validate_tc does not call _ns — ns_name is accepted but not used."""
        from shorewall_nft.compiler.tc import TcConfig

        stub_cfg = _make_stub_config()
        ns_calls = []

        def _spy(ns, cmd, **kw):
            ns_calls.append(ns)
            return _completed(0)

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.tc.parse_tc_config", return_value=TcConfig()), \
             patch(_NS_PATCH, side_effect=_spy):
            validate_tc(Path("/fake/config"), ns_name="test-ns")

        # validate_tc is pure; _ns should NOT have been called.
        assert ns_calls == []


# ---------------------------------------------------------------------------
# validate_nft_loaded — ns_name threading
# ---------------------------------------------------------------------------

class TestValidateNftLoadedNsName:
    def test_ns_name_threaded(self, monkeypatch):
        ns_calls = []

        def _ns_spy(ns_name, cmd, **kw):
            ns_calls.append(ns_name)
            return _completed(1, stdout="")  # table not loaded

        monkeypatch.setattr("shorewall_nft_netkit.validators.tc_validate._ns", _ns_spy)
        validate_nft_loaded(ns_name="my-fw-ns")

        assert ns_calls == ["my-fw-ns"]

    def test_no_table_fails_immediately(self):
        with patch(_NS_PATCH, return_value=_completed(1, stdout="")):
            results = validate_nft_loaded()

        assert len(results) == 1
        assert results[0].name == "nft:loaded"
        assert results[0].passed is False

    def test_table_with_chains_passes(self):
        nft_output = (
            "table inet shorewall {\n"
            "  chain input { type filter hook input priority 0; policy drop;\n"
            "  }\n"
            "  chain forward { type filter hook forward priority 0; policy drop;\n"
            "  }\n"
            "  chain output { type filter hook output priority 0; policy drop;\n"
            "    ct state established,related accept\n"
            "  }\n"
            "  type nat hook prerouting priority -100;\n"
            "}\n"
        )
        with patch(_NS_PATCH, return_value=_completed(0, stdout=nft_output)):
            results = validate_nft_loaded(ns_name="custom-fw-ns")

        named = {r.name: r for r in results}
        assert named["nft:loaded"].passed is True
        assert named["nft:chain:input"].passed is True
        assert named["nft:chain:forward"].passed is True
        assert named["nft:chain:output"].passed is True
        assert named["nft:ct_state"].passed is True

    @pytest.mark.parametrize("ns_name", [
        "shorewall-next-sim-fw",
        "simlab-fw",
        "stagelab-fw-netns",
    ])
    def test_ns_name_parameter_accepted(self, ns_name):
        with patch(_NS_PATCH, return_value=_completed(1, stdout="")):
            results = validate_nft_loaded(ns_name=ns_name)
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# run_all_validations — orchestrator wires ns_name through
# ---------------------------------------------------------------------------

@_requires_shorewall_nft
class TestRunAllValidations:
    def test_ns_name_propagated_to_all_sub_validators(self, monkeypatch):
        """run_all_validations must thread ns_name to all three sub-validators."""
        target_ns = "orchestrator-test-ns"
        ns_calls = []

        def _ns_spy(ns_name, cmd, **kw):
            ns_calls.append(ns_name)
            # Minimal responses to avoid KeyError / attribute errors.
            if "ip_forward" in cmd:
                return _completed(0, stdout="1")
            if "ip -o link show" in cmd:
                return _completed(0, stdout="lo bond1 bond0.20")
            # nft list table — fail fast so we don't traverse all chain checks.
            return _completed(1, stdout="")

        monkeypatch.setattr("shorewall_nft_netkit.validators.tc_validate._ns", _ns_spy)

        stub_cfg = _make_stub_config()
        from shorewall_nft.compiler.tc import TcConfig

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.tc.parse_tc_config", return_value=TcConfig()):
            run_all_validations(Path("/fake"), ns_name=target_ns)

        # Every _ns call must use the propagated ns_name.
        assert all(c == target_ns for c in ns_calls), (
            f"Expected {target_ns!r} in every call; got: {set(ns_calls)}"
        )
