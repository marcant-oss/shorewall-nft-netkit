"""Unit tests for shorewall_nft_netkit.validators.connstate.

All tests are pure-logic: no network namespaces, no root, no scapy.
``_ns_shell`` (the subprocess side-effect) is patched to a stub.
``NFCTSocket`` is patched to an in-memory fake that never opens a real
netlink socket.

Verifies:
1. ``ns_name`` is correctly threaded to NFCTSocket calls in
   ``run_small_conntrack_probe``.
2. ``ns_src`` / ``src_ip`` are passed correctly to scapy-based tests.
3. The socket.create_connection injector fires (replacing the old ``nc``
   call) and its exception paths are handled gracefully.
4. Counter / pass / fail semantics are unchanged from the original.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

import shorewall_nft_netkit.validators.connstate as _connstate_mod
from shorewall_nft_netkit.validators.connstate import (
    ConnStateResult,
    run_connstate_tests,
    run_small_conntrack_probe,
)

# Alias test_* functions under private names so pytest doesn't collect them
# as test cases (they are public API functions that happen to be named test_*).
_test_established_tcp = _connstate_mod.test_established_tcp
_test_drop_not_syn = _connstate_mod.test_drop_not_syn
_test_invalid_flags = _connstate_mod.test_invalid_flags
_test_syn_to_allowed = _connstate_mod.test_syn_to_allowed
_test_syn_to_blocked = _connstate_mod.test_syn_to_blocked
_test_udp_conntrack = _connstate_mod.test_udp_conntrack
_test_rfc1918_blocked = _connstate_mod.test_rfc1918_blocked

# Canonical patch targets.
_NS_PATCH = "shorewall_nft_netkit.validators.connstate._ns_shell"
_NFCT_PATCH = "shorewall_nft_netkit.validators.connstate.NFCTSocket"
_SOCKET_PATCH = "shorewall_nft_netkit.validators.connstate.socket"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _make_nfct_mock(entries_per_dump: int = 1) -> MagicMock:
    """Return a mock for ``NFCTSocket`` that behaves as a context manager."""
    ct_instance = MagicMock()
    ct_instance.dump.side_effect = lambda *_a, **_kw: iter([object()] * entries_per_dump)
    ct_instance.flush.return_value = None
    ct_instance.__enter__ = MagicMock(return_value=ct_instance)
    ct_instance.__exit__ = MagicMock(return_value=False)
    return MagicMock(return_value=ct_instance)


def _make_socket_mock() -> MagicMock:
    """Mock the socket module so no real network calls happen."""
    sock = MagicMock()
    sock.create_connection.side_effect = OSError("no route")
    sock_instance = MagicMock()
    sock_instance.__enter__ = MagicMock(return_value=sock_instance)
    sock_instance.__exit__ = MagicMock(return_value=False)
    sock.socket.return_value = sock_instance
    sock.AF_INET = 2
    sock.SOCK_DGRAM = 2
    sock.SOCK_RAW = 3
    sock.IPPROTO_ICMP = 1
    sock.timeout = OSError
    sock.getprotobyname.side_effect = lambda p: {"tcp": 6, "udp": 17, "icmp": 1}[p]
    return sock


# ---------------------------------------------------------------------------
# ConnStateResult dataclass
# ---------------------------------------------------------------------------

class TestConnStateResult:
    def test_fields_accessible(self):
        r = ConnStateResult(name="foo", passed=True, detail="ok", ms=42)
        assert r.name == "foo"
        assert r.passed is True
        assert r.detail == "ok"
        assert r.ms == 42

    def test_default_ms_is_zero(self):
        r = ConnStateResult(name="bar", passed=False, detail="fail")
        assert r.ms == 0

    def test_equality(self):
        a = ConnStateResult(name="x", passed=True, detail="d", ms=1)
        b = ConnStateResult(name="x", passed=True, detail="d", ms=1)
        assert a == b


# ---------------------------------------------------------------------------
# test_established_tcp
# ---------------------------------------------------------------------------

class TestEstablishedTcp:
    def test_happy_path_returncode_zero(self):
        """returncode=0 → passed=True."""
        with patch(_NS_PATCH, return_value=_completed(0)):
            r = _test_established_tcp("10.0.0.1", port=80)
        assert r.passed is True
        assert r.name == "ct_state_established"

    def test_nonzero_returncode_is_failure(self):
        with patch(_NS_PATCH, return_value=_completed(1)):
            r = _test_established_tcp("10.0.0.1", port=443)
        assert r.passed is False

    def test_ns_src_threaded(self):
        """ns_src kwarg must be forwarded to _ns_shell as first argument."""
        captured = []

        def _spy(ns_name, cmd, **kw):
            captured.append(ns_name)
            return _completed(0)

        with patch(_NS_PATCH, side_effect=_spy):
            _test_established_tcp("10.0.0.1", ns_src="my-src-ns")

        assert "my-src-ns" in captured

    def test_ms_field_non_negative(self):
        with patch(_NS_PATCH, return_value=_completed(0)):
            r = _test_established_tcp("10.0.0.1")
        assert r.ms >= 0


# ---------------------------------------------------------------------------
# test_drop_not_syn
# ---------------------------------------------------------------------------

class TestDropNotSyn:
    def test_dropped_passes(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="DROPPED")):
            r = _test_drop_not_syn("10.0.0.1")
        assert r.passed is True
        assert r.name == "dropNotSyn"

    def test_rst_fails(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="RST")):
            r = _test_drop_not_syn("10.0.0.1")
        assert r.passed is False

    def test_exception_caught(self):
        with patch(_NS_PATCH, side_effect=RuntimeError("crash")):
            r = _test_drop_not_syn("10.0.0.1")
        assert r.passed is False
        assert "crash" in r.detail

    def test_ns_src_forwarded(self):
        """Verify ns_src is forwarded to _ns_shell."""
        captured = []

        def _spy(ns, cmd, **kw):
            captured.append(ns)
            return _completed(0, stdout="DROPPED")

        with patch(_NS_PATCH, side_effect=_spy):
            _test_drop_not_syn("10.0.0.1", ns_src="probe-src-ns")

        assert captured == ["probe-src-ns"]


# ---------------------------------------------------------------------------
# test_invalid_flags
# ---------------------------------------------------------------------------

class TestInvalidFlags:
    def test_dropped_passes(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="DROPPED")):
            r = _test_invalid_flags("10.0.0.1")
        assert r.passed is True

    def test_response_fails(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="RESPONSE")):
            r = _test_invalid_flags("10.0.0.1")
        assert r.passed is False


# ---------------------------------------------------------------------------
# test_syn_to_allowed / test_syn_to_blocked
# ---------------------------------------------------------------------------

class TestSynToAllowed:
    def test_syn_ack_passes(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="SYN-ACK")):
            r = _test_syn_to_allowed("10.0.0.1", port=80)
        assert r.passed is True

    def test_dropped_fails(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="DROPPED")):
            r = _test_syn_to_allowed("10.0.0.1")
        assert r.passed is False


class TestSynToBlocked:
    @pytest.mark.parametrize("outcome", ["DROPPED", "RST", "ICMP_REJECT"])
    def test_blocked_outcomes_pass(self, outcome):
        with patch(_NS_PATCH, return_value=_completed(0, stdout=outcome)):
            r = _test_syn_to_blocked("10.0.0.1", port=12345)
        assert r.passed is True

    def test_other_outcome_fails(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="OTHER")):
            r = _test_syn_to_blocked("10.0.0.1")
        assert r.passed is False


# ---------------------------------------------------------------------------
# test_udp_conntrack / test_rfc1918_blocked
# ---------------------------------------------------------------------------

class TestUdpConntrack:
    def test_udp_response_passes(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="UDP_RESPONSE")):
            r = _test_udp_conntrack("10.0.0.1")
        assert r.passed is True

    def test_no_response_fails(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="NO_RESPONSE")):
            r = _test_udp_conntrack("10.0.0.1")
        assert r.passed is False


class TestRfc1918Blocked:
    def test_dropped_passes(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="DROPPED")):
            r = _test_rfc1918_blocked("10.0.0.1")
        assert r.passed is True

    def test_response_fails(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="RESPONSE")):
            r = _test_rfc1918_blocked("10.0.0.1")
        assert r.passed is False


# ---------------------------------------------------------------------------
# run_connstate_tests — orchestrator
# ---------------------------------------------------------------------------

class TestRunConnstateTests:
    def test_returns_seven_results(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="DROPPED")):
            results = run_connstate_tests("10.0.0.1", allowed_port=80)
        assert len(results) == 7

    def test_all_items_are_conn_state_result(self):
        with patch(_NS_PATCH, return_value=_completed(0, stdout="DROPPED")):
            results = run_connstate_tests("10.0.0.1")
        assert all(isinstance(r, ConnStateResult) for r in results)

    def test_ns_src_forwarded_to_all_sub_tests(self):
        """run_connstate_tests must pass ns_src to every sub-call."""
        captured = []

        def _spy(ns, cmd, **kw):
            captured.append(ns)
            return _completed(0, stdout="DROPPED")

        with patch(_NS_PATCH, side_effect=_spy):
            run_connstate_tests("10.0.0.1", ns_src="my-src-ns")

        assert all(c == "my-src-ns" for c in captured), (
            f"Expected all calls to use 'my-src-ns'; got: {set(captured)}"
        )


# ---------------------------------------------------------------------------
# run_small_conntrack_probe — socket injector + ns_name for NFCTSocket
# ---------------------------------------------------------------------------

class TestRunSmallConntrackProbe:
    def test_returns_four_results(self):
        with patch(_SOCKET_PATCH, _make_socket_mock()), \
             patch(_NFCT_PATCH, _make_nfct_mock(1)):
            results = run_small_conntrack_probe("10.0.0.1", port=80)
        assert len(results) == 4

    def test_all_pass_when_counts_positive(self):
        with patch(_SOCKET_PATCH, _make_socket_mock()), \
             patch(_NFCT_PATCH, _make_nfct_mock(1)):
            results = run_small_conntrack_probe()
        assert all(r.passed for r in results)

    def test_fails_when_zero_entries(self):
        with patch(_SOCKET_PATCH, _make_socket_mock()), \
             patch(_NFCT_PATCH, _make_nfct_mock(0)):
            results = run_small_conntrack_probe()
        named = {r.name: r for r in results}
        assert not named["ct:tcp_flow_tracked"].passed
        assert not named["ct:udp_flow_tracked"].passed
        assert not named["ct:icmp_flow_tracked"].passed
        assert not named["ct:table_nonempty"].passed

    def test_result_names(self):
        expected = {
            "ct:tcp_flow_tracked",
            "ct:udp_flow_tracked",
            "ct:icmp_flow_tracked",
            "ct:table_nonempty",
        }
        with patch(_SOCKET_PATCH, _make_socket_mock()), \
             patch(_NFCT_PATCH, _make_nfct_mock(1)):
            results = run_small_conntrack_probe()
        assert {r.name for r in results} == expected

    def test_ns_name_forwarded_to_nfct_socket(self):
        """ns_name must be passed to NFCTSocket(netns=...)."""
        nfct_calls = []

        class _NFCTSpy:
            def __init__(self, *args, **kwargs):
                nfct_calls.append(kwargs.get("netns"))
                self._entries = 1

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def dump(self, *a, **kw):
                return iter([object()] * self._entries)

            def flush(self):
                pass

        with patch(_SOCKET_PATCH, _make_socket_mock()), \
             patch(_NFCT_PATCH, _NFCTSpy):
            run_small_conntrack_probe("10.0.0.1", ns_name="probe-fw-ns")

        assert all(n == "probe-fw-ns" for n in nfct_calls), (
            f"Expected all NFCTSocket calls to use 'probe-fw-ns'; got: {set(nfct_calls)}"
        )

    def test_socket_create_connection_fires_for_tcp(self):
        """socket.create_connection must be called for the TCP probe."""
        sock_mock = _make_socket_mock()
        # Allow create_connection to succeed this time.
        fake_conn = MagicMock()
        fake_conn.sendall.return_value = None
        fake_conn.close.return_value = None
        sock_mock.create_connection.return_value = fake_conn
        sock_mock.create_connection.side_effect = None  # override OSError

        with patch(_SOCKET_PATCH, sock_mock), \
             patch(_NFCT_PATCH, _make_nfct_mock(1)):
            run_small_conntrack_probe("10.0.0.1")

        sock_mock.create_connection.assert_called_once_with(("10.0.0.1", 80), timeout=1)

    def test_socket_error_does_not_propagate(self):
        """OSError from socket calls must be silently consumed."""
        sock_mock = _make_socket_mock()
        sock_mock.create_connection.side_effect = OSError("connection refused")
        sock_mock.socket.side_effect = OSError("raw socket not permitted")

        with patch(_SOCKET_PATCH, sock_mock), \
             patch(_NFCT_PATCH, _make_nfct_mock(0)):
            results = run_small_conntrack_probe()

        # Function must complete and return 4 results.
        assert len(results) == 4

    def test_exception_in_count_treated_as_zero(self):
        """If NFCTSocket raises, _ct_count returns 0 and results fail."""
        ct_instance = MagicMock()
        ct_instance.dump.side_effect = OSError("netns gone")
        ct_instance.flush.return_value = None
        ct_instance.__enter__ = MagicMock(return_value=ct_instance)
        ct_instance.__exit__ = MagicMock(return_value=False)
        nfct_cls = MagicMock(return_value=ct_instance)

        with patch(_SOCKET_PATCH, _make_socket_mock()), \
             patch(_NFCT_PATCH, nfct_cls):
            results = run_small_conntrack_probe()

        named = {r.name: r for r in results}
        assert not named["ct:tcp_flow_tracked"].passed

    @pytest.mark.parametrize("ns_name", [
        "shorewall-next-sim-fw",
        "simlab-fw",
        "stagelab-netns-fw",
    ])
    def test_ns_name_parameter_accepted(self, ns_name):
        """run_small_conntrack_probe must accept any ns_name."""
        with patch(_SOCKET_PATCH, _make_socket_mock()), \
             patch(_NFCT_PATCH, _make_nfct_mock(1)):
            results = run_small_conntrack_probe(ns_name=ns_name)
        assert len(results) == 4
