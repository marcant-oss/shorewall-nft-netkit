"""Shared validator layer for shorewall-nft runtimes.

Provides backend-agnostic validation functions that can be called from both
``verify/simulate.py`` and ``shorewall-nft-simlab``.  All privileged reads
accept ``ns_name`` as a keyword argument so validators can operate in any
named network namespace.

Public surface
--------------
From ``tc_validate``:

- :func:`validate_tc` — TC script generation check.
- :func:`validate_sysctl` — sysctl-vs-config conformance.
- :func:`validate_routing` — basic routing + interface presence.
- :func:`validate_nft_loaded` — nft ruleset loaded check.
- :func:`run_all_validations` — convenience orchestrator.
- :class:`ValidationResult` — result dataclass.

From ``connstate``:

- :func:`run_small_conntrack_probe` — 4-probe conntrack sanity check.
- :func:`run_connstate_tests` — full scapy-based ct state suite.
- :class:`ConnStateResult` — result dataclass.

From ``nat_verify`` (Phase IV):

- :func:`verify_dnat` — assert DNAT rewrite at conntrack layer.
- :func:`verify_snat` — assert SNAT / MASQUERADE rewrite.
- :func:`verify_ct_state` — assert conntrack state (NEW/ESTABLISHED/…).
- :func:`verify_ct_nat_tuple` — assert tuplehash orig vs reply divergence.
- :func:`extract_nat_rules` — extract NAT rules from parsed iptables dump.
- :func:`verify_nat_rule` — convenience: run all four checks for one rule.
- :class:`NatResult` — result dataclass for DNAT/SNAT verifiers.
- :class:`CtStateResult` — result dataclass for ct-state verifier.
- :class:`CtNatResult` — result dataclass for ct-tuple verifier.
- :class:`NatRule` — parsed NAT rule from iptables dump.
- :class:`ProbeSpec` — probe specification for NAT verifiers.
"""

from shorewall_nft_netkit.validators.connstate import (
    ConnStateResult,
    run_connstate_tests,
    run_small_conntrack_probe,
    snapshot_ct_5tuples,
    test_drop_not_syn,
    test_established_tcp,
    test_invalid_flags,
    test_rfc1918_blocked,
    test_syn_to_allowed,
    test_syn_to_blocked,
    test_udp_conntrack,
)
from shorewall_nft_netkit.validators.nat_verify import (
    CtNatResult,
    CtStateResult as NatCtStateResult,
    NatResult,
    NatRule,
    ProbeSpec,
    extract_nat_rules,
    verify_ct_nat_tuple,
    verify_ct_state,
    verify_dnat,
    verify_nat_rule,
    verify_snat,
)
from shorewall_nft_netkit.validators.tc_validate import (
    ValidationResult,
    run_all_validations,
    validate_nft_loaded,
    validate_routing,
    validate_sysctl,
    validate_tc,
)

# Re-export CtStateResult under its canonical name (the nat_verify module
# defines its own CtStateResult — expose it as the primary export; callers
# that need the connstate one import from the sub-module directly).
CtStateResult = NatCtStateResult

__all__ = [
    # tc_validate
    "ValidationResult",
    "validate_tc",
    "validate_sysctl",
    "validate_routing",
    "validate_nft_loaded",
    "run_all_validations",
    # connstate
    "ConnStateResult",
    "run_small_conntrack_probe",
    "run_connstate_tests",
    "snapshot_ct_5tuples",
    "test_established_tcp",
    "test_drop_not_syn",
    "test_invalid_flags",
    "test_syn_to_allowed",
    "test_syn_to_blocked",
    "test_udp_conntrack",
    "test_rfc1918_blocked",
    # nat_verify (Phase IV)
    "NatResult",
    "CtStateResult",
    "CtNatResult",
    "NatRule",
    "ProbeSpec",
    "extract_nat_rules",
    "verify_dnat",
    "verify_snat",
    "verify_ct_state",
    "verify_ct_nat_tuple",
    "verify_nat_rule",
]
