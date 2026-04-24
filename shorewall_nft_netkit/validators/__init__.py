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
"""

from shorewall_nft_netkit.validators.connstate import (
    ConnStateResult,
    run_connstate_tests,
    run_small_conntrack_probe,
    test_drop_not_syn,
    test_established_tcp,
    test_invalid_flags,
    test_rfc1918_blocked,
    test_syn_to_allowed,
    test_syn_to_blocked,
    test_udp_conntrack,
)
from shorewall_nft_netkit.validators.tc_validate import (
    ValidationResult,
    run_all_validations,
    validate_nft_loaded,
    validate_routing,
    validate_sysctl,
    validate_tc,
)

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
    "test_established_tcp",
    "test_drop_not_syn",
    "test_invalid_flags",
    "test_syn_to_allowed",
    "test_syn_to_blocked",
    "test_udp_conntrack",
    "test_rfc1918_blocked",
]
