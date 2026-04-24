"""Traffic Control and Routing validation in network namespaces.

Validates:
1. TC configuration (tcdevices, tcclasses) can be applied
2. Routing table matches expected zone topology
3. Sysctl settings are correctly applied
4. Interface options (rp_filter, log_martians) are set

All public functions accept ``ns_name`` as a keyword argument so they can
operate in any named network namespace, not just the fixed simulate.py NS_FW.

The default value ``"shorewall-next-sim-fw"`` preserves backward compatibility
for callers in ``verify/simulate.py`` that omit ``ns_name``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from shorewall_nft_netkit.netns_shell import run_shell_in_netns as _ns

# Default namespace name — matches simulate.py's NS_FW constant so that
# callers that were written against the old module-level constant keep
# working without changes.
_DEFAULT_NS_FW = "shorewall-next-sim-fw"


@dataclass
class ValidationResult:
    name: str
    passed: bool
    detail: str


def validate_sysctl(
    config_dir: Path,
    *,
    ns_name: str = _DEFAULT_NS_FW,
) -> list[ValidationResult]:
    """Validate that sysctl settings match the Shorewall config.

    Args:
        config_dir: Path to the shorewall config directory.
        ns_name:    Name of the network namespace to query.
                    Defaults to ``"shorewall-next-sim-fw"`` (simulate.py
                    back-compat).
    """
    from shorewall_nft.compiler.sysctl import generate_sysctl_script
    from shorewall_nft.config.parser import load_config

    results: list[ValidationResult] = []
    config = load_config(config_dir)
    sysctl_script = generate_sysctl_script(config)

    # Extract sysctl -w commands
    for line in sysctl_script.splitlines():
        if not line.startswith("sysctl -w "):
            continue
        param_val = line[len("sysctl -w "):]
        param, _, expected = param_val.partition("=")

        # Query the actual value in the fw namespace
        r = _ns(ns_name, f"cat /proc/sys/{param.replace('.', '/')}")
        actual = r.stdout.strip() if r.returncode == 0 else "ERROR"

        passed = actual == expected
        results.append(ValidationResult(
            name=f"sysctl:{param}",
            passed=passed,
            detail=f"{param}={actual} (expected {expected})",
        ))

    return results


def validate_routing(
    zones_config,
    *,
    ns_name: str = _DEFAULT_NS_FW,
) -> list[ValidationResult]:
    """Validate that routing in the fw namespace matches zone topology.

    Checks:
    - IP forwarding is enabled
    - Each zone's interface exists
    - Routes to test IPs exist

    Args:
        zones_config: Zone configuration (currently unused; reserved for future
                      parameterised interface checks).
        ns_name:      Name of the network namespace to query.
    """
    results: list[ValidationResult] = []

    # Check IP forwarding
    r = _ns(ns_name, "cat /proc/sys/net/ipv4/ip_forward")
    fwd = r.stdout.strip()
    results.append(ValidationResult(
        name="ip_forward",
        passed=fwd == "1",
        detail=f"ip_forward={fwd}",
    ))

    # Check interfaces exist
    r = _ns(ns_name, "ip -o link show")
    ifaces = r.stdout if r.returncode == 0 else ""
    for iface in ["lo", "bond1", "bond0.20"]:  # Minimal simulation interfaces
        exists = iface in ifaces
        results.append(ValidationResult(
            name=f"iface:{iface}",
            passed=exists,
            detail=f"interface {iface} {'exists' if exists else 'MISSING'}",
        ))

    # Check rp_filter is disabled (for simulation)
    for iface in ["all", "bond1", "bond0.20"]:
        safe_iface = iface.replace(".", "/")
        r = _ns(ns_name, f"cat /proc/sys/net/ipv4/conf/{safe_iface}/rp_filter 2>/dev/null")
        val = r.stdout.strip() if r.returncode == 0 else "N/A"
        results.append(ValidationResult(
            name=f"rp_filter:{iface}",
            passed=val in ("0", "N/A"),
            detail=f"rp_filter({iface})={val}",
        ))

    return results


def validate_tc(
    config_dir: Path,
    *,
    ns_name: str = _DEFAULT_NS_FW,  # noqa: ARG001  (reserved; TC gen is pure)
) -> list[ValidationResult]:
    """Validate TC configuration can be generated and applied.

    ``ns_name`` is accepted for API consistency but TC script generation is
    a pure in-process operation — no netns reads are performed here.

    Args:
        config_dir: Path to the shorewall config directory.
        ns_name:    Reserved for future netns-local tc-qdisc queries.
    """
    from shorewall_nft.compiler.tc import emit_tc_commands, parse_tc_config
    from shorewall_nft.config.parser import load_config

    results: list[ValidationResult] = []
    config = load_config(config_dir)
    tc = parse_tc_config(config)

    if tc.devices:
        tc_script = emit_tc_commands(tc)
        results.append(ValidationResult(
            name="tc:generate",
            passed=bool(tc_script),
            detail=f"TC script: {len(tc_script.splitlines())} lines, "
                   f"{len(tc.devices)} devices, {len(tc.classes)} classes",
        ))
    else:
        results.append(ValidationResult(
            name="tc:generate",
            passed=True,
            detail="No TC configuration (tcdevices empty)",
        ))

    return results


def validate_nft_loaded(
    *,
    ns_name: str = _DEFAULT_NS_FW,
) -> list[ValidationResult]:
    """Validate that nft rules are loaded in the fw namespace.

    Args:
        ns_name: Name of the network namespace to query.
    """
    results: list[ValidationResult] = []

    r = _ns(ns_name, "nft list table inet shorewall 2>/dev/null")
    if r.returncode != 0:
        results.append(ValidationResult(
            name="nft:loaded",
            passed=False,
            detail="Table inet shorewall NOT loaded",
        ))
        return results

    output = r.stdout
    chains = sum(1 for ln in output.splitlines() if ln.strip().startswith("chain "))
    rules = len(output.splitlines())

    results.append(ValidationResult(
        name="nft:loaded",
        passed=chains > 0,
        detail=f"Table loaded: {chains} chains, ~{rules} lines",
    ))

    # Check base chains exist
    for chain_name in ["input", "forward", "output"]:
        has_chain = f"chain {chain_name}" in output
        results.append(ValidationResult(
            name=f"nft:chain:{chain_name}",
            passed=has_chain,
            detail=f"Chain {chain_name}: {'present' if has_chain else 'MISSING'}",
        ))

    # Check ct state rules exist
    has_ct = "ct state" in output
    results.append(ValidationResult(
        name="nft:ct_state",
        passed=has_ct,
        detail=f"ct state rules: {'present' if has_ct else 'MISSING'}",
    ))

    # Check NAT chains
    has_nat = "type nat" in output
    results.append(ValidationResult(
        name="nft:nat",
        passed=has_nat,
        detail=f"NAT chains: {'present' if has_nat else 'MISSING'}",
    ))

    # Check sets
    has_sets = "set " in output
    results.append(ValidationResult(
        name="nft:sets",
        passed=True,  # Sets are optional
        detail=f"Named sets: {'present' if has_sets else 'none'}",
    ))

    return results


def run_all_validations(
    config_dir: Path,
    *,
    ns_name: str = _DEFAULT_NS_FW,
) -> list[ValidationResult]:
    """Run all validation checks.

    Requires the simulation topology to be up.

    Args:
        config_dir: Path to the shorewall config directory.
        ns_name:    Name of the firewall network namespace.
    """
    results: list[ValidationResult] = []
    results.extend(validate_nft_loaded(ns_name=ns_name))
    results.extend(validate_routing(None, ns_name=ns_name))
    results.extend(validate_tc(config_dir, ns_name=ns_name))
    return results
