# CLAUDE.md — shorewall-nft-netkit

Low-level netns / TUN-TAP / packet-construction primitives shared by
`shorewall-nft-simlab` and `shorewall-nft-stagelab`.

**Development: use the repo-root venv at `../../.venv/` (Python 3.13).**

## Shared validator layer (`validators/`)

The `validators/` sub-package was added in Phase II of the dual-stack plan
to give both `verify/simulate.py` and `shorewall-nft-simlab` a single,
runtime-neutral validator implementation.  Every function accepts `ns_name`
as a keyword argument so it works in any named network namespace.

### Why here?

The original validators lived in `shorewall_nft.verify.tc_validate` and
`shorewall_nft.verify.connstate` and hard-coded `NS_FW = "shorewall-next-sim-fw"`.
Moving them to netkit:

1. Makes them available to simlab without a circular import (netkit does
   not depend on shorewall-nft's config/compiler machinery — callers
   pass pre-parsed data).
2. Lets the `ns_name` default preserve simulate.py back-compat while
   allowing simlab to use its own namespace name.
3. Centralises the pyroute2 `NFCTSocket` usage in one place.

The original modules (`shorewall_nft.verify.tc_validate` and
`shorewall_nft.verify.connstate`) are now thin re-export shims; existing
callers are unaffected.

### API

```python
from shorewall_nft_netkit.validators import (
    # tc_validate
    ValidationResult,
    validate_tc,         # TC script generation check (pure; ns_name reserved)
    validate_sysctl,     # sysctl-vs-config conformance  (ns_name: fw namespace)
    validate_routing,    # IP forwarding + interface presence
    validate_nft_loaded, # nft table + base chains loaded
    run_all_validations, # orchestrator

    # connstate
    ConnStateResult,
    run_small_conntrack_probe,  # 4-probe ct sanity (socket injector, no NS_SRC)
    run_connstate_tests,        # full scapy ct test suite
    test_established_tcp, test_drop_not_syn, test_invalid_flags,
    test_syn_to_allowed, test_syn_to_blocked,
    test_udp_conntrack, test_rfc1918_blocked,
)
```

### `ns_name` default

`"shorewall-next-sim-fw"` — matches simulate.py's `NS_FW` constant.
Pass any other name when running inside a different topology.

### Injector change in `run_small_conntrack_probe`

The old implementation called `ns(NS_SRC, "nc ...")` to generate TCP/UDP
flows.  The new implementation uses `socket.create_connection()` /
`socket.socket()` in the **calling process's netns**.  This means:

- No dependency on a separate NS_SRC namespace.
- The caller is responsible for entering the correct netns before calling
  the probe (simulate.py does this naturally since it already runs inside
  NS_FW at probe time).
- `PermissionError` / `OSError` from raw sockets is caught and silently
  ignored — the ct-count assertion still fires.

## Shared primitives

- `nsstub.py` — `spawn_nsstub(name)` / `stop_nsstub(name, pid)`: fork a
  tiny stub process that creates a named netns via `unshare(CLONE_NEWNET)` +
  bind-mount and keeps it alive until the caller closes the keep-alive pipe.
  Cleans up `/run/netns/<name>` on exit even if the parent dies by SIGKILL
  (uses SIGTERM PR_SET_PDEATHSIG + cleanup handler).

- `tundev.py` — `create_tuntap` / `close_tuntap`: create/destroy TUN/TAP
  devices in the current netns.

- `packets.py` — `build_tcp`, `build_udp`, `fast_probe_id`,
  `PacketSummary`: scapy-based packet construction helpers used by simlab
  probe generators.

- `netns_fork.py` — three primitives for running code inside a named netns
  without leaking or rebinding cached netlink sockets. Replace all
  `subprocess.run(["ip", "netns", "exec", …])` call sites with these.
  Full architecture: `docs/architecture/netns-fork.md`.

  - **`run_in_netns_fork(netns, fn, *args, timeout=30.0, **kwargs)`** —
    one-shot: fork, `setns()`, run `fn(*args, **kwargs)`, return result via
    pickle IPC. Payloads < 4 MiB travel inline; larger payloads are routed
    through a sealed `memfd_create(2)` region (zero-copy, no `/tmp` touch).
    `fn` must be pickleable (module-scope function, not a lambda). Typical
    use: single nft apply, one-off netlink query.

  - **`PersistentNetnsWorker(netns, child_main)`** — long-lived worker:
    the child loops on `ctx.recv()` / `ctx.send()` calls until the parent
    closes the socket or calls `worker.stop()`. Uses `SOCK_STREAM` (no
    per-message size cap). Typical use: shorewalld hot-path dispatch,
    repeated nft operations in the same netns.

  - **`run_nft_in_netns_zc(netns, script, *, check_only=False, timeout=60.0)`** —
    specialised helper for nft script execution. Ships the script via sealed
    memfd; streams stdout/stderr via drain threads; returns
    `NftResult(rc, stdout, stderr)`. Scales to multi-hundred-MB scripts
    (bulk ip-list loads). Raises `NftError` on non-zero rc unless
    `check_only=True`. Typical use: `shorewall-nft apply-tc` / rule load.

  - **`MEMFD_SUPPORTED`** (module-level bool) — `True` when
    `os.memfd_create` is available (Linux ≥ 3.17, Python ≥ 3.8). Check
    this before using `run_nft_in_netns_zc` on legacy kernels.

## Key invariants

- `PR_SET_PDEATHSIG` is always `SIGTERM` (not `SIGKILL`) — SIGKILL skips
  cleanup handlers and leaves orphaned bind-mounts in `/run/netns/`.
- All child processes set `SIGTERM`/`SIGINT`/`SIGHUP` to `SIG_DFL` at start
  to avoid inheriting parent signal handlers that could interfere.
- `os.pipe2(O_CLOEXEC)` is used wherever available to prevent FD leaks into
  unrelated children.

## Tests

```bash
# Non-root tests only (fast):
pytest packages/shorewall-nft-netkit/tests -q

# Root tests (require root, create real named netns):
sudo .venv/bin/pytest packages/shorewall-nft-netkit/tests -q
```

Root-required tests are marked `@pytest.mark.skipif(os.geteuid() != 0, ...)`.
