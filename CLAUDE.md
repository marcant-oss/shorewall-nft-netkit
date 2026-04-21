# CLAUDE.md — shorewall-nft-netkit

Low-level netns / TUN-TAP / packet-construction primitives shared by
`shorewall-nft-simlab` and `shorewall-nft-stagelab`.

**Development: use the repo-root venv at `../../.venv/` (Python 3.13).**

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
