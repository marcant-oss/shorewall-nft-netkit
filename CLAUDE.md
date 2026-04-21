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

- `netns_fork.py` — `run_in_netns_fork` / `PersistentNetnsWorker`:
  fork+setns+pickle-IPC primitive for running callables inside a named netns
  without leaking or rebinding cached netlink sockets. Use this instead of
  `subprocess.run(["ip", "netns", "exec", …])` for in-process operations.
  Architecture doc: `docs/architecture/netns-fork.md`.

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
