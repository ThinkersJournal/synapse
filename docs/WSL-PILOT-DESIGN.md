# WSL2 pilot: Synapse across the Windows/Linux boundary (design note, spike)

Task: PM `WSL-LANE-PILOT.md` item 3. Status: design only, no code. Probed 2026-10-23 read-only in `lane-spike`.

## Measured (distro `lane-spike`, WSL 2.7.8, no `.wslconfig`, i.e. NAT)
- Guest route: default via 172.25.224.1 (the host). From the guest, `127.0.0.1:7920` refuses; `172.25.224.1:7920` times out.
  The Windows daemon is loopback-only (`127.0.0.1:7920`, pid 46792), so under NAT it is unreachable. That is the wanted default.
- `curl`, `python3`, `bwrap` are present; `socat` is not.

## Constraints
1. Daemon stays loopback-only; one Windows daemon, one store. 2. No shared loopback between lanes. 3. Per-role key check unchanged.
4. Do not edit `/etc/wsl.conf` (PM owns it).

## Options for the link
- **A. `networkingMode=mirrored`** (global `.wslconfig`, needs `wsl --shutdown`, hits every distro incl. docker-desktop).
  Guest `127.0.0.1` is then the host's loopback, so every unsandboxed WSL process reaches every Windows loopback service
  (claude-peers 7899, Serena 9962, the daemon). Isolation then rests wholly on `bwrap --unshare-net` plus a Unix-socket proxy.
  Quickest to try; widest blast radius; global side effects.
- **B. NAT + Hyper-V socket relay (recommended).** No network listener at all. A small Windows relay (per lane, own service GUID)
  accepts on AF_HYPERV and forwards to `127.0.0.1:7920`. In the guest, a proxy OUTSIDE the sandbox (own Linux user) connects
  with AF_VSOCK to the host and serves a per-lane Unix socket that is bind-mounted into the bwrap. Cost: one-time admin registry
  entry per GUID (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\<guid>`), a new
  ~100-line Windows relay + ~50-line guest proxy (Rust, in this repo, or python for the spike).
- **C. NAT + Windows forwarder on the vEthernet(WSL) address.** A second, non-loopback listener. Rejected: breaks the stop condition.

## Inside the sandbox (all options)
`bwrap --unshare-net`, with a tiny in-sandbox relay: `127.0.0.1:7920` (sandbox-private) <-> bind-mounted Unix socket.
The unchanged client keeps using `SYNAPSE_ADDR=127.0.0.1:7920`; no other lane shares that loopback.

## One real client change needed
`read_announce` -> `daemon_alive(pid)` on Unix is `kill(pid, 0)`. The announce file names a WINDOWS pid, so on Linux every
announce is "stale" and `connect_existing` says "no daemon answered". Needed: a way to mark a remote daemon (e.g. env
`SYNAPSE_REMOTE_DAEMON=1`, or announce `pid` 0 means "not local"), skipping only the pid check; the HMAC health proof still decides.
Same family as #236 (the proof, not a process property, should decide). The lane needs a copy of `synapsed.json`
(addr, instance_id: not a secret, but owner-only) rewritten to the sandbox address.

## Spike plan after PM picks A or B
1. Linux build of `synapse` + `synapse-claude-channel` (in `lane-spike`, rustup as the lane user).
2. `synapse id init` in the lane home -> role `lane-commysdk` key; PM/CireSnave registers the account/agent cert per the identity roadmap.
3. Link per the chosen option; transcript: `lane-commysdk` <-> `pm@ciresnave` and one Windows lane, send + fetch both ways.
