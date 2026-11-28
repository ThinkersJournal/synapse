<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Swapping the installed adapter to rc.271 (H1 redeliver), exact steps

Written 2026-11-28 against `origin/main@0b7b333c` (tag `v6.0.0-rc.271`) for pm-platform (PM ask tp4668-jd4-7i).
Each claim is marked READ (seen in code or on this machine today) or NOT RUN (a step nobody has executed).
**Nothing here was run; no swap was performed.** Precedent: `2026-10-30-restart-the-live-daemon.md` section 3 (rename of a running exe, rehearsed on a scratch home).

## 1. Which executables change (READ)

- `git show --stat 0b7b333c` (#388): code changes are only `crates/synapse-mcp-server/src/push.rs` (+ its test). Every other file is a version stamp / docs.
- `synapse-mcp-server` is linked into **`synapse-claude-channel.exe`** only among the installed binaries. `synapse.exe` and `synapsed.exe` have no behaviour change in rc.271 (version string only).
- Installed in `C:/Users/cires/.cargo/bin` (READ via `--version`, mtime): `synapse-claude-channel.exe` rc.269 (2026-11-25 19:58), `synapse.exe` rc.247 (2026-11-13), `synapsed.exe` rc.247 (2026-11-13). The running daemon is pid 50276 (`tasklist`, 2026-11-28), task `\synapsed-cires` Status Running.
- **Swap only `synapse-claude-channel.exe`. Do not touch `synapsed.exe` or `synapse.exe`.**

## 2. Method (rename of a running exe: READ as precedent, NOT RUN for this swap)

1. Stage (from a `main` checkout at `v6.0.0-rc.271`, in a worktree or a clean checkout, never over the live bin):
   `cargo install --path crates/synapse-claude-channel --locked --root C:/Projects/_stage-rc271`
2. Check the staged binary: `C:/Projects/_stage-rc271/bin/synapse-claude-channel.exe --version` must print `6.0.0-rc.271`.
3. Swap (Windows allows renaming a running exe; 31 adapters are running now):
   `cd C:/Users/cires/.cargo/bin`
   `ren synapse-claude-channel.exe synapse-claude-channel.exe.rc269.bak`
   `copy C:\Projects\_stage-rc271\bin\synapse-claude-channel.exe synapse-claude-channel.exe`
4. Verify: `synapse-claude-channel.exe --version` prints rc.271; `.rc269.bak` still present.

## 3. Who restarts, and when (READ from code)

- **Running adapters keep their loaded image.** A process started from the old file stays old until it exits. The 31 adapters run old code until each lane's session restarts. A lane that restarts afterwards launches the new exe automatically. No process is restarted by the swap itself.
- **No `synapsed` restart is needed for H1.** The redeliver is adapter-side: the adapter's poll loop checks for `redeliver-<role>.request` in the lane's Synapse home each tick (`push.rs`, `take_redeliver_request`) and rewrites its own unacked pushes. It uses no new daemon endpoint. A daemon restart would only drop in-memory counters and make each lane re-attach once, so it is not part of this swap.
- **What a lane sees:** nothing at swap time. After its own restart it behaves as before until a host creates the request file. H1 does nothing until the launcher creates `redeliver-<role>.request` after the dev-channels dialog answer (pm-platform / agentlife own that; not built here). Until then rc.271 is inert and safe.
- The request is consumed once (the file is deleted when read); an acked message is not resent.

## 4. Rollback (NOT RUN)

`cd C:/Users/cires/.cargo/bin`
`ren synapse-claude-channel.exe synapse-claude-channel.exe.rc271.bad`
`ren synapse-claude-channel.exe.rc269.bak synapse-claude-channel.exe`
Lanes already restarted onto rc.271 keep running it until their next restart; the rename back affects only sessions started after it. If a rename fails with "in use", the new exe is held by a running session: wait for it to exit, or copy `.rc269.bak` over under the name once those sessions end. Never kill a process by image name.

## 5. Duration

NOT RUN, so not measured. The release build of one crate is the slow part (minutes; not timed here). The rename and copy are seconds. No downtime for any lane at swap time.

## 6. Scratch-home smoke test (NOT RUN; touches no live home or port)

Automated, read-only against live: in a worktree at the tag, `cargo test -p synapse-mcp-server --test push` includes `a_redeliver_request_rewrites_every_unacked_message_at_once` and `the_redeliver_request_file_is_consumed_once`; both must pass.

Manual, on a scratch home, **RUN 2026-11-28** (real output in PR #389). Port `127.0.0.1:7961` only, home `C:/Projects/_scratch-rc271/home`, binaries built with `CARGO_TARGET_DIR=C:/Projects/_scratch-rc271-target cargo build --release -p synapse-claude-channel -p synapsectl`, old daemon = a copy of rc.247 `synapsed.exe` made into the scratch dir (the live bin was only read). Set `SYNAPSE_NO_AUTOSTART=1 SYNAPSE_HOME=<home> SYNAPSE_ADDR=127.0.0.1:7961` for every command; leave `SYNAPSE_MAILBOX_STORE` unset (the daemon records `sqlite-full` on a fresh home).
1. `synapse id init --account scratch`; `synapse claim --role a`, `synapse claim --role pm` (a role must claim before it can be a recipient; the receiver is `pm` because `a` holds see/send only on `agent:pm@scratch` by default). Start `synapsed` (rc.247) in the background; `curl /v1/health` shows `"version":"6.0.0-rc.247"`. Send 3 messages `a` -> `pm`: each prints `outcome: queued`.
2. `python -I 2026-11-28-rc271-smoke-driver.py <staged channel.exe> <home> pm` plays the MCP host (declares `claude/channel`). Expected and seen: the 3 pushes at start (`notifications: 3`).
3. The driver creates `redeliver-pm.request`. Seen: the same 3 notifications again within one poll tick, the file consumed (`request exists after #1: False`).
4. The driver acks the first message, then creates the request again. Seen: 2 redeliveries (smoke-5, smoke-6), not 3. The driver's window also catches the ordinary 10 s repush of those two, so that window reads 4; the first window (under 10 s) reads exactly 3.
5. Kill the scratch daemon by its recorded pid (`taskkill /PID <pid> /F`), start it again: health answered again, `pm` still shows its 2 unacked messages `queued` (the lease reset at restart). Not timed. The adapter re-attach after a daemon restart was **not** re-run here (2026-10-30 rehearsal covers a restart).
6. Kill the scratch daemon by pid and delete the scratch home and target dir.

## 7. Not established

The swap, a full run of the smoke test, and the launcher side of H1 (who writes the request file) are all NOT RUN / not built.
