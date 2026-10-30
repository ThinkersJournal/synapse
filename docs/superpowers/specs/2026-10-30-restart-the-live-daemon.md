<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Restarting the live `synapsed` without splitting the lanes (ROADMAP row 45)

Design note, 2026-10-30, written against `origin/main@0ec16d0` (6.0.0-rc.197). PM task: agentlife's
`docs/SYNAPSE-MCP-RECONNECT-MEASURE.md` (agentlife#190) saw a daemon back "within ~2 s" of each kill and blamed the
adapter, so stopping the live daemon might split lanes across daemons.

## 1. What the measurement shows, and what it does not

- The adapter **does not start daemons**: `connect` in `crates/synapse-mcp-server/src/lib.rs` calls
  `Daemon::connect_existing` (rc.130, #234, 2026-10-22); the installed adapter was built 2026-10-23. A startup test
  existed (`the_adapter_never_starts_a_daemon`); what was missing is a RUNNING adapter whose daemon dies. It is added
  (`a_running_adapter_whose_daemon_died_starts_no_replacement`, sabotage-checked: with `connect_existing` swapped for
  `connect` it fails).
- The probe also ran `synapse send` from a second role every ~2 s. The `synapse` CLI **does** start a daemon when none
  answers (`Daemon::connect`), from the CLI's own environment. The 2 s reappearance matches that cadence. This is the
  more likely starter. **Not established** (the probe's installed adapter version was not recorded, and I have not rerun
  its sender-less variant against the old adapter).
- The real hole, whichever process did it in that run: anything that calls `Daemon::connect` from a lane. A lane's
  `synapse` CLI call with no `SYNAPSE_NO_AUTOSTART` and no `SYNAPSE_DAEMON_HOME` starts a `synapsed` from the lane's
  environment. Reproduced in the new test, red before the fix: a command in a role-only home printed
  `synapse: started synapsed (pid N)`, the daemon exited 2 ("no account"), and it left `mailbox-store.json` in the lane
  home. A lane whose home held the account key could have kept such a daemon (not tried).

## 2. Decision (built in this PR, rc.199)

A **role-only home** (names an account, holds no account key: what `id provision` makes) can never run a daemon, so
`Daemon::connect` treats it like `SYNAPSE_NO_AUTOSTART`: `connect_existing`, never `spawn_daemon`
(`Keystore::is_role_only_home`). It needs no environment variable, so a lane cannot forget it. The CLI on the owner's
account home keeps starting a daemon for a fresh install. Rejected: "refuse when the announce file's daemon is down":
the daemon deletes the file at a clean stop, so a gap after `schtasks /End` looks like a fresh home.
Still open, by design: a legacy lane that shares the account home and has neither variable can start a daemon during a
gap. Closing it means moving that lane onto a provisioned role home (readiness item 3), not another guard.

## 3. Restart procedure for the live daemon (rehearsed on a scratch home)

Preconditions: CireSnave's/the PM's go (message loss on a restart is acceptable, 2026-10-30; the window is the gap
below); record the daemon's pid from the process table (never kill by image name); new build installed to a STAGING
path first.

1. Stage: `cargo install --path crates/synapsed --locked --root <staging>` from a `main` checkout (not over the
   running `~/.cargo/bin/synapsed.exe`).
2. Swap: Windows lets a RUNNING exe be renamed: rename `synapsed.exe` to `synapsed.exe.rc<old>`, copy the staged one in.
3. Stop the recorded pid (or `schtasks /End /TN \synapsed-cires`), then start it again the way the task does
   (`schtasks /Run /TN \synapsed-cires`). Same environment, same home: the task's.
4. Check: `GET /v1/health` shows the new `version`; `synapse stats --role <any> --daemon` shows `scope":"home"`; a queued
   message is still in its inbox; each lane's first call afterwards fails once and the next works (re-attach); no
   `synapsed-start.err` in any lane home.

Rehearsal 2026-10-30 (scratch home and port 127.0.0.1:7947, old `synapsed` rc.179 from `~/.cargo/bin`, new build rc.197,
`SYNAPSE_MAILBOX_STORE=sqlite`, three messages queued for `b`): renaming the running exe worked; kill to health
answered by the new version took **2.6 s**; `b`'s inbox held all 3 messages afterwards; the new daemon's stats read
`scope: home`; no `synapsed-start.err`. Not rehearsed: the scheduled-task start (needs the real task), and
`stats.json` itself (it is written on the first counted event after the restart, none occurred in the rehearsal).
The counters of the old build are in memory and are lost at this restart; they begin persisting from it.

## 4. Slices

1. This PR: `is_role_only_home` guard, the two tests, this note, ROADMAP row 45.
2. The live restart itself (needs the go).
3. Readiness item 3 for any lane still on the account home.
