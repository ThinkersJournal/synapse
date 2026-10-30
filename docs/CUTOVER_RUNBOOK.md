<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Cutover runbook: what the daemon, the lanes and the schedule must carry

Companion to `docs/PILOT_T0_RUNBOOK.md` (the pilot's steps) and `docs/CUTOVER_READINESS_2026-10-15.md` (gates G1-G9).
This page is the settings a cutover depends on, each with the check that proves it took. It starts no task and
changes no home: **registering a scheduled task waits for CireSnave's go**, and nothing here reads or changes the
pilot's keys (the PM says so in writing first).

Written against `6.0.0-rc.185`. Items marked *(rc.185)* need that build or later.

## 1. The daemon's environment (G7: whoever starts `synapsed` at login)

A lane's environment never reaches the daemon, so every setting below belongs in the wrapper the login task runs
(agentlife `scripts/synapsed-task.ps1` writes it to `%SYNAPSE_HOME%\task\synapsed-run-*.cmd`). Read the wrapper after
registering; the script sets only some of these.

| Variable | Value | Why | Proof it took |
|---|---|---|---|
| `SYNAPSE_HOME` | the promoted home (section 4) | the daemon's keys and store | `synapsed.json` appears there |
| `SYNAPSE_ADDR` | `127.0.0.1:<port>` | the address lanes announce | `Get-NetTCPConnection -LocalPort <port>` |
| `SYNAPSE_MAILBOX_STORE` | `sqlite` | Decision 237; the default is redb | `mailbox.sqlite`, not `mailbox.redb`, appears in the home |
| `SYNAPSE_LAUNCHER_ROLES` | the roles a launcher watches | enables `GET /v1/waiting` | `synapse stats --daemon` |
| `SYNAPSE_LAUNCH_SENDERS` | `role` (this account) or `role@account`, comma-separated | **fail closed**: launcher roles set and this empty means no launch signal is ever raised | `synapse stats --daemon` prints `launch_senders_set: true` |

`SYNAPSE_LAUNCH_SENDERS` may also live in `<home>/synapsed.toml` as `launch.senders`; the daemon re-reads that file every
5 s and keeps the last good list on a bad edit.

`SYNAPSE_MAILBOX_STORE=sqlite` needs a `synapsed` built with `--features sqlite-store`; a build without it refuses the
pin and does not start (this cost an outage on 2026-10-29; ROADMAP row 42 makes SQLite part of the default build).
`--features` applies to every package in one `cargo install`, so install `synapsed` on its own:
```powershell
cargo install synapsed --version <rc> --locked --features sqlite-store
cargo install synapsectl synapse-claude-channel --version <rc> --locked
synapsed --version; synapse --version; synapse-claude-channel --version   # which build is installed
```
`--version` and `--help` open no home, store or port, so they are safe to run anywhere.

## 2. The lane's environment

- `SYNAPSE_HOME` is the lane's own role home (section 3), in the `.mcp.json` `env` block as well as `--home`.
- `SYNAPSE_NO_AUTOSTART=1` *(rc.185)*: the `synapse` CLI finds the owner's daemon and never starts one. Without it a
  CLI call with no answering daemon starts `synapsed` from the caller's environment (wrong store, wrong address,
  outside the login task). The adapters already never start one. With it set and no daemon the command exits non-zero
  with `no daemon answered`; that is the intended failure, not a bug to retry around.
- Unknown flags exit 2 and start nothing, in all four binaries.

## 3. Weekly provision: each lane gets a role-only home

`synapse id provision` is run with the **account key** (so from the account home, by the owner, not from a lane):
```powershell
$env:SYNAPSE_HOME = "<account home>"
synapse id provision --roles-file roles.txt --lane-home-root <DIR>            # dry run: writes nothing
synapse id provision --roles-file roles.txt --lane-home-root <DIR> --apply    # --days 30 --renew-below-days 14 by default
```
- `roles.txt`: one role per line, `#` comments. A bad or repeated name refuses the whole file before anything is written.
- Each role gets `<DIR>/<role>` with its keys and a current certificate and **not** the account key.
- Prints `<role> <ok|created|renewed|would-create|would-renew|refused: ...>`; never a key, certificate or path. Exit 2 if any
  role was refused; the others are still done. Idempotent: a current certificate is `ok` and untouched.
- Certificates last at most 30 days and a lane cannot renew its own, so the schedule must be **shorter than
  `--renew-below-days`** (14 by default): weekly leaves a week of slack. A skipped run is not noticed until a lane's
  certificate lapses, so read the output of each run for `refused` and `renewed` counts.
- **Not isolation.** Lanes run as one OS user, so any lane can read any role's home. This keeps the account key out of lanes
  and keys out of output, nothing more. Same-user versus per-user isolation is a question with CireSnave.
- Registering the weekly task (Task Scheduler) waits for CireSnave's go. Until then it is run by hand.

## 4. Which home becomes the production home

PM ruling: **promote the pilot home and keep its account key**, after sweeping dead and unacked mail out of it. Not
done, and not mine to do: the sweep method and its timing are the PM's to specify, and the pilot's keys are not read or
changed until the PM says so in writing. Consequences to plan for:

- The promoted home keeps its account, so lanes' identities (`role@account`) do not change; `SYNAPSE_LAUNCH_SENDERS`
  entries written as `role@account` stay valid.
- A home that holds `mailbox.redb` and no `mailbox.sqlite`, started on the SQLite store, is migrated on that first start
  (copied, verified, marker `mailbox.sqlite.migrated`; the redb file is kept, now stale). A home with both files and no
  marker refuses to start: only the operator knows which is current. Design: `docs/MAILBOX_MIGRATION_REDB_TO_SQLITE.md`.
  A different store is otherwise a different file: nothing else is converted. Check which files the home holds before
  the first start.
- `SYNAPSE_MAILBOX_STORE` is the deprecated pin. The recorded form is `<home>/mailbox-store.json`
  (`synapse storage list`, `synapse storage use`; see `docs/MAILBOX_STORES.md`); the environment pin wins over it.

## 5. After a restart or an install: what to read

1. `synapsed --version` (installed build).
2. The daemon answers: `synapse list --role <role>` (a bare `list` exits 2); in an MCP session, `whoami`.
3. `synapse stats --daemon`: `launch_senders_set` is `true` whenever launcher roles are set.
4. The store file in the home matches `SYNAPSE_MAILBOX_STORE`.
5. Each role home's certificate is current (the last provision printed `ok` or `renewed` for it).

Rollback and the side-by-side phases are in `docs/CUTOVER_READINESS_2026-10-15.md` section 4.
