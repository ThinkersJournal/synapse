<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Runbook: move a home with two mailbox stores onto sqlite, import the redb side, restart

For a home where `mailbox.redb` and `mailbox.sqlite` both exist, no `mailbox.sqlite.migrated`, and the running
daemon serves redb (started without a pin, so `select_store` chose it). The task script pins
`SYNAPSE_MAILBOX_STORE=sqlite`, so a plain restart through the task REFUSES to start ("not known which holds the
mail"). Everything below was rehearsed on a scratch home and port (`rehearse.sh`, `rehearse2.sh`, 2026-11-17); the
live home was never opened. Nothing here is run without the PM's go in the window.

Names: `$H` the daemon's home; `$B` a new empty backup directory outside `$H`; `$TOOLS` the staged
`synapse-store-tools.exe` (a release build that has `storage inspect` and `storage import`; the installed
`synapse.exe` does not). Never kill by image name; the daemon's pid is read from the process table.

## Before the window (read-only)

0. Stage `$TOOLS`. Keep the OLD `synapsed.exe` exactly as it is (it is the rollback). No daemon binary changes.
1. Record the roster: `synapse list --role <any>` to `$B\pre-list.jsonl` and `synapse stats --role <any> --daemon`
   to `$B\pre-stats.json` (role, epoch, pending: what F compares against).

## The window

A. **Copy sqlite with its sidecars, inspect.** `Copy-Item $H\mailbox.sqlite*  $B\sqlite\` (the `-wal` and `-shm`
   MUST come with it, under the same names: a lone renamed file silently loses the WAL). Nobody holds sqlite while
   the daemon serves redb. Then `$TOOLS storage inspect $B\sqlite\mailbox.sqlite`.
B. **Stop the daemon:** `synapse shutdown --role <a role with daemon-admin>` (exit 0, so the task does not retry).
   Read back that pid 22692 is gone (`Get-Process -Id 22692` errors). Between B and E a legacy lane's CLI call can
   auto-start a daemon with no pin, which would lock redb again: C fails loudly if so (a locked file cannot be copied).
C. **Copy the redb file, never open the original:** `Copy-Item $H\mailbox.redb $B\redb\mailbox.redb`.
   Then `$TOOLS storage inspect $B\redb\mailbox.redb`.
D. **Import on COPIES.** `Copy-Item $H\mailbox.sqlite* $B\work\` (again, after the stop), then
   `$TOOLS storage import --from $B\redb\mailbox.redb --into $B\work\mailbox.sqlite` (dry run: roles added or raised,
   messages added, dropped as acked in the redb side, left out as already acked, acks added, counter), then the same
   with `--apply`. Compare: `$TOOLS storage inspect $B\work\mailbox.sqlite --against $B\sqlite\mailbox.sqlite` (what
   the import added) and `--against $B\redb\mailbox.redb` (any "only in B" line is a loss: there must be none).
   **Report these counts to the PM and stop for the go.**
E. **On the go, in this order:**
   1. `$TOOLS storage use sqlite-full --file mailbox.sqlite` with `SYNAPSE_HOME=$H`. It MUST print `recorded`. Only
      then continue. (With the record written, any auto-start opens sqlite and never creates an empty redb.)
   2. `Rename-Item $H\mailbox.redb mailbox.redb.pre-restart` (rename, never delete). Needed because the task's
      `SYNAPSE_MAILBOX_STORE=sqlite` pin still runs the migration check, which refuses while both files exist.
   3. Apply to the LIVE sqlite, from the copy: `$TOOLS storage import --from $B\redb\mailbox.redb --into $H\mailbox.sqlite --apply`.
      It prints `applied and read back equal to the plan`; its counts must equal D's.
   4. Write `$H\synapsed.toml`:
      `[launch]` / `roles = ["agentlife-launcher"]` / `senders = ["pm","pm-platform","pm-assist","pm-kernels","pm-ants","pm-web"]`.
   5. `schtasks /Run /TN synapsed-cires`.
F. **Checks.** `synapse stats --role <any> --daemon` shows `launch_senders_set: true`; the launcher's log stops
   printing `forbidden`; `synapse list` roles and epochs match `pre-list.jsonl` (a lane that re-claimed since may be
   higher, never lower); three lanes each send a test message and read it back; `mailbox.redb` is NOT recreated in `$H`.
G. **Rollback**, if the new daemon will not start or F fails:
   1. Stop whatever is running (recorded pid).
   2. `Rename-Item $H\mailbox.redb.pre-restart mailbox.redb`; `Remove-Item $H\mailbox-store.json`; delete nothing else.
   3. Remove the `[launch]` lines from `$H\synapsed.toml` if the daemon would not start on them.
   4. `schtasks /Run /TN synapsed-cires`. With the record gone and the SYNAPSE_MAILBOX_STORE=sqlite pin in the task,
      this refuses again (both files, no marker): start the daemon the way it was running (no pin) so it serves redb,
      the state before the window. `$B\sqlite` and `$B\redb` are the untouched copies of both sides.
   The live sqlite after E3 holds the import; to undo it, restore `$B\sqlite\mailbox.sqlite*` over it (daemon stopped).

## What was and was not measured

Rehearsed (scratch): the refusal; unpinned start serving redb; the import dry run, apply, second apply (a no-op),
inspect against both sources; `storage use` then an unpinned start serving sqlite with the mail of both eras; both
orders around the redb rename. Unit-tested and sabotaged: each of the six import rules. NOT measured: the import on the
real stores (their size and any message ids present in both stores), the scheduled-task start itself, and how the ~50
lanes' adapters behave across the restart beyond the 2026-10-30 rehearsal.
