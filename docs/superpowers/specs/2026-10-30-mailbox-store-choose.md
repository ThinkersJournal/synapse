<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Mailbox store through PersistAnt `choose` (ROADMAP row 42): what is built, what is left

Design note, written 2026-10-30 against `origin/main@8ac9a70` (6.0.0-rc.186). No code changes. Row 42's text lists four
items; reading the code first changed the list, so the plan below replaces the row's wording once it is agreed.

## 1. What exists already (row item 2 is mostly done, behind a feature)

In a `--features sqlite-store` build, `synapsed` already selects its store through PersistAnt (`crates/synapsed/src/main.rs`
`named_choice`, `Daemon::open_named`, `RegistryMailStore::open_choice` with `MailboxNeeds::MAILBOX`):

1. a pin (`SYNAPSE_MAILBOX_STORE` / `storage.id`) wins, and the environment form prints a deprecation note;
2. else `<home>/mailbox-store.json` (written by `synapse storage use`);
3. else a home that already holds `mailbox.redb` or `mailbox.sqlite` is left on the store it has (`None`, so `open_with`);
4. else, on a fresh home, the first *file* provider PersistAnt lists for the mailbox's needs is recorded and used.

PersistAnt checks the chosen provider against the needs again at open (every call bounded), so an id that no longer
meets them stops the start. The daemon hard-wires no backend name on the `Named` path; it does on the `StoreKind` path
(`Redb`, `Sqlite`), which a build without the feature, or a pin of `redb`/`sqlite`, still takes.

**So the row's item (2) is not "write the selection"; it is "make the selection the only path".** That is item B below.

## 2. What is left, in the order I would do it

**A. SQLite joins the default build.** Today `sqlite-store` is off by default (`crates/synapsed/Cargo.toml:37`). A build without
it refuses a `sqlite` pin and exits 2, which cost a daemon outage on 2026-10-29; and a plain `cargo install synapsed`, given a
home that a `sqlite-store` build has been using and no pin, opens `mailbox.redb` (the stale file, or a fresh empty one), not the
SQLite store the mail is in. A default build removes that trap.
- Change: `default = ["sqlite-store"]` for `synapsed`; the `cfg(feature = "sqlite-store")` gates stay (a build can still opt out
  with `--no-default-features`), so the diff is the feature line plus a test that a default build accepts `sqlite`.
- Cost to state, not hide: `synapse-mailbox-persistant` pulls `persistant` with `registry-sqlite`, `registry-postgres` and
  `registry-mysql`, i.e. sqlx for three databases, into every `synapsed` build. That is install time and binary size for
  an operator who only wants a file store. Measure both before and after in the PR (size of `synapsed.exe` release, cold
  `cargo install` time) rather than assert them here. If the size is a problem, the follow-up is to enable only
  `registry-sqlite` by default and keep the server providers behind their own features; PersistAnt's `choose` then lists
  fewer providers and says so.

**B. One selection path.** Fold `StoreKind::{Redb, Sqlite}` into the `choose` path: a pin of `sqlite` or `redb` becomes
"use provider id X", resolved by `choose`, instead of a second open code path (`Daemon::open_with`). Behaviour to keep,
each with a test: the 2026-10 migration (redb to SQLite on first start, `migration::prepare`) still runs for that
transition; a home with both files and no marker still refuses to start; `SYNAPSE_MAILBOX_STORE` keeps working and keeps
printing its deprecation line. Risk: this is the daemon's store open, so it gets the same red-first, mutation-checked
treatment as the migration did. Not started until A has merged.

**C. redb: keep as fallback, or retire (a decision, not code).** Board D1 said "Redb is fine for now". Facts for the decider:
- redb stays the *fallback* only if something needs it: a home that already has `mailbox.redb` (migrates on first
  SQLite start; the file is kept, stale) and a build without the SQLite provider (after A, only `--no-default-features`).
- The daemon's *state* engine also uses redb (`synapse::state::RedbBackend`, `state.redb`; `crates/synapsed/src/lib.rs`
  `open_store`). Retiring redb as the mailbox store does not retire it from the daemon. That is a separate, larger
  question and this note does not answer it.
- Recommendation: keep redb as a read-only migration source for one release line after A, then drop the mailbox-store
  variant and keep the dependency only for state. Needs the PM or CireSnave to confirm; nothing here depends on it.

**D. WAL handling at startup: dropped (2026-10-30, PM agreed).**
- The premise was wrong. A read-only inspection of a COPY of the live `mailbox.sqlite`, `-wal` and `-shm` found the WAL at
  4,120,032 bytes = 32 + 1000 x (4096 + 24): exactly 1000 frames, which is SQLite's default `wal_autocheckpoint` (1000
  pages). That is the steady-state size of a WAL that is checkpointed and reused, not growth. `checkpoint_seq` was 3,
  `integrity_check` ok, `persistant_kv` 346 rows. The earlier statement that "a 4 MB un-checkpointed WAL" caused the
  pool timeout is retracted. A checkpoint at start is therefore not built.
- What the daemon's own log (`task/synapsed.log`) does show: 5 `pool timed out` failures between 2026-10-22 and
  2026-10-29, and on the first start after the 2026-10-29 reboot the step "sqlite and key-value layer open" ended 10 s
  after the open began (a warm start took 23 ms). The slow part was the pool connect.
- **Cause: not established. Who held `mailbox.sqlite` at the failures: not established** (`handle64.exe` printed nothing from
  an unelevated shell; the process table at capture time held one `synapsed`, four adapters and Windows Defender's
  `MsMpEng`, none shown to hold the file). Nothing here claims a cause.
- Done instead (rc.190): every cold-start step line now carries its own UTC clock, the time since the previous step and
  since the open began, so the next failure brings its own evidence. A bounded retry exists already (`OPEN_RETRIES`);
  whether more is needed waits for a failure that carries those timestamps.

## 3. Dependency lag to resolve first (standing rule: newest dependencies)

`crates/synapse-mailbox-persistant/Cargo.toml` declares `persistant` 0.9.10, `persistant-sqlx` 0.9.4 and `persistant-kv` 0.9.4 (lock:
`persistant-sqlx` 0.9.10). `cargo search` on 2026-10-30 reports 0.12.3 for all three. That is three minor lines behind, and 0.x
minors are breaking in cargo's terms. Whatever A to D change in the store, they should be written against the version the
rule wants, or the work is redone. This is a bump PR of its own (read the 0.10, 0.11 and 0.12 changelogs for the `choose`,
`KvOnRelational`, `Bounded` and `open_durable` surfaces first), and it should be sequenced before B.

## 4. Slices (each its own PR, red-first)

0. `persistant` 0.9 to 0.12 (section 3).
1. A: SQLite in the default build, with the size and install-time measurement.
2. B: one selection path.
3. D: dropped; step lines timestamped instead (rc.190).
4. C: redb decision applied (code only after the decision).

## 5. The PM's answers (2026-10-30)

1. Slice 0 (persistant 0.9 to 0.12.3): yes, now. Done as #296 (rc.190).
2. A: accept sqlx for SQLite, PostgreSQL and MySQL in the default build for now; file a PersistAnt ask to make the registry
   features splittable, as a scheduled ROADMAP row (not blocking).
3. C: keep redb for one release line as a migration source, then drop the mailbox variant, with the drop dated in the CHANGELOG.
4. D: read-only capture done by the synapse lane on copies; slice D dropped (section 2).
