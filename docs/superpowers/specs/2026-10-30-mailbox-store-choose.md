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

**D. WAL handling at startup (the evidence is thinner than the row implies).**
- Evidence: the daemon exited with `pool timed out while waiting for an open connection` on 2026-10-22, 2026-10-24 and
  2026-10-29; the 2026-10-29 note records a 4 MB un-checkpointed WAL. `retry_pool_timeouts` (3 attempts, 30 s busy wait
  each) was added for the first.
- A checkpoint cannot cure a connect that timed out: it runs after the pool exists. `PersistAnt` exposes the pool
  (`SqliteBackend::pool()`), so `PRAGMA wal_checkpoint(TRUNCATE)` after `open_durable` is possible, and it would stop
  an oversized WAL from persisting across restarts and shorten the next recovery. Neither `persistant-sqlx` 0.9.10 nor
  0.12.3 has a checkpoint helper or sets `wal_autocheckpoint`/`journal_size_limit` (searched `src/` of both).
- What is NOT known: why a 4 MB WAL made a connection wait 30 s three times. Recovering a WAL of that size should be quick (not measured here);
  a 30 s wait suggests another process holding the file (a second daemon, an antivirus scan, the previous process still
  exiting) rather than WAL size. **Before writing a checkpoint, capture it:** the `step(...)` timings the open already
  prints, and who holds `mailbox.sqlite` / `mailbox.sqlite-wal` at the time (`Get-Process` / handle listing). If it is a
  second holder, the fix is the lock, not the checkpoint.
- Proposed code, once the cause is known: checkpoint-and-truncate at open (failure is a warning, never fatal), and again at
  graceful shutdown, each with a test that a grown WAL is truncated. Do not ship it as a cure for the timeout unless the
  capture says so.

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
3. D: capture the cause of the pool timeout; then the checkpoint if the capture supports it.
4. C: redb decision applied (code only after the decision).

## 5. Open calls for the PM

1. Is the persistant bump (slice 0) mine to start now? It predates this row and the rule says it was due.
2. A's cost: accept sqlx for all three databases in every build, or ask PersistAnt to split the registry features?
3. C: keep redb for one line as a migration source, then drop the mailbox variant?
4. D: allowed to capture handle and timing evidence on the live daemon (read-only), or does the PM run it?
