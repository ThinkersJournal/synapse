<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Row 42 slice C: retiring the redb mailbox store (design, not built)

Written 2026-10-30 against `origin/main@5e8372b` (rc.199). Slice C of
`2026-10-30-mailbox-store-choose.md`. **Not scheduled to build.** PM ruling 2026-10-30: earliest 2026-11-30, and only
after (a) the live daemon's home is migrated to SQLite with a tested path and (b) the 3-day Phase B soak is closed and
Phase C decided. This note fixes the scope so the later PR is mechanical.

## 1. Where the conditions stand

- **(a) The live home is already on SQLite.** Read from file names only (no contents), 2026-10-30: the pilot home holds
  `mailbox.sqlite` (+ `-wal`, `-shm`, `.lock`), **no live `mailbox.redb`**, and only dated `mailbox.redb.*-bak` files from
  2026-10-22/23 (stray daemons started by an adapter or CLI before rc.130, #234). It runs on `SYNAPSE_MAILBOX_STORE=sqlite`.
  So (a) needs no migration of the live mail; what is left is the tested path for ANY other redb home
  (`migration::prepare`, `tests/migrate.rs`: exists and tested), and the live home moving from the env pin to a recorded
  choice (`synapse storage use`) so the deprecated pin can go.
- **(b) is the PM's.** Nothing in code waits on it.

## 2. What stays, whatever slice C does

`state.redb` (the daemon's state engine, `synapse::state::RedbBackend`, `redb` crate) is a different store and is not
touched. The `redb` dependency and the `mailbox-redb` core feature stay for as long as `RedbBackend` or the migration
reader needs them.

## 3. Slice C in two steps

**C1 (the dated one): redb stops being a daemon mailbox option.**
- `StoreKind::Redb` and the `redb` pin value go; `select_store` returns `Selection::Named` or `Kind(Sqlite)` only. A pin
  of `redb` becomes an error naming the migration (`synapsed` exit 2, text points to the CHANGELOG entry).
- `sqlite-store` stops being a feature: the dependency is unconditional, the `cfg(feature = "sqlite-store")` gates in
  `lib.rs`, `main.rs`, `select.rs` and the tests go, and `--no-default-features` no longer builds a redb daemon. (That is
  a build-surface change; the CHANGELOG says Breaking.)
- A home that holds a live `mailbox.redb` and no marker still migrates on first start (`migration::prepare` is kept), so
  an operator who skipped the release lines in between is not stranded. The both-files-no-marker refusal stays.
- `Daemon::open` (used by tests and examples with the default store) becomes SQLite: `tests/api.rs` and
  `latency_probe` switch their default; the API suite then takes about 10 minutes instead of 21 s
  (`ci_cd.yml` says so for the SQLite job), so the required job's time is the cost to price before C1. Option: keep a
  memory store for the API suite (`MemStore` exists in core), which also removes redb from the test path.

**C2 (later): the migration reader goes.** After one more release line with no redb home reported, remove
`migration.rs`, `tests/migrate.rs`, `RedbStore` use in `synapsed`, and, if `RedbBackend` is the only other user, decide
the `mailbox-redb` feature (the core mailbox's redb store, its benches `mailbox_*_cost` and `tests/mailbox_{redb,crash,held}.rs`
go or move to the SQLite adapter).

## 4. Migration window to state in the CHANGELOG entry

Mail accepted before the stop is copied and verified; sends during the stop-to-first-start gap get the no-daemon answer and
are not queued; going back to redb after the move loses mail accepted since (acceptable: CireSnave 2026-10-30, archive 326).

## 5. Checks before C1 is built

1. `git grep -c "StoreKind\|mailbox.redb\|RedbStore"` shows the inventory (rc.199: `src/mailbox.rs` 16, `synapsed` 51 across
   `lib.rs`/`select.rs`/`migration.rs`/tests, core tests/benches ~40). Re-take it at build time.
2. Every active home (live pilot, role homes, WSL pilot) read for `mailbox.redb` without `.migrated`/`.sqlite`: file names only.
3. The PM's go on the date.
