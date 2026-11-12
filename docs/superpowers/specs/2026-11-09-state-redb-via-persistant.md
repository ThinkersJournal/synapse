<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# `state.redb` through PersistAnt (design, not built)

Written 2026-11-09 against `origin/main@42d2a319` (Synapse) and PersistAnt `origin/main@32ccc43` (0.16.8). PM TASK
2026-11-09, after CireSnave: *"None of our projects should work directly with persistence services if it can be done
through persistant. Unless there is some reason it can't work through PersistAnt, get auth-framework transitioning to
PersistAnt being its default for persistence."* This note is the exact terms for the PersistAnt lane. No code changes.

## 1. What `state.redb` is

The daemon's shared lane state (`synapse::state::StateEngine<RedbBackend>`, `crates/synapsed/src/lib.rs`, file
`<home>/state.redb`). The engine owns all logic; the backend is "rows and atomicity, nothing else"
(`src/state.rs`, trait `Backend`, `Txn`, `TxnRead`). `RedbBackend` is the only durable implementation
(`src/state/redb_backend.rs`); `MemoryBackend` is the test one. Row 42 slice 3 asked "keep or retire"; the PM has since
ruled retire, via PersistAnt.

## 2. Exact terms (what a PersistAnt-backed `Backend` needs)

**Data model (redb tables, all values serde_json bytes, `FORMAT = 1`):**

| redb table | key | needs |
|---|---|---|
| `records` | `&str` id (`T-<n>`, from `next_number`) | point get/put; full ordered scan (`all`) |
| `history` | `(id, revision: u64)` | ordered range of one id, ascending revision (`history(id)`) |
| `notices` | `u64` seq | ascending scan with a limit (`notices(max)`); point delete (`remove_notice`) |
| `facts` | `&str` fact spec | point get/put |
| `derived_flags` | `&str` id | point get/put |
| `counters` | `"record"`, `"notice"`, `"format"` | read-modify-write of a u64 inside the transaction (`next_number`, `push_notice` seq) |

**T1. Atomic multi-key transaction.** `Backend::write(f)`: every `put_record`, `append`, `push_notice`, `remove_notice`,
`put_fact`, `put_derived_flags` and counter change made by `f` commits together or not at all; `Err` from `f` discards
all of it. A crash leaves the whole previous state or the whole new one, never a mix (the engine relies on a record, its
history entry, its notice and the counters moving together).

**T2. Read-your-writes inside the transaction.** `f` reads through the same `Txn` it writes through (`next_number` reads
the counter then writes it; `put_record` then `record(id)`; `derive_in` reads facts and other records mid-write). A read
inside `write` must see that transaction's own earlier writes.

**T3. Consistent snapshot reads.** `Backend::read(f)`: all reads in `f` see one snapshot (a record and its history from
the same instant). Today redb serves `read` from a *write* transaction (`begin_write`, `redb_backend.rs`), which is
stronger than needed and serialises readers behind writers; a snapshot is sufficient.

**T4. Ordered scans.** Ascending by key bytes; `history` needs a prefix scan per id with revisions in numeric order (so a
key encoding that sorts numerically, such as zero-padded decimal), `notices` a scan from the lowest seq with a limit,
`records` a full scan.

**T5. Owner-only file, refused when broader.** `open` creates the file `0600` on Unix (on Windows it inherits the user
profile's ACL) and **refuses** an existing file broader than its owner (`keystore::check_owner_only`). A PersistAnt
provider for this need must declare the file owner-only, or Synapse keeps its own check on the path the provider reports.
Not applicable to a networked provider: such a provider must be refused for this need (see T7).

**T6. One process per file.** redb takes an exclusive file lock; a second daemon on the same home fails at open. A
provider must either hold such a lock or the daemon must (the mailbox adapter's `.lock` file is the precedent).

**T7. Durability and locality.** Durability `Machine` (a committed transaction survives power loss), single machine, no
network provider for lane state (it holds who is working on what; it is not shared between hosts). Stated as the
`ProviderNeeds` the daemon declares, as the mailbox does with `MailboxNeeds`.

**T8. Format stamp.** `counters["format"] = 1`, refuse a store whose stamp is newer than the binary knows.

**T9. Size.** Small: records, history, notices and facts for lanes in one account (hundreds to low thousands of rows,
bytes each of JSON). No bulk, no blobs.

## 3. What PersistAnt already offers (read at 32ccc43, `persistant-kv`)

`KvBackend` has: `get`, `put`, `put_if_absent`, `compare_and_swap`, `compare_and_delete`, `ordered_scan` and
**`ordered_scan_values` from one consistent snapshot** (T3, T4), and **`batch(&[BatchOp])`**: `Put`, `Delete` and
**`Require { key, expected }`**, applied as one unit, `Ok(false)` and nothing changed when a `Require` fails, concurrent
batches requiring the same value resolve to one winner (`kv.batch_atomic.rollback`, `.concurrent_read`).
`KvOnRelational<SqliteBackend>` is what the mailbox adapter already runs on (WAL, `synchronous=FULL` via
`open_durable`). So the mechanisms for T1, T3, T4 exist.

## 4. The gaps (what would have to be true)

**G1. Optimistic, not interactive, transactions.** `batch` is write-only plus preconditions; the engine's closure reads
mid-write (T2). The adapter must buffer writes and serve reads from the buffer over the store, recording every key the
closure read (value or absence) as a `Require` in the final `batch`. That gives T1 and T2 without a PersistAnt change.
Two real limits to state: (a) **range reads are not covered by `Require`** (`all`, `history`, `notices` scan, so a
concurrent insert is a phantom). In one process this does not occur if the adapter serialises `write` behind a mutex
(T6 makes the daemon the only writer), so the `Require`s are a guard, not the mechanism; (b) `Backend::write` takes an
`FnOnce` closure, so a failed `Require` cannot be retried by the adapter. Under the mutex it cannot fail; if it does,
return `StateError::Store` rather than retry.
*Ask of PersistAnt:* confirm that `batch` + `Require` is the intended way to build a read-then-write transaction, or say
if an interactive transaction (a `kv.txn` leaf: begin, get, put, scan, commit) is planned. Synapse works with the former
now; the latter would remove G1(a).

**G2. Counters.** `next_number` and the notice `seq` are read-modify-write; with G1 they are a `Require(old)` + `Put(new)`
in the transaction. No atomic increment is needed. (If one existed, it would avoid growing the `Require` set.)

**G3. Key encoding.** `records/<id>`, `history/<id>/<revision as 20-digit decimal>`, `notices/<seq as 20-digit decimal>`,
`facts/<spec>`, `flags/<id>`, `counters/<name>`: string keys with a fixed prefix per table. `ordered_scan_values` with
the prefix covers `all`, `history(id)` and `notices(max)` (a page limit). Needs: keys are compared as bytes ascending
(stated), and the id and fact-spec alphabets exclude `/` or are escaped (the adapter checks; Synapse's ids are `T-<n>`).
*Ask:* confirm key length limits (a fact spec is the longest key).

**G4. Async at a sync boundary.** `Backend` is synchronous and `KvBackend` is async. The mailbox adapter already bridges
this inside the daemon (a runtime handle, blocking at the boundary). The state adapter does the same; no PersistAnt
change. Stated so nobody expects `Backend` to become async in this change.

**G5. Provider selection and the stored choice.** Per EXPECTATIONS 6.17 steps 1-5, the daemon declares a need
(`StateNeeds`: durability Machine, kv with `batch_atomic` and `ordered_scan_values`, local only, one process per file),
PersistAnt returns the providers that meet it, the operator picks, the id is stored in the daemon's config
(`<home>/state-store.json`, like `mailbox-store.json`), and calls are backend-agnostic. *Ask:* the `providers(&needs)`
and `open_named` entry points the mailbox uses (`persistant 0.16`), with a `kv.batch_atomic` + `kv.ordered_scan_values`
requirement; and a statement of which providers pass today (SQLite does for the mailbox; Postgres and MySQL pass the
leaf tests but T7 excludes them).

**G6. Owner-only (T5).** *Ask:* does a provider report the path it opened, or can the need say "file must be owner-only"
so it is enforced by the provider? If not, Synapse checks the path itself (as `RedbBackend::open` does).

## 5. Migration (Synapse side, not PersistAnt)

First start on the new store with a `state.redb` in the home and no state-store marker: copy every table into the new
store inside one batch per table family, read it back, record the marker, rename the file to `state.redb.migrated`.
`migration::prepare` (mailbox) is the precedent: both-present-no-marker is refused; a copy is verified before the marker
is written; going back loses what was written since. State is small (T9), so the copy is a single pass.
State is derived in part (`derived_flags`, facts) and could be rebuilt by `refresh_derived`; do **not** rely on that:
copy everything, including history and notices undelivered.

## 6. Order of work

1. PersistAnt lane answers G1, G3, G5, G6 (this note's asks; nothing else is needed from it).
2. Synapse: `synapse-state-persistant` adapter (a new crate beside `synapse-mailbox-persistant`, so the core crate keeps
   no PersistAnt dependency), `StateNeeds`, selection and marker, migration, tests: the state conformance suite the
   engine already runs against `MemoryBackend` and `RedbBackend`, plus a crash-between-writes case and a two-daemons case.
3. Default flips to the PersistAnt store for new homes; existing homes migrate on first start.
4. Slice C2 (with the mailbox's, `2026-10-30-slice-c-retire-redb-mailbox.md`): the `redb` dependency, `RedbBackend`,
   `mailbox-redb` and the migration readers go. **Not before** slice C1 (2026-11-30, PM) and not before the live home is
   on a recorded storage choice (the PM has not confirmed it).

## 7. Not covered

The owner-only JSON files (keystore keys and certificates, `trust/`, `access.json`, config) are not databases. The PM:
*key material and tiny documents stay as files unless CireSnave says otherwise.* This note does not claim his ruling
covers them.

## 8. What was verified and what was not

Read at the refs above: the `Backend`/`Txn`/`TxnRead` traits, `RedbBackend` (tables, open, owner-only check, `read` on a
write transaction), `KvBackend::{batch, ordered_scan_values, compare_and_swap}` and `BatchOp::Require` signatures and
docs. **Not verified:** that `KvOnRelational<SqliteBackend>` passes `kv.batch_atomic` and `kv.ordered_scan_values` in the
current matrix (the mailbox adapter relies on it, but I did not read the matrix row); key length limits; whether any
engine code path reads a range inside `write` and depends on seeing its own uncommitted range writes (11 `write`/`read`
call sites in `src/state.rs`; to be audited when the adapter is built, because G1(a) is only sound if none does).
