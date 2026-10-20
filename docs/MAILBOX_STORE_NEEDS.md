<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# What Synapse's mailbox needs from a store

Board 229, ruled by CireSnave 2026-10-18 (option A): *"A power loss does not necessarily kill every agent. If we have
agents running on my laptop, on my desktop, and in the cloud, a power loss for one may not affect others. That said, 229:
A."* Mail acknowledged to a sender must survive power loss, so the required durability class is **Machine**.

This is the contract `synapse::mailbox::MailStore` implementations are held to. "Enforced by" names what fails if a
store does not meet it. A need with no enforcement named is a gap, listed at the end.

| # | Need | Enforced by |
|---|---|---|
| 1 | **Durability class >= Machine.** A write that returned `Ok` is on stable storage; a power cut afterwards loses nothing acknowledged. | `MailStore::durability()` has no default (a store must state its class: compile time). `Mailbox::open` refuses a store declaring less with `MailError::DurabilityTooWeak` (start-up: the daemon will not start). `conformance::declares_the_needed_durability` and `a_store_declaring_less_is_refused`. `Mailbox::open_volatile` skips the check and exists for tests and throwaway stores. |
| 2 | **Atomic enqueue/ack.** `MailStore::write` applies every change its closure makes or none; an `Err` from the closure leaves the store as it was. | `a_failed_write_changes_nothing`; `tests/mailbox_crash.rs` (abort mid-transaction, redb). |
| 3 | **Ordering.** A role's queue is scanned in enqueue order (`seq`, from `next_seq`, never reused). | `an_expired_lease_redelivers_in_order`, `enqueue_then_fetch_leases_and_hides`. |
| 4 | **Lease / visibility timeout.** A fetched message is hidden until its lease expires, then redelivers in order; a takeover voids older epochs' leases at once. | `enqueue_then_fetch_leases_and_hides`, `an_expired_lease_redelivers_in_order`, `a_takeover_frees_the_old_leases_at_once`, `a_superseded_epoch_cannot_fetch_or_ack`, `only_the_lease_holder_acks`. |
| 5 | **TTL / retention.** Acked history older than the retention window is swept; queued mail is never swept. | `sweep_deletes_old_acked_history_never_queued_mail`. |
| 6 | **Idempotence.** A duplicate id while queued is not queued twice; an ack is idempotent; a resend after ack is reported a duplicate. | `a_duplicate_while_queued_is_not_queued_twice`, `ack_is_idempotent`, `ack_removes_for_good_and_a_resend_is_a_duplicate`. |
| 7 | **Bounds without loss.** A full queue refuses the sender and drops nothing; a full dead set keeps the message queued. | `the_bound_refuses_by_count_and_by_bytes_and_keeps_the_queue`, `a_full_dead_set_keeps_the_message_queued`. |
| 8 | **Roles written through.** Claims and epochs persist in the store and a reopen continues from them. | `claims_are_written_through_the_store`; `tests/mailbox.rs` (poison and reopen). |
| 9 | **Stalls become errors.** A store that can stall (MySQL did in PersistAnt's disk-full test, 2026-10-18) must return `Err` within a bound rather than block `write` forever; a timed-out write has an unknown outcome, so a retry under the same id must leave one copy. | `conformance::a_stalled_backend_returns_an_error_not_a_hang` (not in `run_all`: it needs a stall switch, so a store that can stall runs it beside it). Run by `synapse-mailbox-persistant` in `tests/stall.rs`. |

`run_all` runs the semantic cases (2-8) over `Mailbox::open_volatile`, so a `Process` store can still be checked for
semantics. A store that will hold real mail must also pass `declares_the_needed_durability`.

## Gaps

- **Machine is declared, not verified, for redb.** `RedbStore` declares `Machine` because redb commits at its default
  `Durability::Immediate` and this store never lowers it. Synapse has no power-cut test of its own; the crash test aborts
  the process, which is Process-class evidence.
- **Need 9** is a case beside `run_all`, not inside it, so a new stallable store can forget to run it.
- **A backend's declaration is trusted.** For a PersistAnt-backed store, the declaration must come from PersistAnt's
  verified class for the configuration actually opened (for SQLite, `open_durable`: WAL + `synchronous=FULL`), never from
  the backend family.
