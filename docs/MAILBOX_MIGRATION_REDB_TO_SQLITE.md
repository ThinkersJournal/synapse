<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Moving the mailbox from redb to PersistAnt SQLite

Adoption-fit gap 5 (`docs/ADOPTION_FIT_2026-10-17.md`), under board 229 (option A: `Machine` durability). redb
stays the default and nothing here runs unless `synapsed` is built with `--features sqlite-store` and started
with `SYNAPSE_MAILBOX_STORE=sqlite`. **Nothing here has been run against the pilot's mailbox.**

## What is copied

Everything the mailbox keeps, read out of redb through `MailTxn` and written to SQLite without translation:

- every role's queue in order, with leases (epoch and expiry), attempt counts and enqueue times, **including
  mail for roles that never claimed** and **the dead sets** (queues of the pseudo-role `dead:<role>`);
- the acked history that backs resend detection;
- the role epochs, so a restarted role never gets an epoch already issued;
- the sequence counter, so a new message never reuses a number.

A lease taken before the copy is still held after it (`after_the_copy_the_mailbox_carries_on_from_where_it_was`).
Bodies are copied as they are. Session tokens are not part of the mailbox; they are in memory and clients re-claim.

## How it is proved

`synapse::mailbox::migrate::copy_verified`: read the whole of redb, write the whole of it to SQLite in **one
transaction** (all or nothing), read the whole of SQLite back, and require the two reads to be **equal**. A
difference stops the start and names the first one (`a_lossy_destination_fails_verification` drops acked history
on purpose and is caught). redb is only read. The marker `mailbox.sqlite.migrated` is written (and synced) only
after the read-back is equal.

## What `synapsed` does at start (`SYNAPSE_MAILBOX_STORE=sqlite`)

| `mailbox.redb` | `mailbox.sqlite` | marker | result |
|---|---|---|---|
| absent | any | any | open SQLite as it is (fresh home, or already moved) |
| present | absent | any | copy, verify, write the marker, open SQLite |
| present | present | present | open SQLite; redb is kept and is now stale |
| present | present | absent | **refuse to start**, change nothing: either SQLite was made without a copy (a build from rc.109 to rc.113 run with the flag) or a copy was cut short, and only the operator knows which |

Opening redb takes its file lock, so a daemon still serving redb makes the copy fail rather than copy a moving
target. Run it with the old daemon stopped.

## Going back

Possible, and lossy: pointing `synapsed` at redb again serves the old file, which does not have anything accepted
since the move. There is no copy from SQLite to redb. The redb file is never deleted by Synapse.

## Not covered

- A power cut or kill during the copy: the destination is one transaction and the marker comes last, so the
  states are "no SQLite file", "an empty or complete SQLite file without a marker" (refused, above) or "complete
  with a marker". That the one transaction really is atomic across a power cut rests on PersistAnt's `Machine`
  verification (Hyper-V guest, ext4), not on a test of the copy itself.
- Size: the whole mailbox is held in memory twice while it is copied (bounded by `max_bytes`, 64 MiB per role by
  default).
- A mailbox that redb holds in a format older than the current one: opening it migrates it in place first, as it
  always did.
- Timing on a real pilot-sized mailbox.
