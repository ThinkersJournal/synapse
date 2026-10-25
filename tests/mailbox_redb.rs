// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mailbox suite (M4) run against `RedbStore`, plus durability and storage-layout checks.
#![cfg(feature = "mailbox-redb")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Duration;
use synapse::mailbox::conformance as suite;
use synapse::mailbox::{
    Enqueued, Lease, MailConfig, MailError, MailStore, Mailbox, RedbStore, Stored,
};

/// A fresh, never-reused store path in its own directory (the directory is left behind in the
/// temp dir on purpose: a store must outlive the factory closure that the suite calls).
fn fresh_path() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "synapse-redb-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("mailbox.redb")
}

fn fresh() -> RedbStore {
    RedbStore::open(&fresh_path()).expect("open a fresh store")
}

macro_rules! cases {
    ($($name:ident),* $(,)?) => {
        $( #[test] fn $name() { suite::$name(fresh); } )*
    };
}

cases!(
    enqueue_then_fetch_leases_and_hides,
    an_expired_lease_redelivers_in_order,
    ack_removes_for_good_and_a_resend_is_a_duplicate,
    a_duplicate_while_queued_is_not_queued_twice,
    a_superseded_epoch_cannot_fetch_or_ack,
    a_takeover_frees_the_old_leases_at_once,
    only_the_lease_holder_acks,
    ack_is_idempotent,
    the_bound_refuses_by_count_and_by_bytes_and_keeps_the_queue,
    sweep_deletes_old_acked_history_never_queued_mail,
    a_lease_outside_the_range_is_refused,
    mail_waits_for_a_role_that_has_not_claimed_yet,
    claims_are_written_through_the_store,
    role_liveness_is_written_through_the_store,
    depths_count_queued_and_leased_per_role,
    an_expired_or_superseded_lease_counts_as_queued,
    fetch_excluding_skips_the_named_messages_and_leaves_them_unleased,
    fetch_excluding_counts_delivered_messages_not_skipped_ones,
    a_failed_write_changes_nothing,
    a_message_leased_max_deliveries_times_goes_dead_and_is_kept,
    a_full_dead_set_keeps_the_message_queued,
    a_dead_message_can_be_requeued,
);

const LANE: &str = "lane@acct";

fn queue_ids(store: &RedbStore, role: &str) -> Vec<String> {
    let mut ids = Vec::new();
    store
        .write(&mut |txn| {
            ids.clear();
            txn.scan(role, &mut |s| {
                ids.push(s.envelope.message_id.clone());
                true
            })
            .map_err(MailError::Store)
        })
        .unwrap();
    ids
}

#[test]
fn a_reopen_keeps_queue_acks_and_epochs() {
    let path = fresh_path();
    let ids = suite::Ids::new();
    let first = {
        let mut mb = Mailbox::open(
            RedbStore::open(&path).unwrap(),
            MailConfig::default(),
            suite::t0() - Duration::seconds(1),
        )
        .unwrap();
        let epoch = ids.claim(&mut mb, "lane", suite::t0());
        mb.enqueue(suite::env("acked", LANE, b"a"), suite::t0())
            .unwrap();
        mb.enqueue(suite::env("kept", LANE, b"k"), suite::t0())
            .unwrap();
        mb.fetch(LANE, epoch, 1, None, suite::t0()).unwrap();
        mb.ack(LANE, epoch, "acked", suite::t0()).unwrap();
        epoch
    }; // dropped: the database file is closed

    let later = suite::t0() + Duration::minutes(5);
    let mut mb = Mailbox::open(
        RedbStore::open(&path).unwrap(),
        MailConfig::default(),
        later,
    )
    .expect("reopen");
    let next = ids.claim(&mut mb, "lane", later + Duration::seconds(1));
    assert_eq!(next, first + 1, "epochs continue across a reopen");
    let got = mb
        .fetch(LANE, next, 10, None, later + Duration::seconds(1))
        .unwrap();
    assert_eq!(
        got.iter()
            .map(|d| d.envelope.message_id.as_str())
            .collect::<Vec<_>>(),
        ["kept"]
    );
    assert_eq!(
        mb.enqueue(suite::env("acked", LANE, b"a"), later).unwrap(),
        Enqueued::Duplicate,
        "acked history survives a reopen"
    );
}

#[test]
fn stats_agree_with_a_scan_after_mixed_operations() {
    let store = fresh();
    let stored = |id: &str, seq: u64, body: &[u8]| Stored {
        envelope: suite::env(id, LANE, body),
        seq,
        enqueued_at: suite::t0(),
        lease: None,
        attempts: 0,
    };
    store
        .write(&mut |txn| {
            txn.put(LANE, stored("a", 1, b"aaaa"))
                .map_err(MailError::Store)?;
            txn.put(LANE, stored("b", 2, b"bb"))
                .map_err(MailError::Store)?;
            txn.put(LANE, stored("c", 3, b"c"))
                .map_err(MailError::Store)?;
            Ok(())
        })
        .unwrap();
    // An update of an existing id must not change the totals.
    store
        .write(&mut |txn| {
            let mut b = stored("b", 2, b"bb");
            b.attempts = 3;
            txn.put(LANE, b).map_err(MailError::Store)
        })
        .unwrap();
    store
        .write(&mut |txn| txn.remove(LANE, "a").map_err(MailError::Store))
        .unwrap();
    // A failed transaction changes nothing.
    let _ = store.write(&mut |txn| {
        txn.put(LANE, stored("d", 4, b"dddddd"))
            .map_err(MailError::Store)?;
        Err(MailError::MailboxFull)
    });

    let mut stats = (0, 0);
    let mut scanned = (0usize, 0u64);
    store
        .write(&mut |txn| {
            stats = txn.stats(LANE).map_err(MailError::Store)?;
            scanned = (0, 0);
            txn.scan(LANE, &mut |s| {
                scanned.0 += 1;
                scanned.1 += s.envelope.body.len() as u64;
                true
            })
            .map_err(MailError::Store)
        })
        .unwrap();
    assert_eq!(stats, scanned, "stats() must agree with the queue");
    assert_eq!(stats, (2, 3), "b (2 bytes) and c (1 byte) remain");
    assert_eq!(queue_ids(&store, LANE), ["b", "c"]);
}

#[test]
fn a_lease_update_does_not_rewrite_the_body() {
    let store = fresh();
    let mut s = Stored {
        envelope: suite::env("m1", LANE, b"body"),
        seq: 1,
        enqueued_at: suite::t0(),
        lease: None,
        attempts: 0,
    };
    store
        .write(&mut |txn| txn.put(LANE, s.clone()).map_err(MailError::Store))
        .unwrap();
    let after_insert = store.body_writes();
    s.lease = Some(Lease {
        epoch: 1,
        until: suite::t0() + Duration::seconds(60),
    });
    s.attempts = 1;
    store
        .write(&mut |txn| txn.put(LANE, s.clone()).map_err(MailError::Store))
        .unwrap();
    assert_eq!(
        store.body_writes(),
        after_insert,
        "a lease update rewrote the body"
    );
    let mut seen = None;
    store
        .write(&mut |txn| {
            seen = txn.queued(LANE, "m1").map_err(MailError::Store)?;
            Ok(())
        })
        .unwrap();
    let seen = seen.expect("queued");
    assert_eq!(seen.envelope.body, b"body");
    assert_eq!(seen.attempts, 1);
    assert!(seen.lease.is_some());
}

#[test]
fn a_failed_write_leaves_the_file_unchanged() {
    let path = fresh_path();
    {
        let store = RedbStore::open(&path).unwrap();
        let failed = store.write(&mut |txn| {
            let seq = txn.next_seq().map_err(MailError::Store)?;
            txn.put(
                LANE,
                Stored {
                    envelope: suite::env("m1", LANE, b"x"),
                    seq,
                    enqueued_at: suite::t0(),
                    lease: None,
                    attempts: 0,
                },
            )
            .map_err(MailError::Store)?;
            Err(MailError::MailboxFull)
        });
        assert_eq!(failed, Err(MailError::MailboxFull));
    }
    let store = RedbStore::open(&path).unwrap();
    let mut stats = None;
    let mut seq = None;
    store
        .write(&mut |txn| {
            stats = Some(txn.stats(LANE).map_err(MailError::Store)?);
            seq = Some(txn.next_seq().map_err(MailError::Store)?);
            Err(MailError::NotFound) // read-only: abort
        })
        .unwrap_err();
    assert_eq!(
        stats,
        Some((0, 0)),
        "the aborted put did not survive a reopen"
    );
    assert_eq!(
        seq,
        Some(1),
        "the aborted next_seq did not advance the counter"
    );
}

#[cfg(unix)]
#[test]
fn the_store_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = fresh_path();
    drop(RedbStore::open(&path).unwrap());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        RedbStore::open(&path).is_err(),
        "a widened store file is refused"
    );
}

#[cfg(windows)]
#[test]
fn the_store_file_is_owner_only() {
    let path = fresh_path();
    drop(RedbStore::open(&path).unwrap());
    assert!(
        RedbStore::open(&path).is_ok(),
        "control: a fresh store reopens"
    );
    grant_everyone_read(&path);
    assert!(
        RedbStore::open(&path).is_err(),
        "a store Everyone can read is refused"
    );
}

#[cfg(windows)]
fn grant_everyone_read(path: &std::path::Path) {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .arg("/grant")
        .arg("*S-1-1-0:R")
        .stdout(std::process::Stdio::null())
        .status()
        .expect("icacls runs");
    assert!(status.success(), "icacls did not apply the grant");
}

/// Review I2: an update of an existing id keeps the stored body, so it must also keep the stored
/// body length; otherwise STATS (the max_bytes bound) drifts. MemoryStore and RedbStore must agree.
#[test]
fn an_update_with_another_body_keeps_the_stored_body_and_the_stats() {
    let store = fresh();
    let stored = |id: &str, body: &[u8]| Stored {
        envelope: suite::env(id, LANE, body),
        seq: 1,
        enqueued_at: suite::t0(),
        lease: None,
        attempts: 0,
    };
    store
        .write(&mut |txn| {
            txn.put(LANE, stored("m", b"four"))
                .map_err(MailError::Store)?;
            let mut other = stored("n", b"xx");
            other.seq = 2;
            txn.put(LANE, other).map_err(MailError::Store)
        })
        .unwrap();
    store
        .write(&mut |txn| {
            txn.put(LANE, stored("m", b"ten-bytes!"))
                .map_err(MailError::Store)
        })
        .unwrap();
    store
        .write(&mut |txn| txn.remove(LANE, "m").map_err(MailError::Store))
        .unwrap();
    let mut stats = None;
    store
        .write(&mut |txn| {
            stats = Some(txn.stats(LANE).map_err(MailError::Store)?);
            Ok(())
        })
        .unwrap();
    assert_eq!(stats, Some((1, 2)), "only n (2 bytes) remains");
}

/// S-1: `list` polls depths every few seconds, so counting a queue must never load its bodies (a
/// role may hold up to `max_bytes` of them).
#[test]
fn depths_read_no_body() {
    let ids = suite::Ids::new();
    let mut mb = suite::open(fresh());
    ids.claim(&mut mb, "lane", suite::t0());
    mb.enqueue(suite::env("m1", LANE, b"one"), suite::t0())
        .unwrap();
    mb.enqueue(suite::env("m2", LANE, b"two"), suite::t0())
        .unwrap();
    let before = mb.store().body_reads();
    assert_eq!(mb.depths(suite::t0()).unwrap()[LANE].queued, 2);
    assert_eq!(mb.store().body_reads(), before, "depths loaded a body");
    // Control: a scan of the same queue does load them.
    mb.store()
        .write(&mut |txn| txn.scan(LANE, &mut |_| true).map_err(MailError::Store))
        .unwrap();
    assert_eq!(mb.store().body_reads(), before + 2);
}

/// Perf follow-up: `fetch` scans past a role's leased messages, and must not load their bodies. At 10k
/// messages with half leased the scan cost 46 ms p50 on one laptop (`benches/mailbox_depth_cost.rs`).
#[test]
fn fetch_loads_only_the_bodies_it_hands_out() {
    let ids = suite::Ids::new();
    let mut mb = suite::open(fresh());
    let epoch = ids.claim(&mut mb, "lane", suite::t0());
    for n in 0..6 {
        mb.enqueue(suite::env(&format!("m{n}"), LANE, b"body"), suite::t0())
            .unwrap();
    }
    // Lease the first four (a long lease, so they stay leased).
    let held = mb
        .fetch(LANE, epoch, 4, Some(Duration::seconds(60)), suite::t0())
        .unwrap();
    assert_eq!(held.len(), 4);
    let before = mb.store().body_reads();
    let got = mb
        .fetch(LANE, epoch, 1, Some(Duration::seconds(60)), suite::t0())
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].envelope.message_id, "m4");
    assert_eq!(
        mb.store().body_reads() - before,
        1,
        "fetch loaded the bodies of messages it skipped"
    );
}

/// Review of #99: `fetch` must decode META rows as it visits them and stop at `max`, so a malformed row
/// *after* enough free messages cannot fail a fetch that has already found what it needs.
#[test]
fn fetch_stops_at_max_before_reading_a_malformed_row_after_it() {
    let path = fresh_path();
    let ids = suite::Ids::new();
    {
        let mut mb = suite::open(RedbStore::open(&path).unwrap());
        ids.claim(&mut mb, "lane", suite::t0());
        for n in 0..3 {
            mb.enqueue(suite::env(&format!("m{n}"), LANE, b"body"), suite::t0())
                .unwrap();
        }
    }
    // A META row that is not JSON, ordered after every real one.
    {
        let db = redb::Database::open(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let meta: redb::TableDefinition<(&str, u64), &[u8]> =
                redb::TableDefinition::new("meta");
            let mut t = txn.open_table(meta).unwrap();
            t.insert((LANE, u64::MAX - 1), b"not json".as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
    }
    let mut mb = suite::open(RedbStore::open(&path).unwrap());
    let epoch = ids.claim(&mut mb, "lane", suite::t0());
    let got = mb
        .fetch(LANE, epoch, 2, Some(Duration::seconds(60)), suite::t0())
        .expect("fetch found two free messages before the bad row");
    let got: Vec<&str> = got.iter().map(|d| d.envelope.message_id.as_str()).collect();
    assert_eq!(got, ["m0", "m1"]);
    // Control: asking for more than exist does reach the bad row, so the row really is malformed.
    assert!(
        mb.fetch(LANE, epoch, 10, Some(Duration::seconds(60)), suite::t0())
            .is_err(),
        "the injected row should be undecodable"
    );
}

/// Board 229: the redb store declares `Machine` and `Mailbox::open` accepts it.
#[test]
fn redb_declares_the_needed_durability() {
    suite::declares_the_needed_durability(|| RedbStore::open(&fresh_path()).unwrap());
}
