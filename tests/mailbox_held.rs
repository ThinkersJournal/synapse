// SPDX-License-Identifier: MIT OR Apache-2.0
//! The fetch-scan slice (spec `docs/superpowers/specs/2026-10-09-fetch-scan.md`): the redb store
//! keeps a fixed-width `leases` row per held message, so `fetch` decides which messages are free
//! without decoding their JSON metadata. These tests pin that the rows stay equal to the stored
//! leases, that `fetch` still agrees with `MemoryStore`, and that the one-time migration of an
//! rc.26 database is atomic, idempotent and refuses a format it does not know.
#![cfg(feature = "mailbox-redb")]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Duration, Utc};
use synapse::mailbox::conformance as suite;
use synapse::mailbox::{MailConfig, MailStore, Mailbox, MemoryStore, RedbStore};

const ADDR: &str = "lane@acct";

fn fresh_path() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "synapse-held-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("mailbox.redb")
}

fn mailbox(path: &std::path::Path, now: DateTime<Utc>) -> Mailbox<RedbStore> {
    let store = RedbStore::open(path).expect("open");
    Mailbox::open(store, MailConfig::default(), now - Duration::seconds(1)).expect("mailbox")
}

/// A tiny deterministic generator, so a failure replays.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % n
    }
}

/// The oracle: a random run of enqueue, fetch, ack, time passing and takeover gives the same
/// deliveries from `MemoryStore` (which filters in the default `scan_free`) and from `RedbStore`.
/// The `leases` rows must also equal the leases the run left in place.
#[test]
fn fetch_agrees_with_the_memory_store_and_held_rows_track_leases() {
    for seed in 0..4u64 {
        let ids = suite::Ids::new();
        let path = fresh_path();
        let mut redb = mailbox(&path, suite::t0());
        let mut mem = Mailbox::open_volatile(
            MemoryStore::default(),
            MailConfig::default(),
            suite::t0() - Duration::seconds(1),
        )
        .unwrap();
        let mut now = suite::t0();
        let mut epoch_r = ids.claim(&mut redb, "lane", now);
        let mut epoch_m = ids.claim(&mut mem, "lane", now);
        let mut rng = Lcg(seed + 1);
        let mut next_id = 0u32;
        let mut live_ids: BTreeSet<String> = BTreeSet::new();
        for step in 0..400 {
            match rng.next(10) {
                0..=3 => {
                    let id = format!("m{next_id}");
                    next_id += 1;
                    let e = suite::env(&id, ADDR, b"body");
                    redb.enqueue(e.clone(), now).unwrap();
                    mem.enqueue(e, now).unwrap();
                    live_ids.insert(id);
                }
                4..=6 => {
                    let max = 1 + rng.next(3) as usize;
                    let lease = Duration::seconds(5 + rng.next(20) as i64);
                    let a = redb.fetch(ADDR, epoch_r, max, Some(lease), now).unwrap();
                    let b = mem.fetch(ADDR, epoch_m, max, Some(lease), now).unwrap();
                    let ids_a: Vec<_> = a
                        .iter()
                        .map(|d| (&d.envelope.message_id, d.attempts))
                        .collect();
                    let ids_b: Vec<_> = b
                        .iter()
                        .map(|d| (&d.envelope.message_id, d.attempts))
                        .collect();
                    assert_eq!(ids_a, ids_b, "seed {seed} step {step}: fetch differs");
                }
                7 => {
                    if let Some(id) = live_ids
                        .iter()
                        .nth(rng.next(live_ids.len().max(1) as u64) as usize)
                        .cloned()
                    {
                        let a = redb.ack(ADDR, epoch_r, &id, now);
                        let b = mem.ack(ADDR, epoch_m, &id, now);
                        assert_eq!(a.is_ok(), b.is_ok(), "seed {seed} step {step}: ack differs");
                        if a.is_ok() {
                            live_ids.remove(&id);
                        }
                    }
                }
                8 => now += Duration::seconds(1 + rng.next(12) as i64),
                _ => {
                    if rng.next(4) == 0 {
                        epoch_r = ids.claim(&mut redb, "lane", now);
                        epoch_m = ids.claim(&mut mem, "lane", now);
                    }
                }
            }
            let (da, db) = (redb.depths(now).unwrap(), mem.depths(now).unwrap());
            assert_eq!(da, db, "seed {seed} step {step}: depths differ");
        }
        // Rows == leases. The MemoryStore's own view of "has a lease" is the expectation: every
        // stored message with a lease (expired or not) has exactly one row.
        let expected = {
            let mut n = 0usize;
            mem.store()
                .write(&mut |txn| {
                    txn.scan_leases(ADDR, &mut |_, lease| n += usize::from(lease.is_some()))
                        .map_err(synapse::mailbox::MailError::Store)
                })
                .unwrap();
            n
        };
        drop(redb);
        let store = RedbStore::open(&path).unwrap();
        assert_eq!(
            store.held_rows().unwrap(),
            expected,
            "seed {seed}: leases rows != stored leases"
        );
    }
}

/// An rc.26 database has no `leases` rows and no format stamp. Opening it rebuilds the rows in
/// one transaction, and `fetch` then skips the held messages.
#[test]
fn an_rc26_database_is_migrated_on_open() {
    let ids = suite::Ids::new();
    let path = fresh_path();
    let now = suite::t0();
    let mut mb = mailbox(&path, now);
    let epoch = ids.claim(&mut mb, "lane", now);
    for i in 0..6 {
        mb.enqueue(suite::env(&format!("m{i}"), ADDR, b"x"), now)
            .unwrap();
    }
    mb.fetch(ADDR, epoch, 3, None, now).unwrap();
    drop(mb);
    strip_to_rc26(&path);

    let store = RedbStore::open(&path).expect("reopen migrates");
    assert_eq!(
        store.held_rows().unwrap(),
        3,
        "three held messages need three rows"
    );
    let mut mb = Mailbox::open(store, MailConfig::default(), now).unwrap();
    let got = mb.fetch(ADDR, epoch, 10, None, now).unwrap();
    let got: Vec<_> = got.iter().map(|d| d.envelope.message_id.as_str()).collect();
    assert_eq!(got, ["m3", "m4", "m5"], "the held three must be skipped");
}

/// Opening twice changes nothing: the second open sees the stamp and rebuilds nothing.
#[test]
fn migration_is_idempotent() {
    let ids = suite::Ids::new();
    let path = fresh_path();
    let now = suite::t0();
    let mut mb = mailbox(&path, now);
    let epoch = ids.claim(&mut mb, "lane", now);
    for i in 0..4 {
        mb.enqueue(suite::env(&format!("m{i}"), ADDR, b"x"), now)
            .unwrap();
    }
    mb.fetch(ADDR, epoch, 2, None, now).unwrap();
    drop(mb);
    strip_to_rc26(&path);
    for _ in 0..3 {
        let store = RedbStore::open(&path).unwrap();
        assert_eq!(store.held_rows().unwrap(), 2);
        assert_eq!(store.format().unwrap(), Some(2));
    }
}

/// A store stamped with a format newer than this binary knows is refused, not guessed at.
#[test]
fn a_newer_format_is_refused_with_a_clear_error() {
    let path = fresh_path();
    drop(RedbStore::open(&path).unwrap());
    stamp(&path, Some(99));
    let err = RedbStore::open(&path).err().expect("must refuse");
    let text = err.to_string();
    assert!(
        text.contains("format 99") && text.contains("newer"),
        "unclear error: {text}"
    );
    // Control: the same file with the known stamp opens.
    stamp(&path, Some(2));
    RedbStore::open(&path).expect("known format opens");
}

/// Remove the format stamp and every `leases` row, leaving what an rc.26 binary wrote.
fn strip_to_rc26(path: &std::path::Path) {
    stamp(path, None);
    let db = redb::Database::open(path).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let def: redb::TableDefinition<(&str, u64), (u64, i64)> =
            redb::TableDefinition::new("leases");
        let mut t = txn.open_table(def).unwrap();
        t.retain(|_, _| false).unwrap();
    }
    txn.commit().unwrap();
}

fn stamp(path: &std::path::Path, to: Option<u64>) {
    let db = redb::Database::open(path).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let def: redb::TableDefinition<&str, u64> = redb::TableDefinition::new("counters");
        let mut t = txn.open_table(def).unwrap();
        match to {
            Some(v) => drop(t.insert("format", v).unwrap()),
            None => drop(t.remove("format").unwrap()),
        }
    }
    txn.commit().unwrap();
}

/// The point of the slice: with most of a queue held, `fetch(max=1)` decodes only the few rows it
/// has to look at, not every held row. (The decoded lease stays the authority, so a wrong `leases`
/// row cannot be caught by the delivery oracle; only this count catches it.)
#[test]
fn fetch_skips_held_messages_without_decoding_them() {
    let ids = suite::Ids::new();
    let path = fresh_path();
    let now = suite::t0();
    let mut mb = mailbox(&path, now);
    let epoch = ids.claim(&mut mb, "lane", now);
    for i in 0..100 {
        mb.enqueue(suite::env(&format!("m{i}"), ADDR, b"x"), now)
            .unwrap();
    }
    mb.fetch(ADDR, epoch, 90, None, now).unwrap();
    let before = mb.store().meta_decodes();
    let got = mb.fetch(ADDR, epoch, 1, None, now).unwrap();
    assert_eq!(got[0].envelope.message_id, "m90");
    let decoded = mb.store().meta_decodes() - before;
    assert_eq!(
        decoded, 1,
        "only the one free message may be decoded, not the 90 held"
    );
    // Control: once their leases expire the held messages are candidates again, and are decoded.
    let later = now + Duration::seconds(120);
    let before = mb.store().meta_decodes();
    mb.fetch(ADDR, epoch, 1, None, later).unwrap();
    assert_eq!(
        mb.store().meta_decodes() - before,
        1,
        "stops at the first free message"
    );
}
