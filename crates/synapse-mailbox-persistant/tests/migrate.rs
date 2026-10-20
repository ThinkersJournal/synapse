// SPDX-License-Identifier: MIT OR Apache-2.0
//! Migrating a redb mailbox to the PersistAnt SQLite store (board 229, adoption-fit gap 5): a
//! mailbox with live leases, unacked mail, acked history, a dead set and several role epochs is
//! copied, read back and compared, and what a client would see afterwards is checked by hand too.
use chrono::Duration;
use synapse::mailbox::conformance as suite;
use synapse::mailbox::migrate::{MigrateError, copy_verified, dump};
use synapse::mailbox::{MailConfig, MailError, MailStore, MailTxn, Mailbox, RedbStore};
use synapse_mailbox_persistant::SqliteMailStore;

const A: &str = "a@acct";
const B: &str = "b@acct";
const DEAD: &str = "dead-lane@acct";

fn fresh(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    (dir, path)
}

/// The state under test, built through the public mailbox: claims for three roles (so three
/// epochs), mail for two claimed roles and one that never claimed, two leased messages, one acked,
/// and one message dead-lettered.
fn busy_redb(path: &std::path::Path) -> (u64, u64) {
    let ids = suite::Ids::new();
    let config = MailConfig {
        max_deliveries: 3,
        ..MailConfig::default()
    };
    let mut mb = Mailbox::open(
        RedbStore::open(path).unwrap(),
        config,
        suite::t0() - Duration::seconds(1),
    )
    .unwrap();
    let t0 = suite::t0();
    let epoch_a = ids.claim(&mut mb, "a", t0);
    let epoch_b = ids.claim(&mut mb, "b", t0);
    let epoch_dead = ids.claim(&mut mb, "dead-lane", t0);
    for i in 0..5 {
        mb.enqueue(
            suite::env(&format!("a{i}"), A, format!("body a{i}").as_bytes()),
            t0,
        )
        .unwrap();
    }
    mb.enqueue(suite::env("b0", B, b"body b0"), t0).unwrap();
    mb.enqueue(suite::env("u0", "nobody@acct", b"waiting for a role"), t0)
        .unwrap();
    mb.fetch(A, epoch_a, 2, None, t0).unwrap(); // a0, a1 leased, still held after the copy
    mb.ack(A, epoch_a, "a0", t0).unwrap();
    mb.enqueue(suite::env("poison", DEAD, b"payload"), t0)
        .unwrap();
    for round in 0..3 {
        let at = t0 + Duration::seconds(61 * round);
        mb.fetch(DEAD, epoch_dead, 10, None, at).unwrap();
    }
    let at = t0 + Duration::seconds(61 * 3);
    assert!(mb.fetch(DEAD, epoch_dead, 10, None, at).unwrap().is_empty());
    assert_eq!(mb.dead_letters(DEAD, epoch_dead).unwrap().len(), 1);
    let _ = epoch_b;
    (epoch_a, epoch_dead)
}

#[test]
fn a_busy_redb_mailbox_is_copied_whole_and_proved() {
    let (_d1, redb_path) = fresh("mailbox.redb");
    let (_d2, sqlite_path) = fresh("mailbox.sqlite");
    busy_redb(&redb_path);
    let redb = RedbStore::open(&redb_path).unwrap();
    let sqlite = SqliteMailStore::open(&sqlite_path).unwrap();

    let copied = copy_verified(&redb, &sqlite).expect("copy");

    // What was copied is not nothing: the control for every equality below.
    assert_eq!(copied.queues[A].len(), 4, "a1..a4 queued, a0 acked");
    assert_eq!(copied.queues[B].len(), 1);
    assert_eq!(
        copied.queues["nobody@acct"].len(),
        1,
        "mail for a role that never claimed"
    );
    assert_eq!(
        copied.queues[&format!("dead:{DEAD}")].len(),
        1,
        "the dead set"
    );
    assert!(
        copied
            .acked
            .contains_key(&(A.to_string(), "a0".to_string()))
    );
    assert_eq!(copied.roles.roles.len(), 3);
    assert!(copied.seq >= 8);
    let leased: Vec<_> = copied.queues[A]
        .iter()
        .filter(|s| s.lease.is_some())
        .map(|s| s.envelope.message_id.as_str())
        .collect();
    assert_eq!(leased, ["a1"], "a1 is leased (a0 was acked)");

    // The copy is independent of the source and equal to it, read again from scratch.
    assert_eq!(dump(&sqlite).unwrap(), dump(&redb).unwrap());
}

/// What a daemon would do after the move: open the mailbox on the new store and carry on. Leases
/// still hold, epochs continue, a resend of an acked message is still a duplicate, sequence
/// numbers do not repeat.
#[test]
fn after_the_copy_the_mailbox_carries_on_from_where_it_was() {
    let (_d1, redb_path) = fresh("mailbox.redb");
    let (_d2, sqlite_path) = fresh("mailbox.sqlite");
    let (epoch_a, _) = busy_redb(&redb_path);
    {
        let redb = RedbStore::open(&redb_path).unwrap();
        let sqlite = SqliteMailStore::open(&sqlite_path).unwrap();
        copy_verified(&redb, &sqlite).unwrap();
    }
    let ids = suite::Ids::new();
    let t0 = suite::t0();
    let later = t0 + Duration::seconds(10);
    let mut mb = Mailbox::open(
        SqliteMailStore::open(&sqlite_path).unwrap(),
        MailConfig::default(),
        later,
    )
    .expect("the migrated store is accepted as Machine");

    // The same role claiming again gets the next epoch, not a reissued one.
    let epoch = ids.claim(&mut mb, "a", later + Duration::seconds(1));
    assert!(epoch > epoch_a, "epoch {epoch} continues after {epoch_a}");

    // a1's lease (taken before the copy, by the old epoch) is voided by the takeover; a2..a4 and a1
    // are all deliverable, in order, and a0 (acked before) is not.
    let got = mb
        .fetch(A, epoch, 10, None, later + Duration::seconds(2))
        .unwrap();
    let delivered: Vec<_> = got.iter().map(|d| d.envelope.message_id.as_str()).collect();
    assert_eq!(delivered, ["a1", "a2", "a3", "a4"]);

    // Resending an acked message is still recognised.
    assert_eq!(
        mb.enqueue(suite::env("a0", A, b"body a0"), later).unwrap(),
        synapse::mailbox::Enqueued::Duplicate
    );
    // A new message gets a sequence number after everything copied.
    let before = dump(mb.store()).unwrap().seq;
    mb.enqueue(suite::env("fresh", B, b"x"), later).unwrap();
    assert_eq!(dump(mb.store()).unwrap().seq, before + 1);
}

/// A destination that loses something is caught, by name, and the source is left as it was.
#[test]
fn a_lossy_destination_fails_verification() {
    struct DropsAcks(SqliteMailStore);
    struct NoAcks<'a>(&'a mut dyn MailTxn);
    impl MailTxn for NoAcks<'_> {
        fn stats(&self, r: &str) -> Result<(usize, u64), synapse::mailbox::StoreError> {
            self.0.stats(r)
        }
        fn scan(
            &self,
            r: &str,
            v: &mut dyn FnMut(&synapse::mailbox::Stored) -> bool,
        ) -> Result<(), synapse::mailbox::StoreError> {
            self.0.scan(r, v)
        }
        fn queued(
            &self,
            r: &str,
            i: &str,
        ) -> Result<Option<synapse::mailbox::Stored>, synapse::mailbox::StoreError> {
            self.0.queued(r, i)
        }
        fn put(
            &mut self,
            r: &str,
            s: synapse::mailbox::Stored,
        ) -> Result<(), synapse::mailbox::StoreError> {
            self.0.put(r, s)
        }
        fn remove(&mut self, r: &str, i: &str) -> Result<(), synapse::mailbox::StoreError> {
            self.0.remove(r, i)
        }
        fn acked_at(
            &self,
            r: &str,
            i: &str,
        ) -> Result<Option<chrono::DateTime<chrono::Utc>>, synapse::mailbox::StoreError> {
            self.0.acked_at(r, i)
        }
        fn record_ack(
            &mut self,
            _: &str,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), synapse::mailbox::StoreError> {
            Ok(()) // the loss: an acked entry is silently not written
        }
        fn sweep_acked(
            &mut self,
            b: chrono::DateTime<chrono::Utc>,
        ) -> Result<usize, synapse::mailbox::StoreError> {
            self.0.sweep_acked(b)
        }
        fn next_seq(&mut self) -> Result<u64, synapse::mailbox::StoreError> {
            self.0.next_seq()
        }
        fn roles(&self) -> Result<synapse::roles::RolesState, synapse::mailbox::StoreError> {
            self.0.roles()
        }
        fn set_roles(
            &mut self,
            s: &synapse::roles::RolesState,
        ) -> Result<(), synapse::mailbox::StoreError> {
            self.0.set_roles(s)
        }
        fn queue_roles(&self) -> Result<Vec<String>, synapse::mailbox::StoreError> {
            self.0.queue_roles()
        }
        fn all_acked(
            &self,
        ) -> Result<
            Vec<(String, String, chrono::DateTime<chrono::Utc>)>,
            synapse::mailbox::StoreError,
        > {
            self.0.all_acked()
        }
        fn seq_counter(&self) -> Result<u64, synapse::mailbox::StoreError> {
            self.0.seq_counter()
        }
        fn set_seq_counter(&mut self, v: u64) -> Result<(), synapse::mailbox::StoreError> {
            self.0.set_seq_counter(v)
        }
    }
    impl MailStore for DropsAcks {
        fn durability(&self) -> synapse::mailbox::DurabilityClass {
            self.0.durability()
        }
        fn write(
            &self,
            f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
        ) -> Result<(), MailError> {
            self.0.write(&mut |txn| f(&mut NoAcks(txn)))
        }
    }

    let (_d1, redb_path) = fresh("mailbox.redb");
    let (_d2, sqlite_path) = fresh("mailbox.sqlite");
    busy_redb(&redb_path);
    let redb = RedbStore::open(&redb_path).unwrap();
    let before = dump(&redb).unwrap();
    let lossy = DropsAcks(SqliteMailStore::open(&sqlite_path).unwrap());
    match copy_verified(&redb, &lossy) {
        Err(MigrateError::Mismatch(what)) => assert!(what.contains("acked"), "{what}"),
        other => panic!("a store that loses acked history passed verification: {other:?}"),
    }
    assert_eq!(dump(&redb).unwrap(), before, "the source is only read");
    // And the control: the honest store passes the same check.
    let (_d3, honest_path) = fresh("honest.sqlite");
    copy_verified(&redb, &SqliteMailStore::open(&honest_path).unwrap()).expect("honest copy");
}
