// SPDX-License-Identifier: MIT OR Apache-2.0
//! Crash safety of the redb mailbox under REAL process death (M4 PR2, spec §5).
//!
//! Each test sets up a prior state, then re-runs this test binary as a child that performs one
//! mailbox operation through a `CrashingStore`: the operation's changes are made inside the redb
//! write transaction and the child calls `std::process::abort()` before the commit. The parent
//! reopens the file and asserts the prior state survived. The control child commits first and
//! then aborts, and the parent must see the new state, which proves the harness can tell the two
//! apart (review focus 4).
#![cfg(feature = "mailbox-redb")]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chrono::{DateTime, Duration, Utc};
use synapse::mailbox::conformance as suite;
use synapse::mailbox::{MailConfig, MailError, MailStore, MailTxn, Mailbox, RedbStore};

const LANE: &str = "lane@acct";

/// Delegates to a `RedbStore`; once armed, the next write runs its operation inside the
/// transaction and then aborts the process before the transaction can commit.
struct CrashingStore {
    inner: RedbStore,
    armed: AtomicBool,
}

impl MailStore for CrashingStore {
    fn durability(&self) -> synapse::mailbox::DurabilityClass {
        self.inner.durability()
    }

    fn write(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        if !self.armed.load(Ordering::SeqCst) {
            return self.inner.write(f);
        }
        self.inner.write(&mut |txn| {
            f(txn)?;
            crash_point();
            std::process::abort() // inside the transaction: nothing is committed
        })
    }
}

/// Printed by a child immediately before it aborts at the intended point. Review I1: "the child
/// died" alone also holds for a child that panicked early (exit 101) and never reached its write.
const CRASH_POINT: &str = "SYNAPSE-CRASH-POINT-REACHED";

fn crash_point() {
    use std::io::Write;
    let mut err = std::io::stderr();
    let _ = writeln!(err, "{CRASH_POINT}");
    let _ = err.flush();
}

fn fresh_db() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "synapse-crash-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("mailbox.redb")
}

/// When the child opens its mailbox (after every claim the parent made).
fn child_now() -> DateTime<Utc> {
    suite::t0() + Duration::minutes(1)
}

fn open_at(path: &Path, now: DateTime<Utc>) -> Mailbox<RedbStore> {
    Mailbox::open(RedbStore::open(path).unwrap(), MailConfig::default(), now).expect("open")
}

/// Run this binary's `child_entry` with `op`. Asserts the child reached its intended crash point
/// (review I1), and returns its exit status.
fn run_child(op: &str, db: &Path, ids: &suite::Ids, epoch: u64) -> ExitStatus {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("SYNAPSE_CRASH_OP", op)
        .env("SYNAPSE_CRASH_DB", db)
        .env("SYNAPSE_CRASH_KEYS", ids.path())
        .env("SYNAPSE_CRASH_EPOCH", epoch.to_string())
        .output()
        .expect("spawn the child");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(CRASH_POINT),
        "child {op} died without reaching its crash point (status {:?}):
{stderr}",
        out.status
    );
    out.status
}

/// The child half. A no-op in a normal test run (the variable is unset).
#[test]
fn child_entry() {
    let Ok(op) = std::env::var("SYNAPSE_CRASH_OP") else {
        return;
    };
    let db = PathBuf::from(std::env::var("SYNAPSE_CRASH_DB").unwrap());
    let ids = suite::Ids::open_existing(
        Path::new(&std::env::var("SYNAPSE_CRASH_KEYS").unwrap()),
        100,
    );
    let epoch: u64 = std::env::var("SYNAPSE_CRASH_EPOCH")
        .unwrap()
        .parse()
        .unwrap();
    let now = child_now();
    let at = now + Duration::seconds(1);

    if op == "commit-then-abort" {
        let mut mb = open_at(&db, now);
        mb.enqueue(suite::env("ctl", LANE, b"c"), at)
            .expect("committed enqueue");
        crash_point();
        std::process::abort();
    }

    let store = CrashingStore {
        inner: RedbStore::open(&db).unwrap(),
        armed: AtomicBool::new(false),
    };
    let mut mb = Mailbox::open(store, MailConfig::default(), now).expect("open");
    mb.store().armed.store(true, Ordering::SeqCst);
    let _ = match op.as_str() {
        "enqueue" => mb.enqueue(suite::env("x", LANE, b"x"), at).map(|_| ()),
        "fetch" => mb.fetch(LANE, epoch, 10, None, at).map(|_| ()),
        "ack" => mb.ack(LANE, epoch, "x", at).map(|_| ()),
        "claim" => ids.try_claim(&mut mb, "lane", at).map(|_| ()),
        other => panic!("unknown crash op {other}"),
    };
    // Reaching here means the armed write never happened: fail loudly rather than exit cleanly.
    panic!("crash op {op} returned instead of dying inside its transaction");
}

/// Parent setup: claim `lane`, then run `prep`; returns the claimed epoch.
fn prepare(db: &Path, ids: &suite::Ids, prep: impl FnOnce(&mut Mailbox<RedbStore>, u64)) -> u64 {
    let mut mb = open_at(db, suite::t0() - Duration::seconds(1));
    let epoch = ids.claim(&mut mb, "lane", suite::t0());
    prep(&mut mb, epoch);
    epoch
}

fn queued_lease_epoch(db: &Path, id: &str) -> Option<Option<u64>> {
    let store = RedbStore::open(db).unwrap();
    let mut out = None;
    store
        .write(&mut |txn| {
            out = txn
                .queued(LANE, id)
                .map_err(MailError::Store)?
                .map(|s| s.lease.map(|l| l.epoch));
            Ok(())
        })
        .unwrap();
    out
}

#[test]
fn a_death_mid_enqueue_leaves_no_message() {
    let (db, ids) = (fresh_db(), suite::Ids::new());
    let epoch = prepare(&db, &ids, |_, _| {});
    assert!(
        !run_child("enqueue", &db, &ids, epoch).success(),
        "the child must die"
    );
    assert_eq!(
        queued_lease_epoch(&db, "x"),
        None,
        "the enqueue was not committed"
    );
}

#[test]
fn a_death_mid_fetch_leaves_no_lease() {
    let (db, ids) = (fresh_db(), suite::Ids::new());
    let epoch = prepare(&db, &ids, |mb, _| {
        mb.enqueue(suite::env("x", LANE, b"x"), suite::t0())
            .unwrap();
    });
    assert!(
        !run_child("fetch", &db, &ids, epoch).success(),
        "the child must die"
    );
    assert_eq!(
        queued_lease_epoch(&db, "x"),
        Some(None),
        "still queued, still unleased"
    );
}

#[test]
fn a_death_mid_ack_leaves_the_message_queued() {
    let (db, ids) = (fresh_db(), suite::Ids::new());
    let epoch = prepare(&db, &ids, |mb, epoch| {
        mb.enqueue(suite::env("x", LANE, b"x"), suite::t0())
            .unwrap();
        mb.fetch(LANE, epoch, 1, None, suite::t0()).unwrap();
    });
    assert!(
        !run_child("ack", &db, &ids, epoch).success(),
        "the child must die"
    );
    assert_eq!(
        queued_lease_epoch(&db, "x"),
        Some(Some(epoch)),
        "the message is still queued and still leased to the parent's epoch"
    );
}

#[test]
fn a_death_mid_claim_leaves_the_old_epoch() {
    let (db, ids) = (fresh_db(), suite::Ids::new());
    let epoch = prepare(&db, &ids, |_, _| {});
    assert!(
        !run_child("claim", &db, &ids, epoch).success(),
        "the child must die"
    );
    let later = child_now() + Duration::minutes(1);
    let mut mb = open_at(&db, later);
    let next = ids.claim(&mut mb, "lane", later + Duration::seconds(1));
    assert_eq!(
        next,
        epoch + 1,
        "the child's uncommitted epoch was never recorded"
    );
}

#[test]
fn the_control_commit_then_abort_keeps_the_write() {
    let (db, ids) = (fresh_db(), suite::Ids::new());
    let epoch = prepare(&db, &ids, |_, _| {});
    assert!(
        !run_child("commit-then-abort", &db, &ids, epoch).success(),
        "the child must die"
    );
    assert_eq!(
        queued_lease_epoch(&db, "ctl"),
        Some(None),
        "a write committed before death survives: the harness can tell commit from no-commit"
    );
}
