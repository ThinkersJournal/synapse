// SPDX-License-Identifier: MIT OR Apache-2.0
//! One daemon per server-backed store (`lease.rs`), on SQLite so it runs everywhere: two openers of
//! one database, where the second must be refused. The control is the same two openers without a
//! lease, which both succeed; that is what the lease exists to stop.
use persistant_kv::{KvBackend, KvOnRelational};
use std::time::{Duration, Instant};
use synapse::mailbox::MailStore;
use synapse_mailbox_persistant::PersistantMailStore;

type Kv = KvOnRelational<persistant_sqlx::SqliteBackend>;

fn open_kv(path: &std::path::Path) -> Kv {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let db = persistant_sqlx::SqliteBackend::open(path).await.unwrap();
        KvOnRelational::open(db).await.unwrap()
    })
}

fn path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("mail.db");
    (dir, p)
}

#[test]
fn without_a_lease_two_openers_of_one_database_both_succeed() {
    let (_d, p) = path();
    let a = PersistantMailStore::new(open_kv(&p), "t").unwrap();
    let b = PersistantMailStore::new(open_kv(&p), "t").unwrap();
    drop((a, b));
}

#[test]
fn a_second_holder_of_the_lease_is_refused() {
    let (_d, p) = path();
    let mut first = PersistantMailStore::new(open_kv(&p), "t").unwrap();
    first.hold_lease().expect("the first holder takes it");
    let mut second = PersistantMailStore::new(open_kv(&p), "t").unwrap();
    let err = second.hold_lease().expect_err("the second is refused");
    assert!(err.to_string().contains("another process holds"), "{err}");
}

#[test]
fn a_clean_stop_frees_the_lease_at_once() {
    let (_d, p) = path();
    let mut first = PersistantMailStore::new(open_kv(&p), "t").unwrap();
    first.hold_lease().unwrap();
    drop(first);
    let mut second = PersistantMailStore::new(open_kv(&p), "t").unwrap();
    second.hold_lease().expect("free after a clean stop");
}

#[test]
fn a_lease_taken_from_under_the_holder_makes_writes_fail() {
    let (_d, p) = path();
    let mut store = PersistantMailStore::new(open_kv(&p), "t").unwrap();
    store.hold_lease().unwrap();
    store
        .write(&mut |_| Ok(()))
        .expect("holding it, a write works");
    // Another process deleting (or letting lapse) the key is what a lost lease looks like.
    let other = open_kv(&p);
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(other.delete("t/lease"))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if store.write(&mut |_| Ok(())).is_err() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "writes still succeed after the lease was taken"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
