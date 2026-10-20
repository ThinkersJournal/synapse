// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapsed --features sqlite-store` on a home that still holds a redb mailbox (board 229): the
//! mailbox is copied, the copy proved, a marker left, redb untouched; a second start does not copy
//! again; and a home where it is not known which store holds the mail is refused, not guessed at.
#![cfg(feature = "sqlite-store")]

use std::time::Duration;

use synapse::keystore::Keystore;
use synapse::mailbox::conformance as suite;
use synapse::mailbox::migrate::dump;
use synapse::mailbox::{MailConfig, Mailbox, RedbStore};
use synapsed::{Daemon, DaemonConfig, DaemonError, StoreKind};

fn config(home: &std::path::Path) -> DaemonConfig {
    DaemonConfig {
        home: home.to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    }
}

/// A home with an account and a redb mailbox holding a claim, queued mail and a lease.
fn home_with_redb() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let ids = suite::Ids::new();
    let t0 = suite::t0();
    let mut mb = Mailbox::open(
        RedbStore::open(&home.path().join("mailbox.redb")).unwrap(),
        MailConfig::default(),
        t0 - chrono::Duration::seconds(1),
    )
    .unwrap();
    let epoch = ids.claim(&mut mb, "lane", t0);
    for i in 0..3 {
        mb.enqueue(suite::env(&format!("m{i}"), "lane@acct", b"hello"), t0)
            .unwrap();
    }
    mb.fetch("lane@acct", epoch, 1, None, t0).unwrap();
    home
}

#[test]
fn the_first_sqlite_start_copies_the_redb_mailbox_and_leaves_it_alone() {
    let home = home_with_redb();
    let redb_path = home.path().join("mailbox.redb");
    let expected = dump(&RedbStore::open(&redb_path).unwrap()).unwrap();
    assert_eq!(expected.messages(), 3, "control: the source holds mail");

    drop(Daemon::open_with(&config(home.path()), StoreKind::Sqlite).expect("first start"));

    assert!(home.path().join("mailbox.sqlite").exists());
    let marker = std::fs::read_to_string(home.path().join("mailbox.sqlite.migrated")).unwrap();
    assert!(marker.contains("3 queued messages"), "{marker}");
    let copied = dump(
        &synapse_mailbox_persistant::SqliteMailStore::open(home.path().join("mailbox.sqlite"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(copied, expected, "the SQLite store holds what redb held");
    // Contents, not bytes: opening a redb file takes a lock and may touch its own header.
    assert_eq!(
        dump(&RedbStore::open(&redb_path).unwrap()).unwrap(),
        expected,
        "the redb mailbox is unchanged"
    );
}

#[test]
fn a_second_start_does_not_copy_again() {
    let home = home_with_redb();
    drop(Daemon::open_with(&config(home.path()), StoreKind::Sqlite).unwrap());
    let marker = home.path().join("mailbox.sqlite.migrated");
    let first = std::fs::metadata(&marker).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    // Mail accepted after the move lives only in SQLite; a second copy would lose it.
    {
        let store =
            synapse_mailbox_persistant::SqliteMailStore::open(home.path().join("mailbox.sqlite"))
                .unwrap();
        let mut mb = Mailbox::open(
            store,
            MailConfig::default(),
            suite::t0() - chrono::Duration::seconds(1),
        )
        .unwrap();
        mb.enqueue(suite::env("after", "lane@acct", b"new"), suite::t0())
            .unwrap();
    }
    drop(Daemon::open_with(&config(home.path()), StoreKind::Sqlite).expect("second start"));
    assert_eq!(
        std::fs::metadata(&marker).unwrap().modified().unwrap(),
        first
    );
    let held = dump(
        &synapse_mailbox_persistant::SqliteMailStore::open(home.path().join("mailbox.sqlite"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        held.messages(),
        4,
        "the message accepted after the move is still there"
    );
}

#[test]
fn two_stores_and_no_marker_is_refused_not_guessed() {
    let home = home_with_redb();
    // A SQLite store that was created without a copy (an rc.109 to rc.113 build run with the flag).
    drop(
        synapse_mailbox_persistant::SqliteMailStore::open(home.path().join("mailbox.sqlite"))
            .unwrap(),
    );
    let err = Daemon::open_with(&config(home.path()), StoreKind::Sqlite)
        .err()
        .expect("refused");
    assert!(matches!(err, DaemonError::Migration(_)), "{err}");
    assert!(err.to_string().contains("not known"), "{err}");
    assert!(!home.path().join("mailbox.sqlite.migrated").exists());
    // Control: the default store is unaffected by the SQLite file.
    drop(Daemon::open(&config(home.path())).expect("redb start"));
}
