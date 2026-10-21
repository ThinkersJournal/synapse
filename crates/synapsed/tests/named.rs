// SPDX-License-Identifier: MIT OR Apache-2.0
//! The daemon serves the mailbox from the PersistAnt provider recorded in the home
//! (`Daemon::open_named`): a home written by the plain SQLite store is read back unchanged, and an
//! id that does not meet the mailbox's needs stops the start.
#![cfg(feature = "sqlite-store")]

use std::time::Duration;

use synapse::keystore::Keystore;
use synapse::mailbox::conformance as suite;
use synapse::mailbox::migrate::dump;
use synapse::mailbox::{MailConfig, Mailbox};
use synapse_mailbox_persistant::SqliteMailStore;
use synapse_mailbox_persistant::needs::{RegistryMailStore, StoreChoice, listing};
use synapsed::{Daemon, DaemonConfig, DaemonError};

fn config(home: &std::path::Path) -> DaemonConfig {
    DaemonConfig {
        home: home.to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    }
}

fn top_id() -> &'static str {
    listing(&synapse::mailbox::MailboxNeeds::MAILBOX).expect("a store qualifies")[0].id
}

#[test]
fn a_recorded_provider_opens_the_file_the_sqlite_store_wrote() {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let path = home.path().join("mailbox.sqlite");
    let (ids, t0) = (suite::Ids::new(), suite::t0());
    {
        let mut mb = Mailbox::open(
            SqliteMailStore::open(&path).unwrap(),
            MailConfig::default(),
            t0 - chrono::Duration::seconds(1),
        )
        .unwrap();
        ids.claim(&mut mb, "lane", t0);
        for i in 0..3 {
            mb.enqueue(suite::env(&format!("m{i}"), "lane@acct", b"hello"), t0)
                .unwrap();
        }
    }
    let before = dump(&SqliteMailStore::open(&path).unwrap()).unwrap();
    assert_eq!(before.messages(), 3, "control: the file holds mail");

    let choice = StoreChoice::new(top_id(), Some("mailbox.sqlite")).unwrap();
    drop(Daemon::open_named(&config(home.path()), &choice).expect("starts on the recorded store"));

    let after = dump(
        &RegistryMailStore::open_named(
            &choice.id,
            &path,
            &synapse::mailbox::MailboxNeeds::MAILBOX,
            Duration::from_secs(10),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(after, before, "the named store reads the same mailbox");
}

#[test]
fn an_id_that_does_not_meet_the_needs_stops_the_start() {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let choice = StoreChoice::new("memory", None).unwrap();
    let err = Daemon::open_named(&config(home.path()), &choice).err();
    assert!(matches!(err, Some(DaemonError::Store(_))), "{err:?}");
}
