// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mailbox suite against the PersistAnt-backed SQLite store, plus the durability contract
//! (board 229): the durable open declares `Machine` and is accepted; the plain-default declaration
//! is `Process` and `Mailbox::open` refuses it; a reopen keeps acknowledged mail.
use chrono::Duration;
use persistant_kv::KvOnRelational;
use std::sync::Mutex;
use synapse::mailbox::conformance as suite;
use synapse::mailbox::{DurabilityClass, MailConfig, MailError, MailStore, Mailbox};
use synapse_mailbox_persistant::{PersistantMailStore, SqliteMailStore};

/// Keeps every directory alive until the process ends, as the suite requires.
static DIRS: Mutex<Vec<tempfile::TempDir>> = Mutex::new(Vec::new());

fn fresh_path() -> std::path::PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mail.db");
    DIRS.lock().unwrap().push(dir);
    path
}

fn durable() -> SqliteMailStore {
    SqliteMailStore::open(fresh_path()).unwrap()
}

#[test]
fn the_conformance_suite_passes() {
    suite::run_all(durable);
}

#[test]
fn the_durable_open_declares_machine_and_is_accepted() {
    assert_eq!(durable().durability(), DurabilityClass::Machine);
    suite::declares_the_needed_durability(durable);
}

/// `SqliteBackend::open` leaves `synchronous` unasserted: PersistAnt declares `Process`, so the
/// mailbox must refuse it even though the semantics pass.
#[test]
fn a_plain_sqlite_open_declares_process_and_is_refused() {
    let make = || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let kv = rt.block_on(async {
            let db = persistant_sqlx::SqliteBackend::open(fresh_path())
                .await
                .unwrap();
            KvOnRelational::open(db).await.unwrap()
        });
        PersistantMailStore::new(kv, "mail").unwrap()
    };
    let store = make();
    assert_eq!(store.durability(), DurabilityClass::Process);
    suite::a_store_declaring_less_is_refused(make);
    let err = Mailbox::open(store, MailConfig::default(), suite::t0())
        .err()
        .expect("refused");
    assert!(matches!(err, MailError::DurabilityTooWeak { .. }), "{err}");
}

#[test]
fn a_reopen_keeps_queue_acks_and_epochs() {
    let path = fresh_path();
    let ids = suite::Ids::new();
    let lane = "lane@acct";
    let first = {
        let mut mb = Mailbox::open(
            SqliteMailStore::open(&path).unwrap(),
            MailConfig::default(),
            suite::t0() - Duration::seconds(1),
        )
        .unwrap();
        let epoch = ids.claim(&mut mb, "lane", suite::t0());
        mb.enqueue(suite::env("acked", lane, b"a"), suite::t0())
            .unwrap();
        mb.enqueue(suite::env("kept", lane, b"k"), suite::t0())
            .unwrap();
        mb.fetch(lane, epoch, 1, None, suite::t0()).unwrap();
        mb.ack(lane, epoch, "acked", suite::t0()).unwrap();
        epoch
    };
    let later = suite::t0() + Duration::minutes(5);
    let mut mb = Mailbox::open(
        SqliteMailStore::open(&path).unwrap(),
        MailConfig::default(),
        later,
    )
    .unwrap();
    let next = ids.claim(&mut mb, "lane", later + Duration::seconds(1));
    assert!(next > first, "the epoch continues from the store");
    let got = mb
        .fetch(lane, next, 10, None, later + Duration::seconds(2))
        .unwrap();
    let kept: Vec<_> = got.iter().map(|d| d.envelope.message_id.as_str()).collect();
    assert_eq!(
        kept,
        ["kept"],
        "the unacked message survives, the acked one does not"
    );
}

#[cfg(unix)]
#[test]
fn the_store_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = fresh_path();
    drop(SqliteMailStore::open(&path).unwrap());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        SqliteMailStore::open(&path).is_err(),
        "a widened store file is refused"
    );
}

#[cfg(windows)]
#[test]
fn the_store_file_is_owner_only() {
    let path = fresh_path();
    drop(SqliteMailStore::open(&path).unwrap());
    assert!(
        SqliteMailStore::open(&path).is_ok(),
        "control: a fresh store reopens"
    );
    let status = std::process::Command::new("icacls")
        .arg(&path)
        .arg("/grant")
        .arg("*S-1-1-0:R")
        .stdout(std::process::Stdio::null())
        .status()
        .expect("icacls runs");
    assert!(status.success(), "icacls did not apply the grant");
    assert!(
        SqliteMailStore::open(&path).is_err(),
        "a store Everyone can read is refused"
    );
}

/// `synapsed` opens its store from inside `#[tokio::main]`; a `block_on` there would panic.
#[tokio::test]
async fn open_works_inside_a_tokio_runtime() {
    let store = SqliteMailStore::open(fresh_path()).unwrap();
    assert_eq!(store.durability(), DurabilityClass::Machine);
}

/// The mailbox keeps its role epochs in memory, so one database file has one serving process.
#[test]
fn a_second_open_of_a_live_store_is_refused() {
    let path = fresh_path();
    let first = SqliteMailStore::open(&path).unwrap();
    let err = SqliteMailStore::open(&path).err().expect("refused");
    assert!(err.0.contains("another process holds"), "{err}");
    drop(first);
    SqliteMailStore::open(&path).expect("control: free again once the first is dropped");
}
