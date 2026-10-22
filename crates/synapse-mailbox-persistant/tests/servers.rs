// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mailbox on real PostgreSQL / MySQL / MariaDB servers, opened through PersistAnt's registry.
//!
//! Needs `SYNAPSE_TEST_DATABASE_URL` (PostgreSQL) or `SYNAPSE_TEST_MYSQL_URL` (MySQL, or MariaDB with
//! `SYNAPSE_TEST_MYSQL_FLAVOR=mariadb`). Without one these tests print a note and pass, **unless**
//! `SYNAPSE_REQUIRE_DATABASE` / `SYNAPSE_REQUIRE_MYSQL` is `1` (set by the CI jobs that run a service
//! container): a skipped test must not look like a green one there.
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use synapse::mailbox::conformance as suite;
use synapse::mailbox::{DurabilityClass, MailStore, MailboxNeeds};
use synapse_mailbox_persistant::needs::{RegistryMailStore, listing};

const BOUND: Duration = Duration::from_secs(20);
static N: AtomicU32 = AtomicU32::new(0);
/// One test at a time. These tests share a database that may have no tables yet, and every first
/// open runs `CREATE TABLE IF NOT EXISTS`, which PostgreSQL does not make safe to run concurrently
/// (CI run 39702075202 failed on a catalog unique violation). Serialising changes no assertion.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

/// `(id, variable)` of a configured server, `None` (skipped) when unset and not required.
fn server(url_var: &str, require: &str, id: &str) -> Option<(String, String)> {
    if std::env::var(url_var).is_ok() {
        return Some((id.to_string(), url_var.to_string()));
    }
    assert!(
        std::env::var(require).as_deref() != Ok("1"),
        "{require}=1 but {url_var} is not set"
    );
    eprintln!("skipped: {url_var} is not set");
    None
}

fn configured() -> Vec<(String, String)> {
    let mysql = std::env::var("SYNAPSE_TEST_MYSQL_FLAVOR").unwrap_or_else(|_| "mysql".into());
    [
        server(
            "SYNAPSE_TEST_DATABASE_URL",
            "SYNAPSE_REQUIRE_DATABASE",
            "postgres",
        ),
        server("SYNAPSE_TEST_MYSQL_URL", "SYNAPSE_REQUIRE_MYSQL", &mysql),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// A store in a namespace no other test touches, so runs share one database without sharing mail.
fn fresh(id: &str, var: &str) -> RegistryMailStore {
    let ns = format!(
        "t{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    );
    RegistryMailStore::open_named_url_in(id, var, &MailboxNeeds::MAILBOX, BOUND, &ns)
        .expect("opens")
}

#[test]
fn the_server_is_listed_for_the_mailbox_needs() {
    let _one = serial();
    for (id, _) in configured() {
        let ids: Vec<_> = listing(&MailboxNeeds::MAILBOX)
            .expect("a store qualifies")
            .iter()
            .map(|l| l.id)
            .collect();
        assert!(ids.contains(&id.as_str()), "{id} not in {ids:?}");
    }
}

#[test]
fn the_conformance_suite_passes_on_each_server() {
    let _one = serial();
    for (id, var) in configured() {
        let store = fresh(&id, &var);
        assert_eq!(store.durability(), DurabilityClass::Machine, "{id}");
        drop(store);
        suite::run_all(|| fresh(&id, &var));
    }
}

#[test]
fn a_second_daemon_on_the_same_database_is_refused() {
    let _one = serial();
    for (id, var) in configured() {
        let first = RegistryMailStore::open_named_url(&id, &var, &MailboxNeeds::MAILBOX, BOUND)
            .expect("the first daemon opens");
        let err = RegistryMailStore::open_named_url(&id, &var, &MailboxNeeds::MAILBOX, BOUND)
            .err()
            .expect("the second is refused");
        assert!(
            err.to_string().contains("another process holds"),
            "{id}: {err}"
        );
        drop(first);
        RegistryMailStore::open_named_url(&id, &var, &MailboxNeeds::MAILBOX, BOUND)
            .expect("free again after a clean stop");
    }
}

/// The safety property under contention: four daemons open one database at the same moment and
/// exactly one wins; the others are refused by the lease, never by a catalog race or a success.
#[test]
fn of_four_daemons_opening_one_database_at_once_exactly_one_wins() {
    let _one = serial();
    for (id, var) in configured() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (id, var, barrier) = (id.clone(), var.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    RegistryMailStore::open_named_url_in(
                        &id,
                        &var,
                        &MailboxNeeds::MAILBOX,
                        BOUND,
                        "contended",
                    )
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners = results.iter().filter(|r| r.is_ok()).count();
        let refusals = results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .filter(|e| e.to_string().contains("another process holds"))
            .count();
        assert_eq!(
            winners, 1,
            "{id}: {winners} daemons opened the database at once"
        );
        assert_eq!(
            refusals,
            3,
            "{id}: the other three are refused by the lease, got {:?}",
            results
                .iter()
                .map(|r| r.as_ref().err().map(ToString::to_string))
                .collect::<Vec<_>>()
        );
    }
}
