// SPDX-License-Identifier: MIT OR Apache-2.0
//! A role-only keystore (WSL pilot): the role's keys are made where they are used, the account holder
//! issues the certificate for their public halves, and the account key never reaches the role's home.

use chrono::{Duration, Utc};
use std::path::Path;
use synapse::keystore::{Keystore, KeystoreError, load_role};

fn place_cert(home: &Path, role: &str, pem: &str) {
    Keystore::install_role_certificate(home, role, pem).expect("install");
}

/// An account home `a`, a role-only home `b` with `role` keys made there, and the certificate issued.
fn pair(role: &str, days: i64) -> (tempfile::TempDir, tempfile::TempDir) {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    Keystore::init_account(a.path(), "acct").unwrap();
    let pubs = Keystore::init_role(b.path(), "acct", role).unwrap();
    let pem = Keystore::open(a.path())
        .unwrap()
        .issue_role_certificate(role, pubs, Utc::now(), Duration::days(days))
        .unwrap();
    place_cert(b.path(), role, &pem);
    (a, b)
}

#[test]
fn init_role_makes_keys_without_an_account_key_and_is_repeatable() {
    let b = tempfile::tempdir().unwrap();
    let first = Keystore::init_role(b.path(), "acct", "lane-x").unwrap();
    let again = Keystore::init_role(b.path(), "acct", "lane-x").unwrap();
    assert_eq!(first, again, "a second init-role must not replace the keys");
    assert!(!b.path().join("account").join("account.key.pem").exists());
    assert!(matches!(
        Keystore::open(b.path()),
        Err(KeystoreError::NoAccount)
    ));
}

#[test]
fn init_role_refuses_a_home_that_holds_an_account_key() {
    let a = tempfile::tempdir().unwrap();
    Keystore::init_account(a.path(), "acct").unwrap();
    let got = Keystore::init_role(a.path(), "acct", "lane-x");
    assert!(
        matches!(got, Err(KeystoreError::AccountKeyPresent)),
        "init_role must refuse a home holding an account key"
    );
}

#[test]
fn an_issued_certificate_loads_and_chains_to_the_account_key() {
    let (a, b) = pair("lane-x", 8);
    let now = Utc::now();
    let id = Keystore::open_role_only(b.path())
        .unwrap()
        .role("lane-x", now)
        .unwrap();
    assert_eq!(id.global_id, "lane-x@acct");
    assert_eq!(id.not_after - id.not_before, Duration::days(8));
    assert_eq!(id.chain.len(), 1);
    let account = Keystore::open(a.path()).unwrap().account_public_key();
    assert!(id.chain[0].verify_signature(&account));
    assert_eq!(id.chain[0].may_delegate, 0);
}

#[test]
fn open_role_only_refuses_a_home_with_an_account_key() {
    let (a, _b) = pair("lane-x", 8);
    let got = Keystore::open_role_only(a.path());
    assert!(
        matches!(got, Err(KeystoreError::AccountKeyPresent)),
        "{:?}",
        got.err()
    );
}

#[test]
fn an_expired_certificate_is_refused_and_never_renewed() {
    let (_a, b) = pair("lane-x", 8);
    let store = Keystore::open_role_only(b.path()).unwrap();
    let cert = b.path().join("roles").join("lane-x").join("cert.pem");
    let before = std::fs::read(&cert).unwrap();
    let got = store.role("lane-x", Utc::now() + Duration::days(9));
    assert!(
        matches!(got, Err(KeystoreError::CertificateExpired)),
        "{:?}",
        got.err()
    );
    assert!(got_msg(&store).contains("ask the PM to re-issue"));
    // Inside the last 12 h a full keystore would renew; a role-only one must leave the file alone.
    store
        .role(
            "lane-x",
            Utc::now() + Duration::days(8) - Duration::hours(1),
        )
        .unwrap();
    assert_eq!(std::fs::read(&cert).unwrap(), before);
}

fn got_msg(store: &synapse::keystore::RoleOnlyKeystore) -> String {
    store
        .role("lane-x", Utc::now() + Duration::days(30))
        .err()
        .unwrap()
        .to_string()
}

#[test]
fn a_certificate_for_other_keys_or_none_is_refused() {
    let (a, b) = pair("lane-x", 8);
    let other = tempfile::tempdir().unwrap();
    let pubs = Keystore::init_role(other.path(), "acct", "lane-x").unwrap();
    let pem = Keystore::open(a.path())
        .unwrap()
        .issue_role_certificate("lane-x", pubs, Utc::now(), Duration::days(8))
        .unwrap();
    let got = Keystore::install_role_certificate(b.path(), "lane-x", &pem);
    assert!(
        matches!(got, Err(KeystoreError::Corrupt("role certificate"))),
        "a certificate for other keys must be refused as corrupt"
    );

    let c = tempfile::tempdir().unwrap();
    Keystore::init_role(c.path(), "acct", "lane-y").unwrap();
    let got = Keystore::open_role_only(c.path())
        .unwrap()
        .role("lane-y", Utc::now());
    assert!(
        matches!(got, Err(KeystoreError::NoRoleCertificate)),
        "{:?}",
        got.err()
    );
}

#[test]
fn validity_outside_one_to_thirty_days_is_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    Keystore::init_account(a.path(), "acct").unwrap();
    let pubs = Keystore::init_role(b.path(), "acct", "lane-x").unwrap();
    let store = Keystore::open(a.path()).unwrap();
    for days in [0, 31] {
        let got = store.issue_role_certificate("lane-x", pubs, Utc::now(), Duration::days(days));
        assert!(
            matches!(got, Err(KeystoreError::InvalidValidity)),
            "{days} days must be refused as an invalid validity"
        );
    }
}

#[test]
fn load_role_uses_whichever_keystore_the_home_is() {
    let (a, b) = pair("lane-x", 8);
    assert_eq!(
        load_role(b.path(), "lane-x", Utc::now()).unwrap().global_id,
        "lane-x@acct"
    );
    assert_eq!(
        load_role(a.path(), "other", Utc::now()).unwrap().global_id,
        "other@acct"
    );
}
