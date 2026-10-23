// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared-state permissions (design: docs/superpowers/specs/2026-10-23-shared-state-design.md, S2):
//! every role holds `state-write`; `state-read-all`, `state-admin` and `state-derive` are granted by
//! the account holder and reach the role's certificate.

use chrono::{Duration, TimeZone, Utc};
use synapse::certificate::{Permission, chain_from_pem};
use synapse::keystore::Keystore;

fn t0() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 23, 12, 0, 0).unwrap()
}

fn names(permissions: &[Permission]) -> Vec<String> {
    permissions.iter().map(Permission::as_str).collect()
}

fn store() -> (tempfile::TempDir, Keystore) {
    let dir = tempfile::tempdir().unwrap();
    Keystore::init_account(dir.path(), "acct").unwrap();
    let store = Keystore::open(dir.path()).unwrap();
    (dir, store)
}

#[test]
fn every_role_holds_state_write_and_nothing_wider_by_default() {
    let (_d, s) = store();
    let role = s.role("lane", t0()).unwrap();
    assert_eq!(
        names(&role.permissions),
        ["ack", "request-ack", "send", "state-write"]
    );
}

#[test]
fn a_grant_reaches_the_certificate_and_an_ungrant_removes_it() {
    let (_d, s) = store();
    let before = s.role("pm", t0()).unwrap();
    s.grant("pm", &Permission::StateReadAll).unwrap();
    s.grant("pm", &Permission::StateReadAll).unwrap();
    assert_eq!(
        s.grants("pm").unwrap(),
        [Permission::StateReadAll],
        "idempotent"
    );
    let after = s.role("pm", t0() + Duration::minutes(1)).unwrap();
    assert!(after.permissions.contains(&Permission::StateReadAll));
    assert_ne!(
        before.chain[0].serial, after.chain[0].serial,
        "the certificate was re-issued to carry the grant"
    );
    s.ungrant("pm", &Permission::StateReadAll).unwrap();
    let back = s.role("pm", t0() + Duration::minutes(2)).unwrap();
    assert!(!back.permissions.contains(&Permission::StateReadAll));
    assert!(s.grants("pm").unwrap().is_empty());
}

#[test]
fn only_the_state_extras_are_grantable() {
    let (_d, s) = store();
    for p in [Permission::Send, Permission::Ack, Permission::StateWrite] {
        assert!(s.grant("pm", &p).is_err(), "{}", p.as_str());
    }
    assert!(s.grant("bad name", &Permission::StateAdmin).is_err());
    assert!(s.grant("pm", &Permission::StateAdmin).is_ok());
    assert!(s.grant("pm", &Permission::StateDerive).is_ok());
    assert_eq!(
        names(&s.grants("pm").unwrap()),
        ["state-admin", "state-derive"]
    );
}

#[test]
fn an_issued_certificate_carries_the_grants() {
    let (_d, s) = store();
    s.grant("checker", &Permission::StateDerive).unwrap();
    let other = tempfile::tempdir().unwrap();
    let pubs = Keystore::init_role(other.path(), "acct", "checker").unwrap();
    let pem = s
        .issue_role_certificate("checker", pubs, t0(), Duration::days(8))
        .unwrap();
    let chain = chain_from_pem(&pem).unwrap();
    assert_eq!(
        names(&chain[0].permissions),
        ["ack", "request-ack", "send", "state-derive", "state-write"]
    );
}

#[test]
fn a_corrupt_grants_file_is_refused_not_skipped() {
    let (d, s) = store();
    s.role("lane", t0()).unwrap();
    std::fs::write(d.path().join("roles").join("lane").join("grants"), "send\n").unwrap();
    assert!(s.grants("lane").is_err());
    assert!(s.role("lane", t0() + Duration::minutes(1)).is_err());
}

#[test]
fn the_new_names_parse_and_unknown_ones_still_do_not() {
    for n in [
        "state-write",
        "state-read-all",
        "state-admin",
        "state-derive",
    ] {
        assert_eq!(Permission::parse(n).unwrap().as_str(), n);
    }
    assert!(Permission::parse("state-root").is_none());
    assert_eq!(
        Permission::parse("x-state-write"),
        Some(Permission::Extension("x-state-write".into()))
    );
}
