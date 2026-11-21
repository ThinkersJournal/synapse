// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse storage inspect` and `storage import` end to end through the real binary (ROADMAP row 53):
//! two mailbox files built with the stores' own API, then the CLI's dry run, its refusals, its write, and
//! the read-back. The six import rules have unit tests in the library; this pins the command a person
//! types. Messages are built from JSON so a later field on `Envelope` or `Stored` does not break it.
#![cfg(feature = "storage")]

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};
use synapse::mailbox::{MailError, MailStore, RedbStore, Stored};
use synapse::roles::RolesState;
use synapse_mailbox_persistant::SqliteMailStore;

const BODY: &[u8] = b"secret-body-text";

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_synapse"))
        .args(args)
        .env("SYNAPSE_HOME", home)
        .output()
        .expect("the synapse binary runs")
}

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn message(id: &str, to: &str, seq: u64) -> Stored {
    serde_json::from_value(json!({
        "envelope": {
            "message_id": format!("sender@acct/{id}"),
            "to": to,
            "from": "sender@acct",
            "body": BODY,
        },
        "seq": seq,
        "enqueued_at": "2026-11-01T00:00:00Z",
        "lease": null,
        "attempts": 0,
    }))
    .expect("a stored message")
}

fn roles(list: &[(&str, u64)]) -> RolesState {
    let roles: serde_json::Map<String, Value> = list
        .iter()
        .map(|(r, e)| {
            (
                (*r).to_string(),
                json!({"epoch": e, "claimed_at": "2026-11-01T00:00:00Z", "last_seen": null, "retired_at": null}),
            )
        })
        .collect();
    serde_json::from_value(json!({ "roles": roles })).expect("roles")
}

/// Fill any store: `roles`, then `messages` as `(queue, message)`, and the seq counter.
fn fill(store: &impl MailStore, state: &RolesState, messages: &[(&str, Stored)], seq: u64) {
    store
        .write(&mut |txn| {
            txn.set_roles(state).map_err(MailError::Store)?;
            for (queue, stored) in messages {
                txn.put(queue, stored.clone()).map_err(MailError::Store)?;
            }
            txn.set_seq_counter(seq).map_err(MailError::Store)?;
            Ok(())
        })
        .expect("write the fixture");
}

struct Files {
    _dir: tempfile::TempDir,
    home: tempfile::TempDir,
    redb: std::path::PathBuf,
    sqlite: std::path::PathBuf,
}

/// A redb source (alice epoch 3, bob epoch 1; alice holds m1 and m2) and a sqlite target (alice epoch 1;
/// holds m2 and m3), with m2 in both.
fn files() -> Files {
    let dir = tempfile::tempdir().unwrap();
    let redb = dir.path().join("old.redb");
    let sqlite = dir.path().join("new.sqlite");
    {
        let store = RedbStore::open(&redb).unwrap();
        fill(
            &store,
            &roles(&[("alice@acct", 3), ("bob@acct", 1)]),
            &[
                ("alice@acct", message("m1", "alice@acct", 1)),
                ("alice@acct", message("m2", "alice@acct", 2)),
            ],
            2,
        );
    }
    {
        let store = SqliteMailStore::open(&sqlite).unwrap();
        fill(
            &store,
            &roles(&[("alice@acct", 1)]),
            &[
                ("alice@acct", message("m2", "alice@acct", 4)),
                ("alice@acct", message("m3", "alice@acct", 5)),
            ],
            5,
        );
    }
    Files {
        _dir: dir,
        home: tempfile::tempdir().unwrap(),
        redb,
        sqlite,
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn inspect_counts_a_file_and_never_prints_a_body() {
    let f = files();
    let o = run(f.home.path(), &["storage", "inspect", s(&f.redb)]);
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    let text = out(&o);
    assert!(text.contains("roles 2 (0 retired)"), "{text}");
    assert!(text.contains("queued messages 2"), "{text}");
    assert!(text.contains("queue alice@acct: 2 message(s)"), "{text}");
    assert!(
        !text.contains("secret-body-text"),
        "a body must never be printed: {text}"
    );
    // Nor as bytes: "secret" is 115, 101, 99, 114, 101, 116.
    assert!(
        !text.contains("115, 101, 99"),
        "a body must never be printed as bytes: {text}"
    );
}

#[test]
fn inspect_against_names_what_is_on_one_side_only() {
    let f = files();
    let o = run(
        f.home.path(),
        &["storage", "inspect", s(&f.sqlite), "--against", s(&f.redb)],
    );
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    let text = out(&o);
    assert!(text.contains("role only in B: bob@acct"), "{text}");
    assert!(
        text.contains("role epoch differs: alice@acct A=1 B=3"),
        "{text}"
    );
    assert!(
        text.contains("queued only in A: alice@acct sender@acct/m3"),
        "{text}"
    );
    assert!(
        text.contains("queued only in B: alice@acct sender@acct/m1"),
        "{text}"
    );
}

#[test]
fn a_dry_run_reports_the_plan_and_writes_nothing() {
    let f = files();
    let o = run(
        f.home.path(),
        &[
            "storage",
            "import",
            "--from",
            s(&f.redb),
            "--into",
            s(&f.sqlite),
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    let text = out(&o);
    assert!(
        text.contains("roles: 1 added, 1 raised to the source's higher epoch"),
        "{text}"
    );
    assert!(
        text.contains("messages: 1 added (0 dead letters), 1 already queued"),
        "{text}"
    );
    assert!(text.contains("dry run: nothing written"), "{text}");
    let after = run(f.home.path(), &["storage", "inspect", s(&f.sqlite)]);
    assert!(
        out(&after).contains("queued messages 2"),
        "the dry run changed the target: {}",
        out(&after)
    );
}

#[test]
fn apply_writes_the_plan_reads_it_back_and_loses_nothing() {
    let f = files();
    let o = run(
        f.home.path(),
        &[
            "storage",
            "import",
            "--from",
            s(&f.redb),
            "--into",
            s(&f.sqlite),
            "--apply",
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    let text = out(&o);
    assert!(
        text.contains("applied and read back equal to the plan: 2 roles, 3 queued messages"),
        "{text}"
    );
    // Nothing in the old file is missing from the new one: no "only in B" line for a queued message.
    let cmp = run(
        f.home.path(),
        &["storage", "inspect", s(&f.sqlite), "--against", s(&f.redb)],
    );
    let diff = out(&cmp);
    assert!(
        !diff.contains("queued only in B"),
        "a message of the source was lost: {diff}"
    );
    assert!(!diff.contains("role only in B"), "{diff}");
    assert!(
        diff.contains("queued only in A: alice@acct sender@acct/m3"),
        "{diff}"
    );
}

#[test]
fn the_wrong_file_kinds_and_missing_files_are_refused_with_a_reason() {
    let f = files();
    let swapped = run(
        f.home.path(),
        &[
            "storage",
            "import",
            "--from",
            s(&f.sqlite),
            "--into",
            s(&f.redb),
        ],
    );
    assert_ne!(swapped.status.code(), Some(0));
    assert!(
        out(&swapped).contains("--from must be a .redb file and --into a .sqlite file"),
        "{}",
        out(&swapped)
    );
    let missing = f.home.path().join("nowhere.sqlite");
    let gone = run(
        f.home.path(),
        &[
            "storage",
            "import",
            "--from",
            s(&f.redb),
            "--into",
            s(&missing),
        ],
    );
    assert_ne!(gone.status.code(), Some(0));
    assert!(out(&gone).contains("no such file"), "{}", out(&gone));
    assert!(
        !missing.exists(),
        "a refused import must not create the target"
    );
    let none = run(f.home.path(), &["storage", "inspect", s(&missing)]);
    assert_ne!(none.status.code(), Some(0));
    assert!(!missing.exists(), "inspect creates nothing");
}
