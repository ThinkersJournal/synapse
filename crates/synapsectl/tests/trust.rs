// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse trust knocks|pinned|pin` over the trust book (ROADMAP row 33, slice 1). Every run gets
//! its own `SYNAPSE_HOME`; the knock is put on the book through the library, because nothing in
//! production creates one yet (the federation receive path is a later slice).

use std::path::Path;
use std::process::{Command, Output};

use synapse::keystore::trust_book::TrustBook;
use synapse::sender_auth::key_id;

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_synapse"))
        .args(args)
        .env("SYNAPSE_HOME", home)
        .output()
        .expect("the synapse binary runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A home with one knock from an account whose public key is `key`.
fn home_with_a_knock(key: &[u8; 32]) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    TrustBook::open(home.path())
        .record_knock(
            "pm@alice",
            "sender-key-id",
            Some(&key_id(key)),
            "unknown_issuer",
            chrono::Utc::now(),
        )
        .unwrap();
    home
}

#[test]
fn knocks_are_listed_and_nothing_is_pinned_until_the_holder_pins() {
    let key = [7u8; 32];
    let home = home_with_a_knock(&key);

    let knocks = run(home.path(), &["trust", "knocks"]);
    assert_eq!(knocks.status.code(), Some(0), "{knocks:?}");
    let lines: Vec<String> = stdout(&knocks).lines().map(str::to_string).collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let row: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(row["claimed_global_id"], "pm@alice");
    assert_eq!(row["account_key_id"], key_id(&key));

    let pinned = run(home.path(), &["trust", "pinned"]);
    assert_eq!(pinned.status.code(), Some(0), "{pinned:?}");
    assert!(
        stdout(&pinned).trim().is_empty(),
        "a knock pins nothing: {}",
        stdout(&pinned)
    );
}

#[test]
fn a_pin_needs_the_key_id_typed_back_and_otherwise_pins_nothing() {
    let key = [7u8; 32];
    let home = home_with_a_knock(&key);
    let (public_key, id) = (hex(&key), key_id(&key));

    // No confirmation flag at all is a usage error, not a yes.
    let missing = run(
        home.path(),
        &[
            "trust",
            "pin",
            "--label",
            "alice",
            "--public-key",
            &public_key,
        ],
    );
    assert_ne!(missing.status.code(), Some(0), "{missing:?}");
    // The wrong id typed back, and half of the right one.
    for wrong in ["0".repeat(64), id[..32].to_string()] {
        let out = run(
            home.path(),
            &[
                "trust",
                "pin",
                "--label",
                "alice",
                "--public-key",
                &public_key,
                "--confirm-key-id",
                &wrong,
            ],
        );
        assert_ne!(out.status.code(), Some(0), "{wrong}: {out:?}");
        assert!(stdout(&out).is_empty(), "nothing is printed on a refusal");
    }
    assert!(
        stdout(&run(home.path(), &["trust", "pinned"]))
            .trim()
            .is_empty()
    );
    assert_eq!(
        stdout(&run(home.path(), &["trust", "knocks"]))
            .lines()
            .count(),
        1
    );

    // Control: the right id typed back pins it, prints the pin, and the knock is answered.
    let ok = run(
        home.path(),
        &[
            "trust",
            "pin",
            "--label",
            "alice",
            "--public-key",
            &public_key,
            "--confirm-key-id",
            &id,
        ],
    );
    assert_eq!(ok.status.code(), Some(0), "{ok:?}");
    let printed: serde_json::Value = serde_json::from_str(stdout(&ok).trim()).unwrap();
    assert_eq!(printed["key_id"], id);
    assert_eq!(printed["label"], "alice");
    assert_eq!(
        stdout(&run(home.path(), &["trust", "pinned"]))
            .lines()
            .count(),
        1
    );
    assert!(
        stdout(&run(home.path(), &["trust", "knocks"]))
            .trim()
            .is_empty()
    );
}

#[test]
fn a_key_that_never_knocked_cannot_be_pinned() {
    let home = home_with_a_knock(&[7u8; 32]);
    let stranger = [9u8; 32];
    let out = run(
        home.path(),
        &[
            "trust",
            "pin",
            "--label",
            "stranger",
            "--public-key",
            &hex(&stranger),
            "--confirm-key-id",
            &key_id(&stranger),
        ],
    );
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("knock"),
        "the refusal says a pin is made only from a knock: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout(&run(home.path(), &["trust", "pinned"]))
            .trim()
            .is_empty()
    );
}
