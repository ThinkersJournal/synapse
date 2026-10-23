// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse id init|show` over the keystore (M2). Every run gets its own `SYNAPSE_HOME`.

use std::path::Path;
use std::process::{Command, Output};

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

fn line<'a>(text: &'a str, label: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{label}: ")))
        .unwrap_or_else(|| panic!("no `{label}:` line in:\n{text}"))
}

#[test]
fn init_then_show_round_trips() {
    let home = tempfile::tempdir().unwrap();
    let init = run(home.path(), &["id", "init", "--account", "acct"]);
    assert_eq!(init.status.code(), Some(0), "{init:?}");
    let init_out = stdout(&init);
    assert_eq!(line(&init_out, "account"), "acct");
    let account_key_id = line(&init_out, "account key id").to_string();
    assert_eq!(account_key_id.len(), 64);

    let first = run(home.path(), &["id", "show", "--role", "worker"]);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let first_out = stdout(&first);
    assert_eq!(line(&first_out, "account key id"), account_key_id);
    assert_eq!(line(&first_out, "identity"), "worker@acct");
    // Sorted by name: the order a certificate encodes, so a fresh issue and a reload print alike.
    assert_eq!(
        line(&first_out, "permissions"),
        "ack, request-ack, send, state-write"
    );
    assert!(line(&first_out, "certificate valid").contains(" to "));

    let second = run(home.path(), &["id", "show", "--role", "worker"]);
    let second_out = stdout(&second);
    assert_eq!(
        line(&second_out, "signing key id"),
        line(&first_out, "signing key id"),
        "the role keeps its key across runs"
    );
}

#[test]
fn init_twice_is_refused_with_exit_2() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(
        run(home.path(), &["id", "init", "--account", "acct"])
            .status
            .code(),
        Some(0)
    );
    let again = run(home.path(), &["id", "init", "--account", "acct"]);
    assert_eq!(again.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&again.stderr).contains("an account already exists"));
}

#[test]
fn no_output_ever_contains_secrets_or_paths() {
    let home = tempfile::tempdir().unwrap();
    let outputs = [
        run(home.path(), &["id", "show"]), // no account yet: an error
        run(home.path(), &["id", "init", "--account", "acct"]),
        run(home.path(), &["id", "init", "--account", "acct"]), // refused
        run(home.path(), &["id", "show"]),
        run(home.path(), &["id", "show", "--role", "r"]),
        run(home.path(), &["id", "show", "--role", "bad.name"]), // refused
    ];
    assert_eq!(
        outputs[0].status.code(),
        Some(2),
        "show with no account must fail"
    );
    let s = home.path().display().to_string();
    let forms = [s.replace('/', "\\"), s.replace('\\', "/")];
    for out in &outputs {
        for text in [
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ] {
            for form in &forms {
                assert!(
                    !text.contains(form.as_str()),
                    "output names the keystore path:\n{text}"
                );
            }
            assert!(
                !text.contains("PRIVATE KEY") && !text.contains("BEGIN"),
                "output carries key material:\n{text}"
            );
        }
    }
}
