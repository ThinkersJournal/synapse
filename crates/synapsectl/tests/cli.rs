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

/// A3: `synapse id delegate` prints the sub-agent's chain for a role-admin, in a form a claim can
/// present, and refuses a role without the budget and a permission its creator lacks.
#[test]
fn id_delegate_issues_a_sub_agent_chain_and_refuses_what_it_may_not() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(
        run(home.path(), &["id", "init", "--account", "acct"])
            .status
            .code(),
        Some(0)
    );
    // The sub-agent's keys are made in a home of its own.
    let sub_home = tempfile::tempdir().unwrap();
    let made = run(
        sub_home.path(),
        &["id", "init-role", "--account", "acct", "--role", "worker"],
    );
    assert_eq!(made.status.code(), Some(0), "{made:?}");
    let made = stdout(&made);
    let (signing, sealing) = (line(&made, "signing-pub"), line(&made, "sealing-pub"));
    let delegate = |role: &str, extra: &[&str]| {
        let mut args = vec![
            "id",
            "delegate",
            "--role",
            role,
            "--label",
            "worker",
            "--signing-pub",
            signing,
            "--sealing-pub",
            sealing,
        ];
        args.extend_from_slice(extra);
        run(home.path(), &args)
    };

    // pm without role-admin has no budget.
    let refused = delegate("pm", &[]);
    assert_ne!(refused.status.code(), Some(0), "no budget, no certificate");
    assert!(stdout(&refused).is_empty(), "nothing printed on a refusal");

    // With role-admin it prints a two-link chain for worker.pm@acct.
    run(home.path(), &["id", "grant", "--role", "pm", "role-admin"]);
    let issued = delegate("pm", &["--permission", "send", "--permission", "ack"]);
    assert_eq!(issued.status.code(), Some(0), "{issued:?}");
    let chain = synapse::certificate::chain_from_pem(&stdout(&issued)).expect("a chain");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].subject_global_id, "worker.pm@acct");
    assert_eq!(chain[1].subject_global_id, "pm@acct");
    assert_eq!(chain[0].permissions.len(), 2, "only what was asked");
    let hex = |bytes: &[u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(&chain[0].subject_signing_key),
        signing,
        "its own signing key"
    );
    assert_eq!(
        hex(&chain[0].subject_sealing_key),
        sealing,
        "its own sealing key"
    );

    // A permission pm lacks, and a name that is not a permission, are refused.
    let wider = delegate("pm", &["--permission", "state-admin"]);
    assert_ne!(wider.status.code(), Some(0), "wider than its creator");
    let typo = delegate("pm", &["--permission", "sendd"]);
    assert_ne!(typo.status.code(), Some(0), "not a permission");
}

/// A3 (b), through the commands: a sub-agent home made with `init-role` installs the chain
/// `id delegate` printed (`install-cert` reads it on stdin) and `id show` reads it back as
/// `worker.pm@acct`, without the home ever holding the account key.
#[test]
fn a_sub_agent_home_installs_a_delegated_chain_and_shows_its_identity() {
    use std::io::Write;
    use std::process::Stdio;
    let account = tempfile::tempdir().unwrap();
    run(account.path(), &["id", "init", "--account", "acct"]);
    run(
        account.path(),
        &["id", "grant", "--role", "pm", "role-admin"],
    );
    let sub_home = tempfile::tempdir().unwrap();
    let made = stdout(&run(
        sub_home.path(),
        &["id", "init-role", "--account", "acct", "--role", "worker"],
    ));
    let issued = run(
        account.path(),
        &[
            "id",
            "delegate",
            "--role",
            "pm",
            "--label",
            "worker",
            "--signing-pub",
            line(&made, "signing-pub"),
            "--sealing-pub",
            line(&made, "sealing-pub"),
        ],
    );
    assert_eq!(issued.status.code(), Some(0), "{issued:?}");

    let mut install = Command::new(env!("CARGO_BIN_EXE_synapse"))
        .args(["id", "install-cert", "--role", "worker"])
        .env("SYNAPSE_HOME", sub_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    install
        .stdin
        .take()
        .unwrap()
        .write_all(&issued.stdout)
        .unwrap();
    let installed = install.wait_with_output().unwrap();
    assert_eq!(installed.status.code(), Some(0), "{installed:?}");

    let shown = run(sub_home.path(), &["id", "show", "--role", "worker"]);
    assert_eq!(shown.status.code(), Some(0), "{shown:?}");
    assert!(
        stdout(&shown).contains("worker.pm@acct"),
        "{}",
        stdout(&shown)
    );
    assert!(
        !sub_home
            .path()
            .join("account")
            .join("account.key.pem")
            .exists(),
        "the sub-agent home never held the account key"
    );
}
