// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse id provision`: a role-only home per lane, dry run by default, idempotent, and no key
//! in what it prints.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

struct Setup {
    _tmp: tempfile::TempDir,
    account_home: PathBuf,
    root: PathBuf,
    roles_file: PathBuf,
}

fn setup(roles: &str) -> Setup {
    let tmp = tempfile::tempdir().unwrap();
    let account_home = tmp.path().join("acct-home");
    let root = tmp.path().join("lanes");
    let o = run(&account_home, &["id", "init", "--account", "acct"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let roles_file = tmp.path().join("roles.txt");
    std::fs::write(&roles_file, roles).unwrap();
    Setup {
        _tmp: tmp,
        account_home,
        root,
        roles_file,
    }
}

fn provision(s: &Setup, extra: &[&str]) -> Output {
    let mut args = vec![
        "id",
        "provision",
        "--roles-file",
        s.roles_file.to_str().unwrap(),
        "--lane-home-root",
        s.root.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run(&s.account_home, &args)
}

fn cert(s: &Setup, role: &str) -> Vec<u8> {
    std::fs::read(s.root.join(role).join("roles").join(role).join("cert.pem"))
        .unwrap_or_else(|e| panic!("no certificate for {role}: {e}"))
}

#[test]
fn a_dry_run_writes_nothing() {
    let s = setup("alpha\nbeta\n");
    let o = provision(&s, &[]);
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    let text = out(&o);
    assert!(text.contains("alpha would-create"), "{text}");
    assert!(text.contains("beta would-create"), "{text}");
    assert!(text.contains("dry run"), "{text}");
    assert!(!s.root.exists(), "a dry run must not even make the root");
}

#[test]
fn apply_creates_role_only_homes_and_prints_no_key() {
    let s = setup("# the lanes\nalpha\n\nbeta # second\n");
    let o = provision(&s, &["--apply"]);
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    let text = out(&o);
    assert!(
        text.contains("alpha created") && text.contains("beta created"),
        "{text}"
    );
    for role in ["alpha", "beta"] {
        assert!(
            !s.root
                .join(role)
                .join("account")
                .join("account.key.pem")
                .exists(),
            "{role}'s home must not hold the account key"
        );
        let shown = run(&s.root.join(role), &["id", "show", "--role", role]);
        assert_eq!(shown.status.code(), Some(0), "{}", out(&shown));
        assert!(out(&shown).contains(&format!("{role}@acct")));
    }
    // No key material, certificate text or path in what was printed.
    assert!(!text.contains("BEGIN") && !text.contains("pem"), "{text}");
    assert!(!text.contains(s.root.to_str().unwrap()), "{text}");
    let hexish = text
        .split(|c: char| !c.is_ascii_hexdigit())
        .any(|w| w.len() >= 32);
    assert!(!hexish, "a long hex string in the output: {text}");
}

#[test]
fn a_second_run_changes_nothing() {
    let s = setup("alpha\n");
    assert_eq!(provision(&s, &["--apply"]).status.code(), Some(0));
    let before = cert(&s, "alpha");
    let o = provision(&s, &["--apply"]);
    assert!(out(&o).contains("alpha ok"), "{}", out(&o));
    assert_eq!(cert(&s, "alpha"), before, "an ok role is not reissued");
}

#[test]
fn a_certificate_near_expiry_is_reissued() {
    let s = setup("alpha\n");
    assert_eq!(
        provision(&s, &["--apply", "--days", "2"]).status.code(),
        Some(0)
    );
    let before = cert(&s, "alpha");
    let dry = provision(&s, &["--renew-below-days", "5"]);
    assert!(out(&dry).contains("alpha would-renew"), "{}", out(&dry));
    assert_eq!(cert(&s, "alpha"), before, "a dry run reissues nothing");
    let o = provision(&s, &["--apply", "--renew-below-days", "5"]);
    assert!(out(&o).contains("alpha renewed"), "{}", out(&o));
    assert_ne!(cert(&s, "alpha"), before);
}

#[test]
fn a_new_grant_is_picked_up_as_a_renewal() {
    let s = setup("alpha\n");
    assert_eq!(provision(&s, &["--apply"]).status.code(), Some(0));
    let g = run(
        &s.account_home,
        &["id", "grant", "--role", "alpha", "state-admin"],
    );
    assert_eq!(g.status.code(), Some(0), "{}", out(&g));
    let o = provision(&s, &["--apply"]);
    assert!(out(&o).contains("alpha renewed"), "{}", out(&o));
}

#[test]
fn a_bad_roles_file_is_refused_before_anything_is_written() {
    for bad in ["alpha\nnot a name\n", "alpha\nalpha\n", "# nothing\n"] {
        let s = setup(bad);
        let o = provision(&s, &["--apply"]);
        assert_eq!(o.status.code(), Some(2), "{bad:?}: {}", out(&o));
        assert!(!s.root.exists(), "{bad:?} wrote before refusing");
    }
}

#[test]
fn the_account_home_is_never_made_a_role_home() {
    let tmp = tempfile::tempdir().unwrap();
    let account_home = tmp.path().join("alpha");
    let o = run(&account_home, &["id", "init", "--account", "acct"]);
    assert_eq!(o.status.code(), Some(0));
    let roles_file = tmp.path().join("roles.txt");
    std::fs::write(&roles_file, "alpha\nbeta\n").unwrap();
    let o = run(
        &account_home,
        &[
            "id",
            "provision",
            "--roles-file",
            roles_file.to_str().unwrap(),
            "--lane-home-root",
            tmp.path().to_str().unwrap(),
            "--apply",
        ],
    );
    let text = out(&o);
    assert_eq!(o.status.code(), Some(2), "{text}");
    assert!(text.contains("alpha refused"), "{text}");
    assert!(
        text.contains("beta created"),
        "one refusal does not stop the rest: {text}"
    );
}
