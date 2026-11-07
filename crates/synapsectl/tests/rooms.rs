// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse room ...` against a real `synapsed` that the CLI starts itself (slice R4b): create,
//! join, post, members, policy, ban and delete, and a bad name refused before any daemon call.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;

/// `cargo test -p synapsectl` does not build another package's binary, so build `synapsed` into
/// the directory the CLI looks in first: next to the `synapse` executable.
fn ensure_synapsed_built() {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let dir = Path::new(env!("CARGO_BIN_EXE_synapse")).parent().unwrap();
        let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cmd.args(["build", "-p", "synapsed", "--bin", "synapsed"]);
        if dir.file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        let status = cmd.status().expect("cargo runs");
        assert!(status.success(), "building synapsed failed");
        let exe = dir.join(format!("synapsed{}", std::env::consts::EXE_SUFFIX));
        assert!(exe.exists(), "synapsed is not at {}", exe.display());
    });
}

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Home {
        ensure_synapsed_built();
        let home = Home {
            dir: tempfile::tempdir().unwrap(),
        };
        let init = home.run(&["id", "init", "--account", "acct"]);
        assert_eq!(init.status.code(), Some(0), "{init:?}");
        // Slice A1: new roles are deny-all, so seed an allow-all rule the way an upgraded home has one.
        std::fs::write(
            home.path().join("access.json"),
            r#"{"grants":[{"principal":"*","actions":["see","send"],"objects":["agent:*"]}]}"#,
        )
        .expect("seed access.json");
        home
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_synapse"));
        cmd.args(args)
            .env("SYNAPSE_HOME", self.path())
            .env("SYNAPSE_ADDR", "127.0.0.1:0")
            .env("SYNAPSE_REDELIVERY_GAPS", "")
            .env_remove("SYNAPSE_ROLE");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args)
            .output()
            .expect("the synapse binary runs")
    }

    /// Run and require success.
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "synapse {args:?} failed: {out:?}"
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn announced_pid(&self) -> Option<u32> {
        let text = std::fs::read_to_string(self.path().join("synapsed.json")).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        v["pid"].as_u64().map(|p| p as u32)
    }

    fn kill_daemon(&self) {
        if let Some(pid) = self.announced_pid() {
            kill(pid);
            wait_dead(pid);
        }
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        self.kill_daemon();
    }
}

fn kill(pid: u32) {
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .output();
    #[cfg(unix)]
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
}

fn alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let out = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
            .output()
            .expect("tasklist runs");
        String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\""))
    }
    #[cfg(unix)]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .is_ok_and(|o| o.status.success())
    }
}

fn wait_dead(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn json_of(text: &str) -> Value {
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("not one JSON line ({e}): {text}"))
}

/// A home where `pm` may create rooms.
fn home_where_pm_makes_rooms() -> Home {
    let home = Home::new();
    home.ok(&["id", "grant", "--role", "pm", "room-create"]);
    home
}

#[test]
fn the_room_commands_create_join_post_list_ban_and_delete() {
    let home = home_where_pm_makes_rooms();
    let made = json_of(&home.ok(&["room", "create", "--role", "pm", "lounge"]));
    assert_eq!(made["room"], "lounge@acct");
    // A new room is visible to its creator only.
    let mine = json_of(&home.ok(&["room", "list", "--role", "pm"]));
    assert_eq!(mine["rooms"][0]["room"], "lounge@acct", "{mine}");
    let theirs = json_of(&home.ok(&["room", "list", "--role", "dev"]));
    assert_eq!(theirs["rooms"], serde_json::json!([]), "{theirs}");
    // dev joins (the name may carry the account), pm sees the member and posts to the room.
    // The room is pm's until it says otherwise: invite dev, who then sees it and joins.
    home.ok(&["room", "invite", "--role", "pm", "lounge", "dev@acct"]);
    let joined = json_of(&home.ok(&["room", "join", "--role", "dev", "lounge@acct"]));
    assert_eq!(joined["joined"], true, "{joined}");
    let members = json_of(&home.ok(&["room", "members", "--role", "pm", "lounge"]));
    assert_eq!(members["members"][0]["member"], "dev@acct", "{members}");
    let sent = home.ok(&["send", "--role", "pm", "--to", "lounge", "hello room"]);
    assert!(sent.contains("queued"), "{sent}");
    let inbox = home.ok(&["inbox", "--role", "dev"]);
    assert!(inbox.contains("hello room"), "{inbox}");
    // pm bans dev: dev cannot come back.
    home.ok(&["room", "ban", "--role", "pm", "lounge", "dev@acct"]);
    let again = home.run(&["room", "join", "--role", "dev", "lounge"]);
    assert_ne!(
        again.status.code(),
        Some(0),
        "a banned role rejoined: {again:?}"
    );
    home.ok(&["room", "delete", "--role", "pm", "lounge"]);
    let gone = json_of(&home.ok(&["room", "list", "--role", "pm"]));
    assert_eq!(gone["rooms"], serde_json::json!([]));
}

#[test]
fn the_policy_command_sets_invite_only_and_an_allow_list() {
    let home = home_where_pm_makes_rooms();
    home.ok(&["room", "create", "--role", "pm", "lounge"]);
    home.ok(&[
        "room",
        "policy",
        "--role",
        "pm",
        "lounge",
        "--join",
        "invite-only",
    ]);
    home.ok(&["room", "invite", "--role", "pm", "lounge", "dev@acct"]);
    assert_eq!(
        json_of(&home.ok(&["room", "join", "--role", "dev", "lounge"]))["joined"],
        true,
        "the invited role joins"
    );
    home.ok(&[
        "room",
        "policy",
        "--role",
        "pm",
        "lounge",
        "--join",
        "allow-list",
        "--allow",
        "ops@acct",
        "--muted",
    ]);
    let ops = json_of(&home.ok(&["room", "join", "--role", "ops", "lounge"]));
    assert_eq!(ops["muted"], true, "{ops}");
    let out = home.run(&["room", "join", "--role", "other", "lounge"]);
    assert_ne!(out.status.code(), Some(0), "an unlisted role joined");
}

#[test]
fn a_bad_room_name_or_policy_is_a_usage_error_before_any_daemon_call() {
    let home = Home::new();
    for args in [
        vec!["room", "join", "--role", "dev", "a b"],
        vec!["room", "members", "--role", "dev", "x&room=lounge"],
        vec![
            "room",
            "policy",
            "--role",
            "pm",
            "lounge",
            "--join",
            "allow-list",
        ],
        vec![
            "room", "policy", "--role", "pm", "lounge", "--join", "open", "--allow", "a@acct",
        ],
        vec![
            "room",
            "policy",
            "--role",
            "pm",
            "lounge",
            "--join",
            "sometimes",
        ],
    ] {
        let out = home.run(&args);
        assert_ne!(out.status.code(), Some(0), "{args:?} was accepted");
        assert!(
            home.announced_pid().is_none(),
            "{args:?} started a daemon: the refusal must come first"
        );
    }
}
