// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse claim|send|inbox|ack|list` against a real `synapsed` that the CLI starts itself (M5b).
//!
//! Every test gets its own `SYNAPSE_HOME` and `SYNAPSE_ADDR=127.0.0.1:0`: the daemon binds a free
//! port and the CLI learns it from the announce file. A guard kills the announced daemon on drop.

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

/// The pids the CLI said it spawned (`synapse: started synapsed (pid N)` on stderr).
fn spawned_pids(out: &Output) -> Vec<u32> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter_map(|l| l.strip_prefix("synapse: started synapsed (pid "))
        .filter_map(|rest| rest.strip_suffix(')'))
        .map(|n| n.parse().expect("a pid"))
        .collect()
}

fn json_lines(text: &str) -> Vec<Value> {
    text.lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
        .collect()
}

fn role_epoch(home: &Home, as_role: &str, global_id: &str) -> u64 {
    let roles = json_lines(&home.ok(&["list", "--role", as_role]));
    roles
        .iter()
        .find(|r| r["global_id"] == global_id)
        .unwrap_or_else(|| panic!("{global_id} not listed: {roles:?}"))["epoch"]
        .as_u64()
        .unwrap()
}

fn line<'a>(text: &'a str, label: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{label}: ")))
        .unwrap_or_else(|| panic!("no `{label}:` line in:\n{text}"))
}

#[test]
fn stats_prints_one_object_per_role_with_scope_and_since() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    home.ok(&["claim", "--role", "beta"]);
    home.ok(&["send", "--role", "alpha", "--to", "beta", "hello"]);
    let stats = json_lines(&home.ok(&["stats", "--role", "alpha"]));
    let entry = |id: &str| {
        stats
            .iter()
            .find(|r| r["global_id"] == id)
            .unwrap_or_else(|| panic!("{id} not in {stats:?}"))
    };
    assert_eq!(entry("beta@acct")["sent"], 1, "{stats:?}");
    assert_eq!(entry("beta@acct")["acked"], 0);
    assert_eq!(entry("alpha@acct")["sent"], 0);
    assert!(
        stats
            .iter()
            .all(|r| r["scope"] == "process" && r["since"].is_string())
    );
}

#[test]
fn a_command_against_a_stopped_daemon_starts_it() {
    let home = Home::new();
    assert!(
        home.announced_pid().is_none(),
        "no daemon before the first command"
    );

    let out = home.run(&["claim", "--role", "alpha"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(line(&text, "identity"), "alpha@acct");
    assert_eq!(line(&text, "epoch"), "1");

    let pid = home.announced_pid().expect("the CLI started a daemon");
    assert_eq!(spawned_pids(&out), vec![pid]);
    assert!(alive(pid));
}

/// Start both commands back to back (not via `output()`, which runs each to completion in turn
/// on its thread), so their auto-starts overlap. Several fresh homes, since a race need not
/// happen on any one try; how many tries really raced is printed.
#[test]
fn two_concurrent_first_commands_leave_one_daemon() {
    let mut raced = 0;
    for _ in 0..5 {
        let home = Home::new();
        let piped = |mut cmd: Command| {
            cmd.stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        };
        let a = piped(home.command(&["claim", "--role", "alpha"]));
        let b = piped(home.command(&["claim", "--role", "beta"]));
        let out_a = a.wait_with_output().unwrap();
        let out_b = b.wait_with_output().unwrap();
        assert_eq!(out_a.status.code(), Some(0), "{out_a:?}");
        assert_eq!(out_b.status.code(), Some(0), "{out_b:?}");

        let winner = home.announced_pid().expect("a daemon announced itself");
        let spawned: Vec<u32> = spawned_pids(&out_a)
            .into_iter()
            .chain(spawned_pids(&out_b))
            .collect();
        assert!(!spawned.is_empty(), "someone started the daemon");
        assert!(
            spawned.contains(&winner),
            "{spawned:?} vs announced {winner}"
        );
        if spawned.len() > 1 {
            raced += 1;
        }
        for pid in spawned.iter().filter(|&&p| p != winner) {
            wait_dead(*pid);
            assert!(!alive(*pid), "a second daemon (pid {pid}) is still running");
        }
        assert!(alive(winner));
        // Both roles were claimed on the one daemon.
        assert_eq!(role_epoch(&home, "alpha", "beta@acct"), 1);
    }
    eprintln!("both commands started a daemon in {raced} of 5 tries");
}

/// Two first commands for one role, at once, on a running daemon: one claim, not two that
/// supersede each other (review I4).
#[test]
fn concurrent_first_commands_for_one_role_claim_once() {
    let home = Home::new();
    home.ok(&["claim", "--role", "beta"]); // the daemon is up
    for role in ["g1", "g2", "g3"] {
        let start = |args: &[&str]| {
            home.command(args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        };
        let a = start(&["send", "--role", role, "--to", role, "one"]);
        let b = start(&["inbox", "--role", role]);
        let out_a = a.wait_with_output().unwrap();
        let out_b = b.wait_with_output().unwrap();
        assert_eq!(out_a.status.code(), Some(0), "{out_a:?}");
        assert_eq!(out_b.status.code(), Some(0), "{out_b:?}");
        assert_eq!(role_epoch(&home, "beta", &format!("{role}@acct")), 1);
    }
}

#[test]
fn a_round_trip_between_two_roles() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    home.ok(&["claim", "--role", "beta"]);

    let sent = home.ok(&["send", "--role", "alpha", "--to", "beta", "hello beta"]);
    assert_eq!(line(&sent, "outcome"), "queued");
    let message_id = line(&sent, "message id").to_string();
    assert!(message_id.starts_with("alpha@acct/"), "{message_id}");

    let inbox = json_lines(&home.ok(&["inbox", "--role", "beta"]));
    assert_eq!(inbox.len(), 1, "{inbox:?}");
    assert_eq!(inbox[0]["from"], "alpha@acct");
    assert_eq!(inbox[0]["body"], "hello beta");
    assert_eq!(inbox[0]["message_id"], message_id.as_str());

    let acked = home.ok(&["ack", "--role", "beta", &message_id]);
    assert_eq!(line(&acked, "outcome"), "removed");
    assert!(
        json_lines(&home.ok(&["inbox", "--role", "beta"])).is_empty(),
        "an acked message is not redelivered"
    );
}

#[test]
fn a_message_can_come_from_stdin() {
    use std::io::Write;
    let home = Home::new();
    home.ok(&["claim", "--role", "beta"]);
    let mut child = home
        .command(&["send", "--role", "beta", "--to", "beta@acct"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"from stdin")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let inbox = json_lines(&home.ok(&["inbox", "--role", "beta"]));
    assert_eq!(inbox[0]["body"], "from stdin");
}

#[test]
fn a_cached_session_is_reused() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    home.ok(&["send", "--role", "alpha", "--to", "alpha", "one"]);
    home.ok(&["send", "--role", "alpha", "--to", "alpha", "two"]);
    home.ok(&["inbox", "--role", "alpha"]);
    assert_eq!(
        role_epoch(&home, "alpha", "alpha@acct"),
        1,
        "commands after a claim must not re-claim"
    );
}

#[test]
fn a_superseded_session_is_reported_not_stolen() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    let cache = home.path().join("sessions").join("alpha.json");
    let stale = std::fs::read(&cache).expect("the session is cached");
    home.ok(&["claim", "--role", "alpha"]); // a deliberate takeover: epoch 2
    std::fs::write(&cache, stale).unwrap(); // a holder still on epoch 1

    let out = home.run(&["send", "--role", "alpha", "--to", "alpha", "late"]);
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("superseded"), "{err}");

    // Nothing re-claimed behind the user's back. (`list` itself must use a current session.)
    home.ok(&["claim", "--role", "beta"]);
    assert_eq!(role_epoch(&home, "beta", "alpha@acct"), 2);
}

/// The daemon forgets sessions more than a few takeovers old, so their calls get 401, not 409.
/// That must not be answered by re-claiming either (review I1).
#[test]
fn a_long_superseded_session_is_not_reclaimed_on_401() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    let cache = home.path().join("sessions").join("alpha.json");
    let stale = std::fs::read(&cache).expect("the session is cached");
    for _ in 0..10 {
        home.ok(&["claim", "--role", "alpha"]);
    }
    std::fs::write(&cache, stale).unwrap();

    let out = home.run(&["send", "--role", "alpha", "--to", "alpha", "late"]);
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unauthorized"), "{err}");
    home.ok(&["claim", "--role", "beta"]);
    assert_eq!(role_epoch(&home, "beta", "alpha@acct"), 11);
}

#[test]
fn a_dead_daemon_is_restarted_and_the_role_reclaimed() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    let first = home.announced_pid().unwrap();
    home.kill_daemon();
    assert!(!alive(first));

    let out = home.run(&["send", "--role", "alpha", "--to", "alpha", "again"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let second = home.announced_pid().unwrap();
    assert_ne!(first, second);
    assert_eq!(spawned_pids(&out), vec![second]);
    let inbox = json_lines(&home.ok(&["inbox", "--role", "alpha"]));
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0]["body"], "again");
}

#[test]
fn a_role_is_required() {
    let home = Home::new();
    let out = home.run(&["inbox"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        home.announced_pid().is_none(),
        "a usage error starts no daemon"
    );
}

/// Open `path` to the broad Users group: what the keystore's owner-only check refuses.
fn loosen(path: &Path) {
    #[cfg(windows)]
    {
        let out = Command::new("icacls")
            .arg(path)
            .args(["/grant", "*S-1-5-32-545:(R)"])
            .output()
            .expect("icacls runs");
        assert!(out.status.success(), "{out:?}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o755 } else { 0o644 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// The CLI's security event file in the home (hardening P8).
const EVENTS_FILE: &str = "cli-security-events.jsonl";

/// Every event the CLI recorded in `home`, oldest first; none if the file is absent.
fn events(home: &Path) -> Vec<Value> {
    match std::fs::read_to_string(home.join(EVENTS_FILE)) {
        Ok(text) => text
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line is one JSON event"))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => panic!("reading the event file: {e}"),
    }
}

/// Opus review I3: a session directory, session file or announce file that others can read is
/// refused, not used. Hardening P8, row 6: the refusal is also recorded as an event.
#[test]
fn a_too_open_session_or_announce_file_is_refused() {
    for (target, item) in [
        ("sessions", "session directory"),
        ("sessions/alpha.json", "session file"),
        ("synapsed.json", "daemon announce file"),
    ] {
        let home = Home::new();
        home.ok(&["claim", "--role", "alpha"]);
        home.ok(&["send", "--role", "alpha", "--to", "alpha", "before"]);
        loosen(&home.path().join(target));
        let out = home.run(&["send", "--role", "alpha", "--to", "alpha", "after"]);
        assert_ne!(out.status.code(), Some(0), "{target}: {out:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("accessible to more than its owner"),
            "{target}: {err}"
        );
        assert!(
            err.contains("security: permissions_too_open synapsectl/files"),
            "{target}: {err}"
        );
        let events = events(home.path());
        assert_eq!(events.len(), 1, "{target}: {events:?}");
        assert_eq!(events[0]["kind"], "permissions_too_open", "{target}");
        assert_eq!(events[0]["surface"], "synapsectl/files", "{target}");
        assert_eq!(events[0]["subject"], item, "{target}");
    }
}

/// Hardening P8, row 7: a keystore key others can reach is refused, and the refusal is recorded.
#[test]
fn a_too_open_account_key_is_refused_and_recorded() {
    let home = Home::new();
    loosen(&home.path().join("account").join("account.key.pem"));
    let out = home.run(&["id", "show"]);
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let events = events(home.path());
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["kind"], "permissions_too_open");
    assert_eq!(events[0]["subject"], "account key");
}

/// Open the directory `path` to writes by the broad Users group (on Unix, by everyone).
fn open_to_writes(path: &Path) {
    #[cfg(windows)]
    {
        let out = Command::new("icacls")
            .arg(path)
            .args(["/grant", "*S-1-5-32-545:(W)"])
            .output()
            .expect("icacls runs");
        assert!(out.status.success(), "{out:?}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
}

/// Hardening P8: in a home others can write, the event goes to stderr only. A file written there
/// could be a planted link to one of the owner's files.
#[test]
fn a_home_others_can_write_gets_no_event_file() {
    let home = Home::new();
    loosen(&home.path().join("account").join("account.key.pem"));
    open_to_writes(home.path());
    let out = home.run(&["id", "show"]);
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("security: permissions_too_open"), "{err}");
    assert!(!home.path().join(EVENTS_FILE).exists());
}

/// Hardening P8, the positive control: commands that meet no refusal record nothing.
#[test]
fn clean_commands_record_no_event() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    home.ok(&["send", "--role", "alpha", "--to", "alpha", "hello"]);
    home.ok(&["id", "show", "--role", "alpha"]);
    assert!(
        !home.path().join(EVENTS_FILE).exists(),
        "{:?}",
        events(home.path())
    );
}

/// Opus review I1 (#74), the client-only mitigation: an announce file whose daemon is dead is not
/// trusted, even when something answers health on its port, so no token reaches that listener.
#[test]
fn a_dead_daemons_port_is_not_trusted() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    let text = std::fs::read_to_string(home.path().join("synapsed.json")).unwrap();
    let addr = serde_json::from_str::<Value>(&text).unwrap()["addr"]
        .as_str()
        .unwrap()
        .to_string();
    let first = home.announced_pid().unwrap();
    home.kill_daemon(); // a kill runs no shutdown handler, so the announce file stays (#74)

    let squatter = Squatter::bind(&addr, None);
    let out = home.run(&["send", "--role", "alpha", "--to", "alpha", "secret"]);
    let seen = squatter.stop();

    assert!(
        !seen.iter().any(|r| r.contains("authorization:")),
        "the token went to the squatter: {seen:?}"
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let second = home.announced_pid().unwrap();
    assert_ne!(first, second);
    assert_eq!(spawned_pids(&out), vec![second], "a fresh daemon took over");
}

/// A fake daemon on a port: it answers every request with an ok health and canned mail replies,
/// and records every request it received (lowercased) so a test can check what reached it.
struct Squatter {
    addr: String,
    seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    thread: std::thread::JoinHandle<()>,
}

impl Squatter {
    /// With `relay`, a challenged health request is forwarded to the live daemon at `relay` and its
    /// genuine reply, proof included, is returned: the relay attack the address in the MAC defeats.
    /// Each relayed reply is also logged, prefixed `relayed:`.
    fn bind(addr: &str, relay: Option<String>) -> Squatter {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(addr).expect("the dead daemon's port is free");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log = std::sync::Arc::clone(&seen);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                if request.starts_with("stop") {
                    return;
                }
                log.lock().unwrap().push(request.clone());
                let canned = r#"{"ok":true,"started_at":"2020-01-01T00:00:00Z","global_id":"alpha@acct","epoch":1,"session":"00","outcome":"queued","message_id":"m","messages":[]}"#;
                let body = match (&relay, request.split_whitespace().nth(1)) {
                    (Some(to), Some(path)) if path.starts_with("/v1/health?challenge=") => {
                        let mut live = std::net::TcpStream::connect(to).unwrap();
                        write!(
                            live,
                            "GET {path} HTTP/1.1\r\nHost: {to}\r\nConnection: close\r\n\r\n"
                        )
                        .unwrap();
                        let mut reply = String::new();
                        live.read_to_string(&mut reply).unwrap();
                        let body = reply.split_once("\r\n\r\n").unwrap().1.to_string();
                        log.lock().unwrap().push(format!("relayed:{body}"));
                        body
                    }
                    _ => canned.to_string(),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Squatter {
            addr: addr.to_string(),
            seen,
            thread,
        }
    }

    /// Stop the fake and return every request it received.
    fn stop(self) -> Vec<String> {
        use std::io::Write;
        std::net::TcpStream::connect(&self.addr)
            .unwrap()
            .write_all(b"stop")
            .unwrap();
        self.thread.join().unwrap();
        self.seen.lock().unwrap().clone()
    }
}

/// #74: a squatter on the announced port gets no credential even while the announced pid is a live
/// `synapsed` (a reused pid), which the pid-liveness check alone cannot catch. Only the daemon that
/// holds the announced instance id can answer the health challenge.
#[test]
fn a_squatter_on_a_live_pids_port_gets_no_credential() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    let announce_path = home.path().join("synapsed.json");
    let mut announce: Value =
        serde_json::from_str(&std::fs::read_to_string(&announce_path).unwrap()).unwrap();
    let addr = announce["addr"].as_str().unwrap().to_string();
    home.kill_daemon();

    // Another home's live synapsed stands in for a process that reused the dead daemon's pid.
    let other = Home::new();
    other.ok(&["claim", "--role", "beta"]);
    let live_pid = other.announced_pid().unwrap();
    assert!(alive(live_pid));
    announce["pid"] = Value::from(live_pid);
    std::fs::write(&announce_path, announce.to_string()).unwrap();

    // The squatter relays every challenge to that live daemon, so it answers with a genuine,
    // well-formed proof, just not one for this address and instance (review: a canned reply with
    // no proof never exercised the HMAC compare).
    let text = std::fs::read_to_string(other.path().join("synapsed.json")).unwrap();
    let live_addr = serde_json::from_str::<Value>(&text).unwrap()["addr"]
        .as_str()
        .unwrap()
        .to_string();
    let squatter = Squatter::bind(&addr, Some(live_addr));
    let out = home.run(&["send", "--role", "alpha", "--to", "alpha", "secret"]);
    let seen = squatter.stop();

    assert!(
        seen.iter()
            .any(|r| r.starts_with("relayed:") && r.contains("\"proof\":\"")),
        "no genuine proof was relayed, so the compare was not exercised: {seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|r| r.contains("authorization:") || r.contains("/v1/claim")),
        "a credential went to the squatter: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|r| r.starts_with("get /v1/health?challenge=")),
        "the squatter was never challenged, so the test proved nothing: {seen:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let warning =
        format!("daemon at {addr} failed its proof; possible port squat; not sending credentials");
    assert_eq!(stderr.matches(&warning).count(), 1, "{stderr}");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    // Hardening P8, row 3 client side: the failed proof is recorded once, like the warning.
    let events = events(home.path());
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["kind"], "proof_failure");
    assert_eq!(events[0]["surface"], "synapsectl/health-proof");
    assert_eq!(events[0]["subject"], addr.as_str());
    let instance_id = announce["instance_id"].as_str().unwrap();
    assert!(
        !events[0].to_string().contains(instance_id),
        "the proof key reached an event: {events:?}"
    );
    let fresh = home.announced_pid().unwrap();
    assert_ne!(fresh, live_pid);
    assert_eq!(spawned_pids(&out), vec![fresh], "a fresh daemon took over");
}

/// #74: `kill` (SIGTERM) stops synapsed gracefully, and it removes its announce file on the way out.
#[cfg(unix)]
#[test]
fn sigterm_removes_the_announce_file() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    let path = home.path().join("synapsed.json");
    assert!(path.exists(), "announced while running");
    let pid = home.announced_pid().unwrap();
    let sent = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    wait_dead(pid);
    assert!(!alive(pid), "synapsed exited on SIGTERM");
    assert!(!path.exists(), "the announce file was removed");
}

/// A refusal whose body is not JSON (axum's own 413 for an oversized body) still names its status.
#[test]
fn a_non_json_refusal_reports_its_http_status() {
    use std::io::Write;
    let home = Home::new();
    home.ok(&["claim", "--role", "beta"]);
    let mut child = home
        .command(&["send", "--role", "beta", "--to", "beta"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&vec![b'x'; 1_700_000])
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("413"), "{err}");
}

/// Opus review (stale-lock race): the role lock is an OS lock, so a lock file left behind blocks
/// nobody, and no lock is ever broken out from under a live holder.
#[test]
fn a_leftover_lock_file_does_not_block_a_claim() {
    let home = Home::new();
    home.ok(&["claim", "--role", "beta"]);
    std::fs::write(home.path().join("sessions").join("alpha.lock"), b"").unwrap();
    let started = Instant::now();
    home.ok(&["claim", "--role", "alpha"]);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the claim waited {:?} on a lock nobody holds",
        started.elapsed()
    );
}

/// #77 M1: while another process holds the role's lock, `claim` gives up after the lock timeout
/// (about 10 s) with an error naming the role; once the lock is released the same claim succeeds.
/// The holder here is the test itself, via `File::lock` on `<home>/sessions/<role>.lock`.
#[test]
fn a_claim_times_out_while_another_holds_the_role_lock_and_succeeds_after() {
    let home = Home::new();
    home.ok(&["claim", "--role", "beta"]); // the daemon is up
    let sessions = home.path().join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(sessions.join("alpha.lock"))
        .unwrap();
    lock.lock().expect("the test takes the exclusive lock");

    let started = Instant::now();
    let out = home.run(&["claim", "--role", "alpha"]);
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("is claiming") && err.contains("alpha"),
        "the refusal should name the role: {err}"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "the claim gave up after {:?}: it did not wait on the lock",
        started.elapsed()
    );

    lock.unlock().expect("the test releases the lock");
    home.ok(&["claim", "--role", "alpha"]);
}

/// Run `synapse claim` against `home`, which no daemon serves yet, so the CLI starts one.
fn claim_in(home: &Path) -> Output {
    ensure_synapsed_built();
    Command::new(env!("CARGO_BIN_EXE_synapse"))
        .args(["claim", "--role", "alpha"])
        .env("SYNAPSE_HOME", home)
        .env("SYNAPSE_ADDR", "127.0.0.1:0")
        .env_remove("SYNAPSE_ROLE")
        .output()
        .expect("the synapse binary runs")
}

/// A daemon that refuses to start says why. The CLI used to start it with stderr discarded, so
/// the user saw only "synapsed exited (exit code: 2) and no daemon answered".
#[test]
fn a_daemon_that_cannot_start_for_want_of_an_account_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let out = claim_in(dir.path());
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no account"), "{err}");
    assert!(
        err.contains(&dir.path().display().to_string()),
        "home not named: {err}"
    );
}

#[test]
fn a_daemon_that_refuses_a_too_open_key_names_the_refusal_and_the_home() {
    let home = Home::new();
    loosen(&home.path().join("account").join("account.key.pem"));
    let out = claim_in(home.path());
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("permissions_too_open"), "{err}");
    assert!(err.contains("account key"), "{err}");
    assert!(
        err.contains(&home.path().display().to_string()),
        "home not named: {err}"
    );
}

/// The file a starting daemon's stderr goes to is owner-only, as the rest of the home is. Unix
/// only: Windows has no mode bits, and its owner-only check is the ACL test above.
#[cfg(unix)]
#[test]
fn the_daemon_start_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    let out = claim_in(home.path());
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let mode = std::fs::metadata(home.path().join("synapsed-start.err"))
        .expect("the start file is left in the home")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
}

/// Positive control: a daemon that starts fine leaks none of its stderr into the CLI's output.
#[test]
fn a_healthy_start_reports_no_daemon_stderr() {
    let home = Home::new();
    let out = claim_in(home.path());
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("listening on"), "{err}");
}

/// The launch-signal client methods against a real daemon: a configured launcher role polls and
/// answers; any other role is refused. (`SYNAPSE_LAUNCHER_ROLES` reaches the daemon the CLI starts.)
#[test]
fn the_client_launch_methods_work_for_the_launcher_role_only() {
    let home = Home::new();
    let first = home
        .command(&["claim", "--role", "agentlife-launcher"])
        .env("SYNAPSE_LAUNCHER_ROLES", "agentlife-launcher")
        .output()
        .expect("the synapse binary runs");
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    home.ok(&["claim", "--role", "beta"]);

    let daemon = synapsed_client::Daemon::connect(home.path()).expect("the daemon is up");
    let waiting = daemon.waiting("agentlife-launcher", 0).expect("polls");
    assert_eq!(waiting["roles"], serde_json::json!([]));
    // A wait above the client's cap is clamped, not a transport error.
    daemon
        .waiting("agentlife-launcher", 600)
        .expect("long poll");

    let epoch = daemon
        .launch_clear("agentlife-launcher", "beta")
        .expect("clears")["epoch"]
        .as_str()
        .expect("an epoch")
        .to_string();
    assert!(!epoch.is_empty());
    let stale = daemon
        .launch_result(
            "agentlife-launcher",
            "beta:none",
            &epoch,
            1,
            "beta",
            synapsed_client::LaunchOutcome::Failed,
            None,
        )
        .expect_err("no open signal");
    assert!(
        matches!(&stale, synapsed_client::MailError::Api { kind, .. } if kind == "stale_signal"),
        "{stale:?}"
    );
    // The daemon parses every wire string the client can send: a valid outcome gets as far as the
    // signal lookup (`stale_signal`), never `malformed`.
    for outcome in synapsed_client::LaunchOutcome::ALL {
        let err = daemon
            .launch_result(
                "agentlife-launcher",
                "beta:none",
                &epoch,
                1,
                "beta",
                outcome,
                None,
            )
            .expect_err("no open signal");
        assert!(
            matches!(&err, synapsed_client::MailError::Api { kind, .. } if kind == "stale_signal"),
            "{} was not accepted by the daemon: {err:?}",
            outcome.as_str()
        );
    }
    // A name that is a launch *state* or a dry run is not an outcome: the daemon says `malformed`.
    for bogus in ["launching", "unreachable", "dry-run"] {
        let body = serde_json::json!({
            "signal_id": "beta:none", "epoch": epoch, "attempt": 1, "role": "beta", "outcome": bogus,
        });
        let err = daemon
            .call("agentlife-launcher", "/v1/launch-result", Some(&body))
            .expect_err("not an outcome");
        assert!(
            matches!(&err, synapsed_client::MailError::Api { kind, .. } if kind == "malformed"),
            "{bogus}: {err:?}"
        );
    }
    let refused = daemon.waiting("beta", 0).expect_err("not a launcher");
    assert!(
        matches!(&refused, synapsed_client::MailError::Api { kind, .. } if kind == "forbidden"),
        "{refused:?}"
    );
}

/// `list --cwd/--repo` keep only roles whose self-reported presence matches exactly. The
/// positive control is the unfiltered list, which holds both roles.
#[test]
fn list_filters_on_reported_cwd_and_repo() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    home.ok(&["claim", "--role", "beta"]);
    let daemon = synapsed_client::Daemon::connect(home.path()).expect("the daemon is running");
    let cwd = r"C:\Projects\a b&c";
    daemon
        .call(
            "alpha",
            "/v1/heartbeat",
            Some(&serde_json::json!({"cwd": cwd, "repo": "ra"})),
        )
        .expect("alpha reports presence");
    daemon
        .call(
            "beta",
            "/v1/heartbeat",
            Some(&serde_json::json!({"cwd": "/other", "repo": "ra"})),
        )
        .expect("beta reports presence");

    let ids = |args: &[&str]| -> Vec<String> {
        let mut argv = vec!["list", "--role", "alpha"];
        argv.extend_from_slice(args);
        let mut ids: Vec<String> = json_lines(&home.ok(&argv))
            .iter()
            .map(|r| r["global_id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(ids(&[]), ["alpha@acct", "beta@acct"], "unfiltered control");
    assert_eq!(ids(&["--cwd", cwd]), ["alpha@acct"]);
    assert_eq!(ids(&["--repo", "ra"]), ["alpha@acct", "beta@acct"]);
    assert_eq!(ids(&["--cwd", "/other", "--repo", "ra"]), ["beta@acct"]);
    assert!(
        ids(&["--cwd", r"C:\Projects"]).is_empty(),
        "exact, not prefix"
    );
}

/// Shared state (S2b) through the real binary: new, show, list, a stale set, a good set, history.
#[test]
fn state_commands_create_show_list_set_and_refuse_a_stale_revision() {
    let home = Home::new();
    let made: Value = serde_json::from_str(&home.ok(&[
        "state",
        "new",
        "--role",
        "alpha",
        "--title",
        "wire it",
        "--party",
        "alpha",
        "--party",
        "beta",
        "--owner",
        "alpha",
        "--verify",
        "crate_version:synapse,ge,6.0.0",
    ]))
    .unwrap();
    assert_eq!(
        (made["id"].as_str(), made["revision"].as_u64()),
        (Some("T-1"), Some(1))
    );
    assert_eq!(made["verify"][0]["fact"], "crate_version:synapse");

    let shown: Value =
        serde_json::from_str(&home.ok(&["state", "show", "--role", "alpha", "T-1"])).unwrap();
    assert_eq!(shown["title"], "wire it");
    let listed = home.ok(&["state", "list", "--role", "alpha", "--state", "open"]);
    assert_eq!(listed.lines().count(), 1);

    let set = home.ok(&[
        "state", "set", "--role", "alpha", "T-1", "--rev", "1", "--state", "waiting",
    ]);
    assert_eq!(serde_json::from_str::<Value>(&set).unwrap()["revision"], 2);
    let stale = home.run(&[
        "state", "set", "--role", "alpha", "T-1", "--rev", "1", "--state", "done",
    ]);
    assert_ne!(stale.status.code(), Some(0), "a stale revision must fail");
    assert!(
        String::from_utf8_lossy(&stale.stderr).contains("stale_revision"),
        "{stale:?}"
    );

    let history = home.ok(&["state", "history", "--role", "alpha", "T-1"]);
    assert_eq!(
        history.lines().count(),
        2,
        "the refused write left no entry"
    );

    let bad = home.run(&[
        "state",
        "new",
        "--role",
        "alpha",
        "--title",
        "t",
        "--party",
        "alpha",
        "--owner",
        "alpha",
        "--verify",
        "not a condition",
    ]);
    assert_eq!(bad.status.code(), Some(2), "{bad:?}");
}

/// A claim never loads the account key: with a valid certificate already in the home, the account
/// key file can be garbage and the state commands (which claim) still work. The old path, which
/// opened the full keystore on every claim, fails here with a corrupt account key.
#[test]
fn the_state_commands_never_load_the_account_key() {
    let home = Home::new();
    home.ok(&["claim", "--role", "alpha"]);
    let key = home.path().join("account").join("account.key.pem");
    assert!(key.exists());
    std::fs::write(&key, b"not a key").unwrap();
    // A fresh claim (the cached session would hide the keystore): it must not open the key.
    home.ok(&["claim", "--role", "alpha"]);

    let made = home.ok(&[
        "state",
        "new",
        "--role",
        "alpha",
        "--title",
        "no key needed",
        "--party",
        "alpha",
        "--owner",
        "alpha",
    ]);
    assert_eq!(serde_json::from_str::<Value>(&made).unwrap()["id"], "T-1");
    let shown = home.ok(&["state", "show", "--role", "alpha", "T-1"]);
    assert_eq!(
        serde_json::from_str::<Value>(&shown).unwrap()["title"],
        "no key needed"
    );
    // Control: the commands that do need the key say so, so the garbage really is in effect.
    let id = home.run(&["id", "show", "--role", "alpha"]);
    assert_ne!(
        id.status.code(),
        Some(0),
        "the corrupted key must be unreadable: {id:?}"
    );
}

/// A stub forge on loopback: answers by path, remembers (path, had a bearer token).
type Seen = std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>>;

fn forge_stub() -> (String, Seen) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = request
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            let auth = request
                .to_ascii_lowercase()
                .contains("authorization: bearer");
            log.lock().unwrap().push((path.clone(), auth));
            let (status, body) = if path == "/api/v1/crates/synapse" {
                (200, r#"{"crate":{"max_version":"6.0.0-rc.168"}}"#)
            } else if path == "/repos/o/r/pulls/7" {
                (
                    200,
                    r#"{"state":"closed","merged_at":"2026-10-24T00:00:00Z"}"#,
                )
            } else if path.starts_with("/repos/o/r/contents/docs/X.md") {
                (404, r#"{"message":"Not Found"}"#)
            } else {
                (500, r#"{"message":"boom"}"#)
            };
            let reason = if status == 200 { "OK" } else { "Error" };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (base, seen)
}

/// The checker, end to end against a stub forge: it reports what it saw, the daemon derives, and a
/// failed lookup answers nothing instead of "absent". The token goes to the GitHub URL only.
#[test]
fn the_checker_reports_forge_facts_and_the_daemon_derives_them() {
    let home = Home::new();
    home.ok(&["id", "grant", "--role", "checker", "state-derive"]);
    let (forge, seen) = forge_stub();
    home.ok(&[
        "state",
        "new",
        "--role",
        "alpha",
        "--title",
        "release",
        "--party",
        "alpha",
        "--owner",
        "alpha",
        "--verify",
        "crate_version:synapse,ge,6.0.0-rc.145",
        "--verify",
        "pr_state:o/r#7,eq,merged",
        "--verify",
        "file_at_ref:o/r@main:docs/X.md,absent",
        "--verify",
        "ref_sha:o/r@main,exists",
    ]);

    // A lane cannot run the checker: the grant is the checker's alone.
    let denied = home.run(&["state", "check", "--role", "alpha", "--once"]);
    assert_ne!(denied.status.code(), Some(0), "{denied:?}");

    let out = home
        .command(&[
            "state",
            "check",
            "--role",
            "checker",
            "--once",
            "--crates-url",
            &forge,
            "--github-url",
            &forge,
        ])
        .env("SYNAPSE_CHECKER_GITHUB_TOKEN", "test-token")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "checked 4 facts: 2 found, 1 absent, 1 failed"
    );

    let shown: Value =
        serde_json::from_str(&home.ok(&["state", "show", "--role", "alpha", "T-1"])).unwrap();
    let verify = &shown["derived"]["verify"];
    assert_eq!(verify[0]["satisfied"], true, "6.0.0-rc.168 >= 6.0.0-rc.145");
    assert_eq!(verify[1]["satisfied"], true, "merged");
    assert_eq!(verify[2]["satisfied"], true, "a 404 is absent");
    assert_eq!(verify[3]["satisfied"], Value::Null, "a 500 answers nothing");
    assert_eq!(verify[3]["error"], "HTTP 500");
    assert_eq!(verify[0]["observed_by"], "checker");
    assert_eq!(
        shown["derived"]["stale"], true,
        "one fact was never observed"
    );
    assert_eq!(shown["derived"]["last_verified"], Value::Null);
    assert_eq!(shown["revision"], 1, "facts are not writes to the record");

    let seen = seen.lock().unwrap();
    assert!(seen.iter().any(|(p, _)| p.starts_with("/api/v1/crates/")));
    assert!(
        seen.iter()
            .filter(|(p, _)| p.starts_with("/repos/"))
            .all(|(_, auth)| *auth),
        "the token goes to GitHub: {seen:?}"
    );
    assert!(
        seen.iter()
            .filter(|(p, _)| p.starts_with("/api/"))
            .all(|(_, auth)| !*auth),
        "and never to crates.io: {seen:?}"
    );
}
