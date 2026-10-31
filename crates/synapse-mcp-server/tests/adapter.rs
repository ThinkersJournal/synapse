// SPDX-License-Identifier: MIT OR Apache-2.0
//! The M6b adapter against a real `synapsed`: every tool, the untrusted-text wording, control
//! characters, a refused call surfacing as a tool error, supersession without a re-claim, secret
//! hygiene, and the stdio process.
//!
//! The daemon is a real `synapsed` process (the client refuses an in-process one: it checks that
//! the announced pid is a live `synapsed`). Tests bind loopback ports, so CireSnave may see a
//! firewall prompt for the new test executable.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::transport::TokioChildProcess;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use synapse::certificate::chain_to_pem;
use synapse::keystore::Keystore;
use synapse::roles::sign_claim_for;
use synapse_mcp_server::{McpConfig, SynapseMcpServer};
use synapsed_client::Daemon;
use tokio::io::AsyncReadExt;

/// `cargo test -p synapse-mcp-server` does not build another package's binary, so build `synapsed`
/// into the directory the client looks in first: next to this package's own binary.
fn exe_dir() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_synapse-mcp"))
        .parent()
        .unwrap()
}

fn ensure_synapsed_built() {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cmd.args(["build", "-p", "synapsed", "--bin", "synapsed"]);
        if exe_dir().file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        assert!(
            cmd.status().expect("cargo runs").success(),
            "building synapsed failed"
        );
        let exe = exe_dir().join(format!("synapsed{}", std::env::consts::EXE_SUFFIX));
        assert!(exe.exists(), "synapsed is not at {}", exe.display());
    });
}

/// Whether a daemon answers at `home`. On its own thread: the client's blocking HTTP client owns a
/// runtime, which panics if dropped inside the async test.
fn connects(home: &Path) -> bool {
    let home = home.to_path_buf();
    std::thread::spawn(move || Daemon::connect_existing(&home).is_ok())
        .join()
        .unwrap_or(false)
}

fn start_daemon(home: &Path) -> std::process::Child {
    let exe = exe_dir().join(format!("synapsed{}", std::env::consts::EXE_SUFFIX));
    Command::new(exe)
        .current_dir(home)
        .env("SYNAPSE_HOME", home)
        .env("SYNAPSE_ADDR", "127.0.0.1:0")
        .env("SYNAPSE_REDELIVERY_GAPS", "")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("synapsed starts")
}

/// A home with an account and a running daemon, killed on drop.
struct Home {
    dir: tempfile::TempDir,
    daemon: std::process::Child,
}

impl Home {
    fn new() -> Home {
        ensure_synapsed_built();
        let dir = tempfile::tempdir().unwrap();
        Keystore::init_account(dir.path(), "acct").expect("init account");
        let daemon = start_daemon(dir.path());
        // Owned by a `Home` first, so a failed wait still kills the daemon.
        let home = Home { dir, daemon };
        home.wait_up();
        home
    }

    /// The announce file is the daemon's own word that it is up; then it must answer the proof.
    fn wait_up(&self) {
        let announce = self.path().join("synapsed.json");
        let deadline = Instant::now() + Duration::from_secs(15);
        while !(announce.exists() && connects(self.path())) {
            assert!(Instant::now() < deadline, "synapsed never announced");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Kill the daemon and start another at the same home: a new instance id, no sessions.
    fn restart(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        // The dead daemon's announce file would pass `wait_up` before the new one writes its own.
        let _ = std::fs::remove_file(self.path().join("synapsed.json"));
        self.daemon = start_daemon(self.path());
        self.wait_up();
    }

    /// Kill the daemon and leave it down, with no announce file.
    fn stop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        let _ = std::fs::remove_file(self.path().join("synapsed.json"));
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn config(&self, role: &str) -> McpConfig {
        McpConfig {
            role: role.to_string(),
            home: self.path().to_path_buf(),
        }
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

/// An adapter and an in-memory MCP client wired to it.
struct Agent {
    client: RunningService<RoleClient, ()>,
    transcript: std::sync::Mutex<Vec<String>>,
}

async fn agent(home: &Home, role: &str) -> Agent {
    let server = SynapseMcpServer::start(home.config(role))
        .await
        .expect("adapter starts");
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    Agent {
        client: ().serve(client_io).await.expect("MCP handshake"),
        transcript: std::sync::Mutex::new(Vec::new()),
    }
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text())
        .map(|t| t.text.clone())
        .collect()
}

impl Agent {
    async fn raw(&self, name: &str, args: Value) -> CallToolResult {
        let mut params = CallToolRequestParams::new(name.to_string());
        if let Value::Object(map) = args {
            params = params.with_arguments(map);
        }
        let result = self.client.call_tool(params).await.expect("call_tool");
        self.transcript.lock().unwrap().push(text_of(&result));
        result
    }

    async fn ok(&self, name: &str, args: Value) -> Value {
        let result = self.raw(name, args).await;
        let text = text_of(&result);
        assert_ne!(result.is_error, Some(true), "{name} failed: {text}");
        serde_json::from_str(&text).expect("tool output is JSON")
    }

    /// The text of a tool error; fails if the call succeeded.
    async fn refused(&self, name: &str, args: Value) -> String {
        let result = self.raw(name, args).await;
        assert_eq!(result.is_error, Some(true), "{name} should fail");
        text_of(&result)
    }
}

/// When `role` was last heard from, as the daemon's `list` reports it to the watching `agent`.
async fn last_seen(watcher: &Agent, role: &str) -> chrono::DateTime<chrono::Utc> {
    let roles = watcher.ok("list", json!({})).await;
    let row = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == format!("{role}@acct"))
        .unwrap_or_else(|| panic!("{role} is not listed: {roles}"));
    row["last_seen"]
        .as_str()
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| panic!("{role} has no last_seen: {row}"))
}

/// ROADMAP row 39 (the M6b "no heartbeat test"): an adapter keeps its role online on its own, by a
/// heartbeat every interval, with no tool call made. The interval is injectable so the test does not
/// wait 30 s; the control is an adapter on the default interval, which must NOT beat in the same time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_adapter_heartbeats_on_its_own_at_its_interval() {
    let home = Home::new();
    let watcher = agent(&home, "watcher").await;
    let _quick =
        SynapseMcpServer::start_with_heartbeat(home.config("quick"), Duration::from_millis(150))
            .await
            .expect("adapter starts");
    let _slow = SynapseMcpServer::start(home.config("slow"))
        .await
        .expect("adapter starts");

    let (quick_first, slow_first) = (
        last_seen(&watcher, "quick").await,
        last_seen(&watcher, "slow").await,
    );
    tokio::time::sleep(Duration::from_millis(900)).await;
    let (quick_later, slow_later) = (
        last_seen(&watcher, "quick").await,
        last_seen(&watcher, "slow").await,
    );
    assert!(
        quick_later - quick_first >= chrono::Duration::milliseconds(600),
        "a 150 ms heartbeat moved last_seen by only {}",
        quick_later - quick_first
    );
    assert_eq!(
        slow_later, slow_first,
        "control: the 30 s default has not beaten yet"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tool_set_and_the_untrusted_wording() {
    let home = Home::new();
    let alice = agent(&home, "alice").await;
    let tools = alice.client.list_all_tools().await.unwrap();
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(
        names,
        ["ack", "fetch", "list", "send", "set_summary", "whoami"]
    );
    for name in ["fetch", "list"] {
        let tool = tools.iter().find(|t| t.name == name).unwrap();
        let description = tool.description.as_deref().unwrap_or("");
        assert!(description.contains("UNTRUSTED"), "{name}: {description}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_fetch_ack_list_summary_and_whoami() {
    let home = Home::new();
    let alice = agent(&home, "alice").await;
    let bob = agent(&home, "bob").await;

    let me = alice.ok("whoami", json!({})).await;
    assert_eq!(me["role"], "alice");
    assert_eq!(me["global_id"], "alice@acct");
    assert!(me["epoch"].as_u64().unwrap() >= 1);
    assert!(!me["daemon_instance"].as_str().unwrap().is_empty());
    // The generic adapter pushes nothing, and says so rather than leaving the field out.
    assert_eq!(me.get("push"), Some(&serde_json::Value::Null), "{me}");

    // A bare role is in the sender's account; a duplicate id is a duplicate, not a second copy.
    let sent = alice
        .ok(
            "send",
            json!({"to": "bob", "body": "hello bob", "message_id": "m1"}),
        )
        .await;
    assert_eq!(sent["outcome"], "queued");
    let again = alice
        .ok(
            "send",
            json!({"to": "bob@acct", "body": "hello bob", "message_id": "m1"}),
        )
        .await;
    assert_eq!(again["outcome"], "duplicate");

    let fetched = bob.ok("fetch", json!({})).await;
    let messages = fetched["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1, "{fetched}");
    assert_eq!(messages[0]["body"], "hello bob");
    assert_eq!(messages[0]["from"], "alice@acct");
    let id = messages[0]["message_id"].as_str().unwrap().to_string();
    // Leased, so a second fetch is empty until the lease ends.
    assert!(
        bob.ok("fetch", json!({})).await["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        bob.ok("ack", json!({"message_id": id})).await["outcome"],
        "removed"
    );

    // A message with no id of its own still gets one.
    let anon = alice
        .ok("send", json!({"to": "bob", "body": "no id"}))
        .await;
    assert!(!anon["message_id"].as_str().unwrap().is_empty());

    alice
        .ok("set_summary", json!({"summary": "writing tests"}))
        .await;
    let roles = bob.ok("list", json!({})).await;
    let alice_row = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == "alice@acct")
        .unwrap_or_else(|| panic!("alice is not listed: {roles}"));
    assert_eq!(alice_row["summary"], "writing tests");
    assert_eq!(alice_row["online"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_characters_in_a_body_or_a_summary_cannot_reach_the_model_raw() {
    let home = Home::new();
    let alice = agent(&home, "alice").await;
    let bob = agent(&home, "bob").await;

    alice
        .ok(
            "send",
            json!({"to": "bob", "body": "a\u{1b}[2Jb\nline two\u{7}"}),
        )
        .await;
    let fetched = bob.ok("fetch", json!({})).await;
    let body = fetched["messages"][0]["body"].as_str().unwrap();
    assert_eq!(body, "a\\u{1b}[2Jb\nline two\\u{7}", "{fetched}");

    // The daemon refuses a control character in a summary; the adapter says so first.
    let refusal = alice
        .refused("set_summary", json!({"summary": "x\u{1b}[0m"}))
        .await;
    assert!(refusal.contains("control character"), "{refusal}");
    let refusal = alice
        .refused("set_summary", json!({"summary": "y".repeat(501)}))
        .await;
    assert!(refusal.contains("500"), "{refusal}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_call_and_an_unknown_recipient_are_tool_errors() {
    let home = Home::new();
    let alice = agent(&home, "alice").await;
    let refusal = alice
        .refused(
            "send",
            json!({"to": "alice", "body": "x", "message_id": "i".repeat(1000)}),
        )
        .await;
    assert!(refusal.contains("malformed"), "{refusal}");
    let refusal = alice
        .refused("send", json!({"to": "nobody", "body": "x"}))
        .await;
    assert!(refusal.contains("unknown_recipient"), "{refusal}");
    // The adapter is still usable after a refusal.
    alice.ok("whoami", json!({})).await;
}

/// Claim `role` directly over HTTP, bypassing the home's session cache, as another holder would.
fn rival_claim(home: &Home, role: &str) -> u64 {
    let announce: Value =
        serde_json::from_str(&std::fs::read_to_string(home.path().join("synapsed.json")).unwrap())
            .unwrap();
    let addr = announce["addr"].as_str().unwrap();
    let instance = announce["instance_id"].as_str().unwrap();
    let identity = Keystore::open(home.path())
        .unwrap()
        .role(role, chrono::Utc::now())
        .unwrap();
    // The daemon refuses claims signed at or before its start; the adapter's claims were later.
    let signed_at = chrono::Utc::now() + chrono::Duration::seconds(1);
    let req = sign_claim_for(
        &identity,
        instance,
        *uuid::Uuid::new_v4().as_bytes(),
        signed_at,
    )
    .unwrap();
    let body = json!({
        "audience": req.audience,
        "chain_pem": chain_to_pem(&req.chain),
        "nonce_hex": req.nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "signed_at": req.signed_at.to_rfc3339(),
        "signature_b64": B64.encode(&req.signature),
    });
    let http = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let resp = http
        .post(format!("http://{addr}/v1/claim"))
        .json(&body)
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "rival claim refused: {:?}",
        resp.text()
    );
    resp.json::<Value>().unwrap()["epoch"].as_u64().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_superseded_adapter_reports_it_and_does_not_claim_the_role_back() {
    let home = Home::new();
    let alice = agent(&home, "alice").await;
    let before = alice.ok("whoami", json!({})).await["epoch"]
        .as_u64()
        .unwrap();

    let taken = tokio::task::block_in_place(|| rival_claim(&home, "alice"));
    assert_eq!(taken, before + 1);

    // The adapter's cached session is now stale. Each tool reports it; none re-claims.
    // (Another holder in a different home is the real case; the cache is per home, so here the
    // rival claimed around it.)
    for (tool, args) in [
        ("fetch", json!({})),
        ("whoami", json!({})),
        ("list", json!({})),
    ] {
        let refusal = alice.refused(tool, args).await;
        assert!(refusal.contains("superseded"), "{tool}: {refusal}");
        assert!(refusal.contains("synapse claim"), "{tool}: {refusal}");
    }
    // The claim count: a re-claim by the adapter would make the next rival epoch jump by two.
    let next = tokio::task::block_in_place(|| rival_claim(&home, "alice"));
    assert_eq!(next, taken + 1, "the adapter claimed the role back");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_key_path_or_key_bytes_reach_any_result_or_error() {
    let home = Home::new();
    let alice = agent(&home, "alice").await;
    let bob = agent(&home, "bob").await;
    alice.ok("send", json!({"to": "bob", "body": "hi"})).await;
    bob.ok("fetch", json!({})).await;
    alice
        .refused("send", json!({"to": "nobody", "body": "x"}))
        .await;
    alice.ok("list", json!({})).await;

    let home_text = home.path().to_string_lossy().to_string();
    let transcript =
        alice.transcript.lock().unwrap().join("\n") + &bob.transcript.lock().unwrap().join("\n");
    // Positive control: the transcript holds real output, and the home really holds key files.
    assert!(transcript.contains("alice@acct"), "{transcript}");
    let has_key_file = std::fs::read_dir(home.path()).unwrap().flatten().any(|e| {
        let n = e.file_name().to_string_lossy().to_lowercase();
        n.contains("key") || n.contains("role") || n.contains("account")
    });
    assert!(has_key_file, "the home holds no key material to leak");
    for needle in [
        home_text.as_str(),
        &home_text.replace('\\', "/"),
        "PRIVATE KEY",
    ] {
        assert!(!transcript.contains(needle), "leaked {needle:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_adapter_never_starts_a_daemon() {
    // The positive control: `synapsed` is built next to this binary, so the spawning client would
    // find it and start one here.
    ensure_synapsed_built();
    let dir = tempfile::tempdir().unwrap();
    Keystore::init_account(dir.path(), "acct").expect("init account");
    let err = SynapseMcpServer::start(McpConfig {
        role: "alice".into(),
        home: dir.path().to_path_buf(),
    })
    .await
    .err()
    .expect("no daemon, so the adapter fails to start");
    assert!(err.contains("not running"), "{err}");
    // Give a daemon spawned by mistake time to announce itself before concluding it was not.
    std::thread::sleep(Duration::from_millis(500));
    for leftover in ["synapsed.json", "synapsed-start.err"] {
        assert!(!dir.path().join(leftover).exists(), "{leftover} exists");
    }
}

/// The 2026-10-30 reconnect measurement saw a daemon back within ~2 s of a kill and blamed the
/// adapter. A RUNNING adapter, with its daemon gone and the variable unset, calls, heartbeats and
/// re-attaches, and still starts nothing (the other test covers startup). The control is that
/// `synapsed` sits next to this binary, so a spawning client would find it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_adapter_whose_daemon_died_starts_no_replacement() {
    let mut home = Home::new();
    let alice = agent(&home, "alice").await;
    alice.ok("list", json!({})).await;

    home.stop();
    for _ in 0..3 {
        assert!(!alice.refused("list", json!({})).await.is_empty());
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    for leftover in ["synapsed.json", "synapsed-start.err"] {
        assert!(!home.path().join(leftover).exists(), "{leftover} exists");
    }
    assert!(!connects(home.path()), "a daemon answers at the home");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_adapter_re_attaches_to_a_restarted_daemon_and_not_after_a_takeover() {
    let mut home = Home::new();
    let alice = agent(&home, "alice").await;
    let before = alice.ok("whoami", json!({})).await["daemon_instance"].clone();
    alice.ok("list", json!({})).await;

    home.restart();
    // The first call after the restart fails (its daemon is gone) and re-attaches; the next works.
    let first = alice.refused("list", json!({})).await;
    assert!(!first.is_empty());
    alice.ok("list", json!({})).await;
    let after = alice.ok("whoami", json!({})).await["daemon_instance"].clone();
    assert_ne!(before, after, "still attached to the old daemon instance");

    // A takeover under the same instance is a human's to answer: no re-attach, no re-claim.
    tokio::task::block_in_place(|| rival_claim(&home, "alice"));
    let refusal = alice.refused("list", json!({})).await;
    assert!(refusal.contains("superseded"), "{refusal}");
    let again = alice.refused("list", json!({})).await;
    assert!(again.contains("superseded"), "{again}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_role_is_a_startup_error_not_a_guess() {
    let home = Home::new();
    for role in ["", "has space", "a/b", &"r".repeat(65)] {
        let err = SynapseMcpServer::start(home.config(role)).await.err();
        let err = err.unwrap_or_else(|| panic!("{role:?} was accepted"));
        assert!(err.contains("role name"), "{err}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stdio_process_serves_the_tools_and_leaks_nothing() {
    let home = Home::new();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_synapse-mcp"));
    command
        .arg("--role")
        .arg("alice")
        .arg("--home")
        .arg(home.path());
    let (transport, stderr) = TokioChildProcess::builder(command)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synapse-mcp");
    let mut stderr = stderr.expect("stderr is piped");
    let stderr = tokio::spawn(async move {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text).await;
        text
    });
    let client = ().serve(transport).await.expect("MCP handshake");
    let result = client
        .call_tool(CallToolRequestParams::new("whoami".to_string()))
        .await
        .unwrap();
    let who: Value = serde_json::from_str(&text_of(&result)).unwrap();
    assert_eq!(who["global_id"], "alice@acct");
    client.cancel().await.unwrap();
    let log = stderr.await.unwrap();
    let home_text = home.path().to_string_lossy().to_string();
    assert!(
        !log.contains(&home_text) && !log.contains("PRIVATE KEY"),
        "{log}"
    );
}

#[test]
fn no_role_is_a_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_synapse-mcp"))
        .env_remove("SYNAPSE_ROLE")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("usage"),
        "{out:?}"
    );
}
