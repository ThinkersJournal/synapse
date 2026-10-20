// SPDX-License-Identifier: MIT OR Apache-2.0
//! The agent against a real `synapsed` and a local OpenAI-compatible mock model: mail in, the
//! model's text out to the sender, the message acknowledged. No network, no key.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use synapse::keystore::Keystore;
use synapse_agent::{Agent, GenaiResponder, Responder, StepReport};
use synapse_mcp_server::{McpConfig, SynapseMcpServer};
use synapsed_client::Daemon;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn exe_dir() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_synapse-agent"))
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
    });
}

/// Whether a daemon answers at `home`; on its own thread because the blocking client owns a runtime.
fn connects(home: &Path) -> bool {
    let home = home.to_path_buf();
    std::thread::spawn(move || Daemon::connect(&home).is_ok())
        .join()
        .unwrap_or(false)
}

/// Run a blocking daemon call off the async test thread. The client is dropped on a plain thread:
/// a blocking reqwest client panics if dropped on an async worker.
async fn call(home: &Path, role: &str, path: &'static str, body: Option<Value>) -> Value {
    let (home, role) = (home.to_path_buf(), role.to_string());
    tokio::task::spawn_blocking(move || {
        let daemon = Daemon::connect(&home).expect("daemon");
        let out = daemon.call(&role, path, body.as_ref()).expect("call");
        std::thread::spawn(move || drop(daemon));
        out
    })
    .await
    .unwrap()
}

struct Home {
    dir: tempfile::TempDir,
    daemon: std::process::Child,
}

impl Home {
    fn new() -> Home {
        ensure_synapsed_built();
        let dir = tempfile::tempdir().unwrap();
        Keystore::init_account(dir.path(), "acct").expect("init account");
        let exe = exe_dir().join(format!("synapsed{}", std::env::consts::EXE_SUFFIX));
        let daemon = Command::new(exe)
            .current_dir(dir.path())
            .env("SYNAPSE_HOME", dir.path())
            .env("SYNAPSE_ADDR", "127.0.0.1:0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("synapsed starts");
        let home = Home { dir, daemon };
        let deadline = Instant::now() + Duration::from_secs(15);
        while !(home.path().join("synapsed.json").exists() && connects(home.path())) {
            assert!(Instant::now() < deadline, "synapsed never announced");
            std::thread::sleep(Duration::from_millis(50));
        }
        home
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    async fn server(&self, role: &str) -> SynapseMcpServer {
        SynapseMcpServer::start(McpConfig {
            role: role.to_string(),
            home: self.path().to_path_buf(),
        })
        .await
        .expect("adapter starts")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

/// What the mock model says.
#[derive(Clone, Copy)]
enum Say {
    Text(&'static str),
    /// A 500.
    Fail,
    /// A call of tool `name` with JSON `arguments`.
    Tool(&'static str, &'static str),
}

/// A local OpenAI-compatible `chat/completions` endpoint. `answers` are served in order (the
/// last repeats). Every request body is recorded.
struct Mock {
    url: String,
    seen: Arc<Mutex<Vec<Value>>>,
}

async fn mock(answers: Vec<Say>) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1/", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut n = 0usize;
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let body = loop {
                let mut chunk = [0u8; 4096];
                let Ok(read) = sock.read(&mut chunk).await else {
                    break None;
                };
                if read == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..read]);
                if let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..split]).to_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if buf.len() >= split + 4 + len {
                        break Some(buf[split + 4..split + 4 + len].to_vec());
                    }
                }
            };
            let Some(body) = body else { continue };
            log.lock()
                .unwrap()
                .push(serde_json::from_slice(&body).unwrap_or(Value::Null));
            let answer = answers[n.min(answers.len() - 1)];
            n += 1;
            let reply = match answer {
                Say::Text(_) | Say::Tool(..) => {
                    let (finish, message) = match answer {
                        Say::Tool(name, arguments) => (
                            "tool_calls",
                            json!({"role": "assistant", "content": null, "tool_calls": [{
                                "id": "call_1", "type": "function",
                                "function": {"name": name, "arguments": arguments}}]}),
                        ),
                        Say::Text(text) => ("stop", json!({"role": "assistant", "content": text})),
                        Say::Fail => unreachable!(),
                    };
                    let payload = json!({"id": "x", "object": "chat.completion", "created": 0,
                        "model": "mock-model",
                        "choices": [{"index": 0, "finish_reason": finish, "message": message}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
                    .to_string();
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                        payload.len()
                    )
                }
                Say::Fail => "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string(),
            };
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    Mock { url, seen }
}

fn responder(mock: &Mock) -> GenaiResponder {
    // The key is read from this variable by name; a test value, not a secret.
    unsafe { std::env::set_var("SYNAPSE_AGENT_TEST_KEY", "test-key") };
    GenaiResponder::openai_compatible("mock-model", &mock.url, "SYNAPSE_AGENT_TEST_KEY")
}

async fn send(home: &Home, from: &str, to: &str, id: &str, text: &str) {
    let to = format!("{to}@acct");
    let body = synapsed_client::encode_body(text.as_bytes());
    call(
        home.path(),
        from,
        "/v1/send",
        Some(json!({"to": to, "message_id": id, "body_b64": body})),
    )
    .await;
}

async fn inbox(home: &Home, role: &str) -> Vec<Value> {
    let reply = call(
        home.path(),
        role,
        "/v1/fetch",
        Some(json!({"max": 20, "lease_secs": 5})),
    )
    .await;
    reply["messages"].as_array().cloned().unwrap_or_default()
}

fn text(message: &Value) -> String {
    synapsed_client::inbox_line(message)["body"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_is_answered_by_the_model_and_acknowledged() {
    let home = Home::new();
    let model = mock(vec![Say::Text("FOUR")]).await;
    // Both roles must exist before mail is addressed to them.
    let _boss = home.server("boss").await;
    let agent = Agent::new(home.server("bot").await, responder(&model)).with_lease_secs(5);
    send(&home, "boss", "bot", "q1", "what is 2+2?").await;

    let report = agent.step().await.expect("a pass");
    assert_eq!(
        report,
        StepReport {
            answered: 1,
            failed: 0,
            dropped: 0
        }
    );

    let got = inbox(&home, "boss").await;
    assert_eq!(got.len(), 1, "boss gets exactly the reply: {got:?}");
    assert_eq!(text(&got[0]), "FOUR");
    assert!(
        got[0]["from"].as_str().unwrap().starts_with("bot@"),
        "the reply is from the agent's role"
    );

    let seen = model.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "one model call");
    let request = seen[0].to_string();
    assert!(
        request.contains("what is 2+2?"),
        "the model saw the mail: {request}"
    );
    assert!(
        seen[0].get("tools").is_none(),
        "no tools unless asked for: {request}"
    );
    assert!(
        request.contains("untrusted"),
        "and was told it is untrusted: {request}"
    );

    // Acknowledged: nothing waits for the agent, even after a lease would have expired.
    tokio::time::sleep(Duration::from_millis(5300)).await;
    assert_eq!(agent.step().await.unwrap(), StepReport::default());
    assert_eq!(model.seen.lock().unwrap().len(), 1, "no second model call");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_failure_leaves_the_message_leased_and_the_next_pass_retries_it() {
    let home = Home::new();
    let model = mock(vec![Say::Fail, Say::Text("RECOVERED")]).await;
    let _boss = home.server("boss").await;
    let agent = Agent::new(home.server("bot").await, responder(&model)).with_lease_secs(5);
    send(&home, "boss", "bot", "q1", "hello").await;

    let first = agent.step().await.expect("a pass");
    assert_eq!(
        first,
        StepReport {
            answered: 0,
            failed: 1,
            dropped: 0
        }
    );
    assert!(inbox(&home, "boss").await.is_empty(), "no reply on failure");

    tokio::time::sleep(Duration::from_millis(5300)).await;
    let second = agent.step().await.expect("a pass");
    assert_eq!(
        second,
        StepReport {
            answered: 1,
            failed: 0,
            dropped: 0
        }
    );
    assert_eq!(text(&inbox(&home, "boss").await[0]), "RECOVERED");
}

struct Failing;
impl Responder for Failing {
    async fn reply(&self, _id: &str, _from: &str, _body: &str) -> Result<String, String> {
        Err("always".into())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_that_keeps_failing_is_dropped_after_max_attempts() {
    let home = Home::new();
    let _boss = home.server("boss").await;
    let agent = Agent::new(home.server("bot").await, Failing).with_lease_secs(5);
    send(&home, "boss", "bot", "poison", "x").await;

    let mut total = StepReport::default();
    for _ in 0..synapse_agent::MAX_ATTEMPTS + 1 {
        let r = agent.step().await.expect("a pass");
        total.failed += r.failed;
        total.dropped += r.dropped;
        tokio::time::sleep(Duration::from_millis(5300)).await;
    }
    assert_eq!(
        total.failed,
        synapse_agent::MAX_ATTEMPTS as usize - 1,
        "{total:?}"
    );
    assert_eq!(total.dropped, 1, "{total:?}");
    assert_eq!(
        agent.step().await.unwrap(),
        StepReport::default(),
        "gone for good"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_model_can_send_to_an_allowed_role_and_not_to_any_other() {
    let home = Home::new();
    // Turn 1 asks to send to ops, turn 2 to a role off the list, turn 3 answers.
    let model = mock(vec![
        Say::Tool("send_message", r#"{"to":"ops","body":"disk is full"}"#),
        Say::Tool("send_message", r#"{"to":"other","body":"leak"}"#),
        Say::Text("DONE"),
    ])
    .await;
    let _boss = home.server("boss").await;
    let ops = home.server("ops").await;
    let _other = home.server("other").await;
    let bot = home.server("bot").await;
    let responder = responder(&model).with_send_tool(bot.clone(), vec!["ops".to_string()]);
    let agent = Agent::new(bot, responder).with_lease_secs(5);
    send(&home, "boss", "bot", "q1", "tell ops").await;

    let report = agent.step().await.expect("a pass");
    assert_eq!(
        report,
        StepReport {
            answered: 1,
            failed: 0,
            dropped: 0
        }
    );

    let to_ops = inbox(&home, "ops").await;
    assert_eq!(to_ops.len(), 1, "ops got the one allowed send: {to_ops:?}");
    assert_eq!(text(&to_ops[0]), "disk is full");
    assert!(
        inbox(&home, "other").await.is_empty(),
        "nothing off the list"
    );
    assert_eq!(text(&inbox(&home, "boss").await[0]), "DONE");

    let seen = model.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "three model turns");
    assert!(seen[0]["tools"].to_string().contains("send_message"));
    let last = seen[2].to_string();
    assert!(
        last.contains("sent"),
        "the model was told it was sent: {last}"
    );
    assert!(
        last.contains("refused"),
        "and that the other was refused: {last}"
    );
    drop(ops);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_call_without_the_tool_is_refused_and_a_runaway_model_is_cut_off() {
    let home = Home::new();
    // The model never stops asking for a tool this agent was not given.
    let model = mock(vec![Say::Tool(
        "send_message",
        r#"{"to":"ops","body":"x"}"#,
    )])
    .await;
    let _boss = home.server("boss").await;
    let _ops = home.server("ops").await;
    let agent = Agent::new(home.server("bot").await, responder(&model)).with_lease_secs(5);
    send(&home, "boss", "bot", "q1", "go").await;

    let report = agent.step().await.expect("a pass");
    assert_eq!(report.failed, 1, "{report:?}");
    assert_eq!(model.seen.lock().unwrap().len(), 4, "cut off after 4 turns");
    assert!(inbox(&home, "ops").await.is_empty(), "nothing was sent");
}
