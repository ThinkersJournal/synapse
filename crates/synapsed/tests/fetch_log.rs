// SPDX-License-Identifier: MIT OR Apache-2.0
//! The per-lease debug line (ROADMAP row 56): on only when asked, one line per leased message, naming
//! the role, id, attempt and lease times, and never the body.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use synapse::certificate::{Permission, chain_to_pem};
use synapse::keystore::Keystore;
use synapse::roles::sign_claim_for;
use synapsed::{Daemon, DaemonConfig};

struct Running {
    addr: SocketAddr,
    home: tempfile::TempDir,
    started_at: DateTime<Utc>,
    /// Held so the test's own shutdown future never fires.
    _stop: tokio::sync::oneshot::Sender<()>,
    _task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl Running {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

/// A daemon with the given fetch log.
async fn start_log(grants: &[(&str, Permission)], log: synapsed::FetchLog) -> Running {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let store = Keystore::open(home.path()).unwrap();
    for (role, permission) in grants {
        store.grant(role, permission).unwrap();
    }
    let cfg = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    };
    common::allow_all(&cfg.home);
    let daemon = Daemon::open(&cfg)
        .expect("open daemon")
        .with_redelivery_gaps(vec![chrono::Duration::milliseconds(300); 3])
        .with_fetch_log(log)
        .with_redelivery_check(Duration::from_millis(50));
    let started_at = daemon.started_at();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.serve(listener, async move {
        let _ = rx.await;
    }));
    let announce = home.path().join("synapsed.json");
    for _ in 0..200 {
        if announce.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Running {
        addr,
        home,
        started_at,
        _stop: tx,
        _task: Some(task),
    }
}

fn instance_id(d: &Running) -> String {
    let text = std::fs::read_to_string(d.home.path().join("synapsed.json")).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    v["instance_id"].as_str().unwrap().to_string()
}

async fn claim(d: &Running, role: &str) -> String {
    let store = Keystore::open(d.home.path()).unwrap();
    let identity = store.role(role, Utc::now()).unwrap();
    let signed_at = Utc::now().max(d.started_at + chrono::Duration::seconds(1));
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let req = sign_claim_for(&identity, &instance_id(d), nonce, signed_at).unwrap();
    let body = json!({
        "audience": req.audience,
        "chain_pem": chain_to_pem(&req.chain),
        "nonce_hex": req.nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "signed_at": req.signed_at.to_rfc3339(),
        "signature_b64": B64.encode(&req.signature),
    });
    let reply = reqwest::Client::new()
        .post(d.url("/v1/claim"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status().as_u16(), 200);
    let reply: Value = reply.json().await.unwrap();
    reply["session"].as_str().unwrap().to_string()
}

async fn call(d: &Running, token: Option<&str>, path: &str, body: Option<Value>) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut req = match &body {
        Some(b) => client.post(d.url(path)).json(b),
        None => client.get(d.url(path)),
    };
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let value = resp.json().await.unwrap_or(Value::Null);
    (status, value)
}

async fn fetch(d: &Running, token: &str) -> Vec<Value> {
    let (status, reply) = call(d, Some(token), "/v1/fetch", Some(json!({"lease_secs": 5}))).await;
    assert_eq!(status, 200, "{reply}");
    reply["messages"].as_array().cloned().unwrap_or_default()
}

async fn send(d: &Running, token: &str, id: &str, text: &str) {
    let (status, reply) = call(
        d,
        Some(token),
        "/v1/send",
        Some(json!({"to": "b@acct", "message_id": id, "body_b64": B64.encode(text.as_bytes())})),
    )
    .await;
    assert_eq!(status, 200, "{reply}");
}

#[tokio::test]
async fn the_fetch_line_appears_only_when_on_and_never_carries_the_body() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let on = start_log(&[], synapsed::FetchLog::Capture(lines.clone())).await;
    let a = claim(&on, "a").await;
    let b = claim(&on, "b").await;
    send(&on, &a, "m1", "SECRET-BODY-TEXT").await;
    assert_eq!(fetch(&on, &b).await.len(), 1);
    assert!(fetch(&on, &b).await.is_empty(), "hidden: no second line");
    {
        let got = lines.lock().unwrap();
        assert_eq!(got.len(), 1, "one line for one lease: {got:?}");
        let line = &got[0];
        assert!(
            line.starts_with("fetch-lease role=b@acct message_id=a@acct/m1 attempts=1 leased_at="),
            "{line}"
        );
        assert!(line.contains(" lease_until="), "{line}");
        assert!(!line.contains("SECRET"), "no body bytes: {line}");
        assert!(!line.contains(&B64.encode("SECRET-BODY-TEXT")), "{line}");
    }

    // Off by default: the same traffic writes nothing (the capture sink is the only way to see it).
    let off = start_log(&[], synapsed::FetchLog::Off).await;
    let a = claim(&off, "a").await;
    let b = claim(&off, "b").await;
    send(&off, &a, "m1", "SECRET-BODY-TEXT").await;
    assert_eq!(fetch(&off, &b).await.len(), 1);
    assert_eq!(
        lines.lock().unwrap().len(),
        1,
        "the off daemon wrote nothing to the sink"
    );
}
