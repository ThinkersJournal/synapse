// SPDX-License-Identifier: MIT OR Apache-2.0
//! Firm acks, back-off and dead letters (ROADMAP row 41, CireSnave 2026-10-31): an unacked message is
//! redelivered on a growing schedule, set aside as dead when it runs out, and its sender gets one
//! `[UNACKED]` notice; an ack stops all of it; a notice is never itself reported.

use std::net::SocketAddr;
use std::time::Duration;

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

/// A daemon whose account has granted `grants` (role, permission) before anyone claims.
async fn start(grants: &[(&str, Permission)]) -> Running {
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
    let daemon = Daemon::open(&cfg)
        .expect("open daemon")
        .with_redelivery_gaps(vec![chrono::Duration::milliseconds(300); 3])
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

async fn dead_lettered(d: &Running, token: &str, who: &str) -> u64 {
    let (_, stats) = call(d, Some(token), "/v1/stats", None).await;
    stats["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == format!("{who}@acct"))
        .unwrap()["dead_lettered"]
        .as_u64()
        .unwrap()
}

fn text(message: &Value) -> String {
    String::from_utf8(B64.decode(message["body_b64"].as_str().unwrap()).unwrap()).unwrap()
}

#[tokio::test]
async fn an_unacked_message_backs_off_goes_dead_and_tells_its_sender_once() {
    let d = start(&[]).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    send(&d, &a, "m1", "[STATUS] lane=a doing=x").await;

    let first = fetch(&d, &b).await;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0]["attempts"], 1);
    assert!(
        fetch(&d, &b).await.is_empty(),
        "hidden for the gap, not for the requested 5 s"
    );
    for attempt in [2, 3] {
        tokio::time::sleep(Duration::from_millis(350)).await;
        let again = fetch(&d, &b).await;
        assert_eq!(again.len(), 1, "attempt {attempt}");
        assert_eq!(again[0]["attempts"], attempt);
    }
    // The third lease runs out: the message is dead and the sender is told.
    let mut notice = Vec::new();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        notice = fetch(&d, &a).await;
        if !notice.is_empty() {
            break;
        }
    }
    assert_eq!(notice.len(), 1, "one notice");
    let body = text(&notice[0]);
    assert!(
        body.starts_with("[UNACKED] to=b id=a@acct/m1 age=") && body.ends_with(" attempts=3"),
        "{body}"
    );
    assert_eq!(notice[0]["from"], "synapsed@acct");
    assert_eq!(dead_lettered(&d, &a, "b").await, 1);
    let (_, list) = call(&d, Some(&a), "/v1/list", None).await;
    let b_row = list["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == "b@acct")
        .unwrap();
    assert_eq!(b_row["pending"]["dead"], 1, "visible in list: {b_row}");
    assert!(fetch(&d, &b).await.is_empty(), "dead is not redelivered");

    // The notice is never itself reported: a never acks it, it runs out its own deliveries and goes
    // dead quietly, and nothing new reaches a (or the daemon's own inbox).
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(
            fetch(&d, &a).await.len(),
            1,
            "the notice is redelivered like any message"
        );
    }
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(fetch(&d, &a).await.is_empty(), "no notice about the notice");
    assert_eq!(dead_lettered(&d, &a, "a").await, 1, "it went dead, counted");
}

#[tokio::test]
async fn an_ack_at_the_second_attempt_stops_redelivery_and_sends_no_notice() {
    let d = start(&[]).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    send(&d, &a, "m2", "[STATUS] lane=a doing=y").await;
    assert_eq!(fetch(&d, &b).await.len(), 1);
    tokio::time::sleep(Duration::from_millis(350)).await;
    let again = fetch(&d, &b).await;
    assert_eq!(again[0]["attempts"], 2);
    let (status, _) = call(
        &d,
        Some(&b),
        "/v1/ack",
        Some(json!({"message_id": again[0]["message_id"]})),
    )
    .await;
    assert_eq!(status, 200);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(fetch(&d, &b).await.is_empty(), "nothing more for b");
    assert!(fetch(&d, &a).await.is_empty(), "no notice for a");
    assert_eq!(dead_lettered(&d, &a, "b").await, 0);
}
