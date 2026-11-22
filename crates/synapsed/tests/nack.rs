// SPDX-License-Identifier: MIT OR Apache-2.0
//! Nack (messaging brief step 2, CireSnave 2026-11-19: "every place we can ack we should also be able to
//! nack"): a recipient declines a message it holds; it leaves the recipient's queue for good and the
//! sender gets one `[DECLINED]` notice with the reason, so the sender can fail over.

mod common;

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
    common::allow_all(&cfg.home);
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

fn text(message: &Value) -> String {
    String::from_utf8(B64.decode(message["body_b64"].as_str().unwrap()).unwrap()).unwrap()
}

#[tokio::test]
async fn a_nack_removes_the_message_and_tells_the_sender_why_once() {
    let d = start(&[]).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    send(&d, &a, "m1", "[STATUS] lane=a doing=x").await;
    let got = fetch(&d, &b).await;
    assert_eq!(got.len(), 1);
    let id = got[0]["message_id"].as_str().unwrap().to_string();

    let (status, reply) = call(
        &d,
        Some(&b),
        "/v1/nack",
        Some(json!({"message_id": id, "reason": "cannot handle this"})),
    )
    .await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["outcome"], "declined");

    // Gone from b for good: not redelivered after the gap.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        fetch(&d, &b).await.is_empty(),
        "a declined message is not redelivered"
    );

    // The sender hears exactly once, from the daemon, with the reason.
    let mut notice = Vec::new();
    for _ in 0..40 {
        notice = fetch(&d, &a).await;
        if !notice.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(notice.len(), 1, "one notice");
    assert_eq!(notice[0]["from"], "synapsed@acct");
    assert_eq!(
        text(&notice[0]),
        "[DECLINED] to=b id=a@acct/m1 reason=cannot_handle_this"
    );

    // Idempotent: a repeat nack answers already_handled and sends nothing more.
    let (status, reply) = call(&d, Some(&b), "/v1/nack", Some(json!({"message_id": id}))).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["outcome"], "already_handled");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(fetch(&d, &a).await.is_empty(), "no second notice");
}

#[tokio::test]
async fn a_nack_needs_the_lease_and_an_unknown_id_is_not_found() {
    let d = start(&[]).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    send(&d, &a, "m2", "[STATUS] lane=a doing=y").await;
    // Never fetched: b holds no lease yet.
    let (status, reply) = call(
        &d,
        Some(&b),
        "/v1/nack",
        Some(json!({"message_id": "a@acct/m2"})),
    )
    .await;
    assert_eq!(status, 403, "{reply}");
    let (status, _) = call(
        &d,
        Some(&b),
        "/v1/nack",
        Some(json!({"message_id": "a@acct/none"})),
    )
    .await;
    assert_eq!(status, 404);
    // The message is still there to be fetched and acked.
    assert_eq!(fetch(&d, &b).await.len(), 1);
}

/// Nack of a fire-and-forget message still tells the sender: failover needs the signal, and a decline is not
/// delivery tracking (review of #375).
#[tokio::test]
async fn a_nack_of_a_fire_and_forget_message_still_tells_the_sender() {
    let d = start(&[]).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    let (status, reply) = call(
        &d,
        Some(&a),
        "/v1/send",
        Some(
            json!({"to": "b@acct", "message_id": "f1", "body_b64": B64.encode(b"x"),
                    "delivery": {"mode": "fire_and_forget"}}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{reply}");
    let got = fetch(&d, &b).await;
    let id = got[0]["message_id"].as_str().unwrap().to_string();
    let (status, reply) = call(&d, Some(&b), "/v1/nack", Some(json!({"message_id": id}))).await;
    assert_eq!(
        (status, reply["outcome"].as_str()),
        (200, Some("declined")),
        "{reply}"
    );
    let mut notice = Vec::new();
    for _ in 0..40 {
        notice = fetch(&d, &a).await;
        if !notice.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(notice.len(), 1);
    assert_eq!(text(&notice[0]), "[DECLINED] to=b id=a@acct/f1 reason=-");
}
