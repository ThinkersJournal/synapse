// SPDX-License-Identifier: MIT OR Apache-2.0
//! Delivery evidence per role (ROADMAP row 41, PM 2026-10-31): `list` and `stats` carry `last_fetch_at`
//! (a fetch that handed the role a message) and `last_ack_at` (an ack that removed one).

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
    let daemon = Daemon::open(&cfg).expect("open daemon");
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

async fn role(d: &Running, token: &str, path: &str, who: &str) -> Value {
    let (status, reply) = call(d, Some(token), path, None).await;
    assert_eq!(status, 200, "{reply}");
    reply["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == format!("{who}@acct"))
        .unwrap_or_else(|| panic!("{who} missing from {path}: {reply}"))
        .clone()
}

#[tokio::test]
async fn list_and_stats_show_when_a_role_last_fetched_and_acked() {
    let d = start(&[]).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    for path in ["/v1/list", "/v1/stats"] {
        let r = role(&d, &a, path, "b").await;
        assert!(
            r["last_fetch_at"].is_null() && r["last_ack_at"].is_null(),
            "{path}: {r}"
        );
    }

    // An empty poll is not a delivery.
    let (status, reply) = call(&d, Some(&b), "/v1/fetch", Some(json!({}))).await;
    assert_eq!(status, 200, "{reply}");
    assert!(role(&d, &a, "/v1/list", "b").await["last_fetch_at"].is_null());

    let (status, sent) = call(
        &d,
        Some(&a),
        "/v1/send",
        Some(json!({"to": "b@acct", "message_id": "m1", "body_b64": B64.encode(b"hi")})),
    )
    .await;
    assert_eq!(status, 200, "{sent}");
    let (_, got) = call(&d, Some(&b), "/v1/fetch", Some(json!({}))).await;
    assert_eq!(got["messages"].as_array().unwrap().len(), 1, "{got}");
    for path in ["/v1/list", "/v1/stats"] {
        let r = role(&d, &a, path, "b").await;
        assert!(r["last_fetch_at"].is_string(), "{path}: {r}");
        assert!(
            r["last_ack_at"].is_null(),
            "fetched, not yet acked: {path}: {r}"
        );
    }
    // The sender never fetched or acked.
    assert!(role(&d, &a, "/v1/list", "a").await["last_fetch_at"].is_null());

    let id = got["messages"][0]["message_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, ack) = call(&d, Some(&b), "/v1/ack", Some(json!({"message_id": id}))).await;
    assert_eq!(status, 200, "{ack}");
    for path in ["/v1/list", "/v1/stats"] {
        let r = role(&d, &a, path, "b").await;
        assert!(r["last_ack_at"].is_string(), "{path}: {r}");
    }
}
