// SPDX-License-Identifier: MIT OR Apache-2.0
//! `POST /v1/daemon/shutdown` over real loopback HTTP (board 342): `daemon-admin` gates it, and the
//! daemon then ends `serve` cleanly (so `synapsed` exits 0 and a restart-on-failure task leaves it
//! stopped) without the caller's own shutdown future firing.

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
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
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
        task: Some(task),
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

#[tokio::test]
async fn only_daemon_admin_may_stop_the_daemon() {
    let mut d = start(&[("pm", Permission::DaemonAdmin)]).await;
    let a = claim(&d, "a").await;
    let pm = claim(&d, "pm").await;

    let (status, _) = call(&d, None, "/v1/daemon/shutdown", Some(json!({}))).await;
    assert_eq!(status, 401);
    let (status, _) = call(&d, Some(&a), "/v1/daemon/shutdown", Some(json!({}))).await;
    assert_eq!(status, 403);
    let (status, _) = call(&d, Some(&pm), "/v1/daemon/shutdown", Some(json!({"x": 1}))).await;
    assert_eq!(
        status, 400,
        "an unknown field is refused and does not stop it"
    );
    // Still serving after the refusals.
    let (status, _) = call(&d, Some(&a), "/v1/list", None).await;
    assert_eq!(status, 200);

    let (status, reply) = call(&d, Some(&pm), "/v1/daemon/shutdown", Some(json!({}))).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["stopping"], true);

    // `serve` returns Ok on its own: the test's own shutdown sender is never fired.
    let task = d.task.take().unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("serve ended after the request")
        .unwrap();
    assert!(ended.is_ok(), "a requested stop is a clean end: {ended:?}");
    assert!(
        !d.home.path().join("synapsed.json").exists(),
        "the announce file is removed at a clean stop"
    );
}
