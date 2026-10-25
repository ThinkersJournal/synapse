// SPDX-License-Identifier: MIT OR Apache-2.0
//! Role retirement over real loopback HTTP (docs/ROLE_LIVENESS_DESIGN.md, slice L2): `role-admin`
//! gates `/v1/roles/retire` and `/v1/roles/revive`, a retired role leaves `list` unless asked for,
//! and a claim by the role itself revives it.

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
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl Running {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
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
        stop: Some(tx),
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

async fn listed(d: &Running, token: &str, include_retired: bool) -> Vec<Value> {
    let path = if include_retired {
        "/v1/list?include_retired=true"
    } else {
        "/v1/list"
    };
    let (status, reply) = call(d, Some(token), path, None).await;
    assert_eq!(status, 200, "{reply}");
    reply["roles"].as_array().cloned().unwrap_or_default()
}

fn ids(entries: &[Value]) -> Vec<&str> {
    entries
        .iter()
        .map(|e| e["global_id"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn only_a_role_admin_retires_a_role_and_a_retired_role_leaves_list() {
    let d = start(&[("pm", Permission::RoleAdmin)]).await;
    let (a, pm) = (claim(&d, "alpha").await, claim(&d, "pm").await);
    let retire = json!({ "role": "alpha" });

    // Without the grant: refused, and nothing changed.
    let (status, reply) = call(&d, Some(&a), "/v1/roles/retire", Some(retire.clone())).await;
    assert_eq!(status, 403, "{reply}");
    assert_eq!(
        ids(&listed(&d, &pm, false).await),
        ["alpha@acct", "pm@acct"]
    );

    let (status, reply) = call(&d, Some(&pm), "/v1/roles/retire", Some(retire.clone())).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(
        ids(&listed(&d, &pm, false).await),
        ["pm@acct"],
        "hidden by default"
    );
    let all = listed(&d, &pm, true).await;
    assert_eq!(ids(&all), ["alpha@acct", "pm@acct"]);
    assert!(all[0]["retired_at"].is_string(), "{}", all[0]);
    assert!(all[1]["retired_at"].is_null());
    assert_eq!(all[0]["epoch"], 1, "the epoch is kept");

    let (status, _) = call(&d, Some(&pm), "/v1/roles/retire", Some(retire)).await;
    assert_eq!(status, 200, "retiring twice is not an error");
    d.stop().await;
}

#[tokio::test]
async fn revive_and_a_fresh_claim_both_bring_a_retired_role_back() {
    let d = start(&[("pm", Permission::RoleAdmin)]).await;
    let (_, pm) = (claim(&d, "alpha").await, claim(&d, "pm").await);
    call(
        &d,
        Some(&pm),
        "/v1/roles/retire",
        Some(json!({ "role": "alpha" })),
    )
    .await;
    assert_eq!(ids(&listed(&d, &pm, false).await), ["pm@acct"]);

    let (status, _) = call(
        &d,
        Some(&pm),
        "/v1/roles/revive",
        Some(json!({ "role": "alpha" })),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        ids(&listed(&d, &pm, false).await),
        ["alpha@acct", "pm@acct"]
    );

    call(
        &d,
        Some(&pm),
        "/v1/roles/retire",
        Some(json!({ "role": "alpha" })),
    )
    .await;
    claim(&d, "alpha").await;
    let back = listed(&d, &pm, false).await;
    assert_eq!(ids(&back), ["alpha@acct", "pm@acct"], "a claim revives");
    assert_eq!(back[0]["epoch"], 2);
    assert!(back[0]["retired_at"].is_null());
    d.stop().await;
}

#[tokio::test]
async fn an_unknown_or_malformed_role_is_refused() {
    let d = start(&[("pm", Permission::RoleAdmin)]).await;
    let pm = claim(&d, "pm").await;
    for path in ["/v1/roles/retire", "/v1/roles/revive"] {
        let (status, _) = call(&d, Some(&pm), path, Some(json!({ "role": "nobody" }))).await;
        assert_eq!(status, 404, "{path}: a role that never claimed");
        let (status, _) = call(&d, Some(&pm), path, Some(json!({ "role": "bad name!" }))).await;
        assert_eq!(status, 400, "{path}: not a role name");
        let (status, _) = call(&d, None, path, Some(json!({ "role": "pm" }))).await;
        assert_eq!(status, 401, "{path}: no session");
    }
    d.stop().await;
}
