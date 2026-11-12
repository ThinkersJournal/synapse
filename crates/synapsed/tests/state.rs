// SPDX-License-Identifier: MIT OR Apache-2.0
//! `/v1/state/*` over real loopback HTTP (shared state, slice S2b). The store's own rules are
//! tested in `tests/state_store.rs` of the root crate; this checks the binding: sessions, the
//! caller built from the certificate, error mapping, and the security event on a refusal.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use synapse::certificate::{Permission, chain_to_pem};
use synapse::keystore::Keystore;
use synapse::roles::sign_claim_for;
use synapsed::{Daemon, DaemonConfig, SECURITY_EVENTS_FILE};

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

fn new_record(title: &str) -> Value {
    json!({ "title": title, "parties": ["alpha", "beta"], "owner": "alpha" })
}

#[tokio::test]
async fn a_thread_is_created_read_listed_patched_and_has_a_history() {
    let d = start(&[]).await;
    let (a, b) = (claim(&d, "alpha").await, claim(&d, "beta").await);

    let (status, created) = call(
        &d,
        Some(&a),
        "/v1/state/create",
        Some(new_record("wire it")),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["record"]["id"], "T-1");
    assert_eq!(created["record"]["revision"], 1);

    let (status, got) = call(&d, Some(&b), "/v1/state/get?id=T-1", None).await;
    assert_eq!(
        (status, got["record"]["title"].as_str()),
        (200, Some("wire it"))
    );
    let (_, listed) = call(&d, Some(&b), "/v1/state/list?state=open&party=beta", None).await;
    assert_eq!(listed["records"].as_array().unwrap().len(), 1);

    let patch = json!({ "id": "T-1", "expected_revision": 1, "patch": { "state": "waiting" } });
    let (status, patched) = call(&d, Some(&b), "/v1/state/patch", Some(patch)).await;
    assert_eq!(
        (status, patched["record"]["revision"].as_u64()),
        (200, Some(2)),
        "{patched}"
    );

    let (_, history) = call(&d, Some(&a), "/v1/state/history?id=T-1", None).await;
    let writers: Vec<_> = history["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["writer"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        writers,
        ["alpha", "beta"],
        "the writer is the session's role"
    );
    d.stop().await;
}

#[tokio::test]
async fn every_state_route_needs_a_session() {
    let d = start(&[]).await;
    for path in [
        "/v1/state/get?id=T-1",
        "/v1/state/list",
        "/v1/state/history?id=T-1",
    ] {
        assert_eq!(call(&d, None, path, None).await.0, 401, "{path}");
    }
    for path in ["/v1/state/create", "/v1/state/patch"] {
        assert_eq!(call(&d, None, path, Some(json!({}))).await.0, 401, "{path}");
    }
    d.stop().await;
}

#[tokio::test]
async fn a_lost_race_is_a_409_carrying_the_current_record() {
    let d = start(&[]).await;
    let (a, b) = (claim(&d, "alpha").await, claim(&d, "beta").await);
    call(&d, Some(&a), "/v1/state/create", Some(new_record("race"))).await;
    let first = json!({ "id": "T-1", "expected_revision": 1, "patch": { "notes": "a" } });
    assert_eq!(
        call(&d, Some(&a), "/v1/state/patch", Some(first)).await.0,
        200
    );
    let second = json!({ "id": "T-1", "expected_revision": 1, "patch": { "notes": "b" } });
    let (status, lost) = call(&d, Some(&b), "/v1/state/patch", Some(second)).await;
    assert_eq!(status, 409);
    assert_eq!(lost["error"], "stale_revision");
    assert_eq!(lost["current"], 2);
    assert_eq!(
        lost["record"]["notes"], "a",
        "the loser gets the winner's record"
    );
    d.stop().await;
}

#[tokio::test]
async fn a_non_party_sees_nothing_and_a_refusal_is_a_security_event() {
    let d = start(&[]).await;
    let (a, g) = (claim(&d, "alpha").await, claim(&d, "gamma").await);
    call(
        &d,
        Some(&a),
        "/v1/state/create",
        Some(new_record("private")),
    )
    .await;

    assert_eq!(
        call(&d, Some(&g), "/v1/state/get?id=T-1", None).await.0,
        404,
        "hidden, not forbidden"
    );
    assert_eq!(
        call(&d, Some(&g), "/v1/state/list", None).await.1["records"],
        json!([])
    );
    assert_eq!(
        call(&d, Some(&g), "/v1/state/history?id=T-1", None).await.0,
        403
    );
    let patch = json!({ "id": "T-1", "expected_revision": 1, "patch": { "state": "done" } });
    assert_eq!(
        call(&d, Some(&g), "/v1/state/patch", Some(patch)).await.0,
        403
    );
    let mine = json!({ "title": "x", "parties": ["alpha"], "owner": "alpha" });
    assert_eq!(
        call(&d, Some(&g), "/v1/state/create", Some(mine)).await.0,
        403,
        "creator must be a party"
    );

    let events = std::fs::read_to_string(d.home.path().join(SECURITY_EVENTS_FILE)).unwrap();
    assert!(events.contains("state_denied"), "{events}");
    assert!(events.contains("gamma@acct"), "{events}");
    d.stop().await;
}

#[tokio::test]
async fn malformed_writes_are_400_and_unknown_fields_are_refused() {
    let d = start(&[]).await;
    let a = claim(&d, "alpha").await;
    let bad = json!({ "title": "", "parties": ["alpha"], "owner": "alpha" });
    let (status, reply) = call(&d, Some(&a), "/v1/state/create", Some(bad)).await;
    assert_eq!((status, reply["error"].as_str()), (400, Some("malformed")));
    let extra = json!({ "title": "t", "parties": ["alpha"], "owner": "alpha", "revision": 9 });
    assert_eq!(
        call(&d, Some(&a), "/v1/state/create", Some(extra)).await.0,
        400
    );
    let ghost = json!({ "title": "t", "parties": ["alpha"], "owner": "alpha", "verify": [{ "fact": "rm_rf:/", "op": "exists" }] });
    assert_eq!(
        call(&d, Some(&a), "/v1/state/create", Some(ghost)).await.0,
        400,
        "facts come from the registry"
    );
    assert_eq!(
        call(&d, Some(&a), "/v1/state/get", None).await.0,
        400,
        "an id is required"
    );
    assert_eq!(
        call(&d, Some(&a), "/v1/state/get?id=T-99", None).await.0,
        404
    );
    d.stop().await;
}

#[tokio::test]
async fn the_grants_in_the_certificate_decide_what_a_role_reads_and_writes() {
    let d = start(&[
        ("pm", Permission::StateReadAll),
        ("root", Permission::StateAdmin),
    ])
    .await;
    let (a, pm, root) = (
        claim(&d, "alpha").await,
        claim(&d, "pm").await,
        claim(&d, "root").await,
    );
    call(&d, Some(&a), "/v1/state/create", Some(new_record("board"))).await;

    // read_all reads everything and writes nothing.
    assert_eq!(
        call(&d, Some(&pm), "/v1/state/get?id=T-1", None).await.0,
        200
    );
    assert_eq!(
        call(&d, Some(&pm), "/v1/state/history?id=T-1", None)
            .await
            .0,
        200
    );
    let patch = json!({ "id": "T-1", "expected_revision": 1, "patch": { "state": "done" } });
    assert_eq!(
        call(&d, Some(&pm), "/v1/state/patch", Some(patch)).await.0,
        403
    );
    // admin patches a record it is not a party to.
    let patch = json!({ "id": "T-1", "expected_revision": 1, "patch": { "state": "done" } });
    assert_eq!(
        call(&d, Some(&root), "/v1/state/patch", Some(patch))
            .await
            .0,
        200
    );
    d.stop().await;
}

async fn fetch_all(d: &Running, token: &str) -> Vec<Value> {
    // The notice is handed to the mailbox by a task the write wakes: give it a moment.
    for _ in 0..100 {
        let (_, reply) = call(d, Some(token), "/v1/fetch", Some(json!({ "max": 10 }))).await;
        let messages = reply["messages"].as_array().cloned().unwrap_or_default();
        if !messages.is_empty() {
            return messages;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Vec::new()
}

fn body_of(message: &Value) -> Value {
    let bytes = B64.decode(message["body_b64"].as_str().unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn a_change_reaches_the_other_parties_as_id_only_mail_from_the_daemon() {
    let d = start(&[]).await;
    let (a, b) = (claim(&d, "alpha").await, claim(&d, "beta").await);
    call(
        &d,
        Some(&a),
        "/v1/state/create",
        Some(new_record("a confidential title")),
    )
    .await;

    let for_beta = fetch_all(&d, &b).await;
    assert_eq!(for_beta.len(), 1);
    assert_eq!(for_beta[0]["from"], "daemon:state@acct");
    assert_eq!(for_beta[0]["message_id"], "state:T-1:1:beta");
    let body = body_of(&for_beta[0]);
    assert_eq!(
        (
            body["id"].as_str(),
            body["revision"].as_u64(),
            body["changed_by"].as_str()
        ),
        (Some("T-1"), Some(1), Some("alpha"))
    );
    assert_eq!(body["fields"], json!(["created"]));
    assert!(
        !body.to_string().contains("confidential"),
        "ids only, no title"
    );

    let patch = json!({ "id": "T-1", "expected_revision": 1, "patch": { "state": "waiting" } });
    assert_eq!(
        call(&d, Some(&b), "/v1/state/patch", Some(patch)).await.0,
        200
    );
    let for_alpha = fetch_all(&d, &a).await;
    assert_eq!(
        for_alpha.len(),
        1,
        "alpha hears about beta's write, not its own create"
    );
    assert_eq!(body_of(&for_alpha[0])["fields"], json!(["state"]));
    d.stop().await;
}

#[tokio::test]
async fn the_checker_reports_facts_and_readers_see_them_derived() {
    let d = start(&[("checker", Permission::StateDerive)]).await;
    let (a, b, c) = (
        claim(&d, "alpha").await,
        claim(&d, "beta").await,
        claim(&d, "checker").await,
    );
    let mut record = new_record("waiting on a release");
    record["verify"] = json!([{ "fact": "crate_version:synapse", "op": "ge", "value": "6.0.0" }]);
    assert_eq!(
        call(&d, Some(&a), "/v1/state/create", Some(record)).await.0,
        200
    );

    // Before the checker has looked: unknown, stale, never verified.
    let (_, got) = call(&d, Some(&a), "/v1/state/get?id=T-1", None).await;
    let derived = &got["record"]["derived"];
    assert_eq!(derived["stale"], true);
    assert_eq!(derived["last_verified"], Value::Null);
    assert_eq!(derived["verify"][0]["satisfied"], Value::Null);
    // The create notice is in beta's mailbox; drain it so the next one is the derived one.
    assert_eq!(fetch_all(&d, &b).await.len(), 1);

    // Only the checker learns what is wanted, and only the checker may report.
    assert_eq!(call(&d, Some(&a), "/v1/state/wanted", None).await.0, 403);
    let (status, wanted) = call(&d, Some(&c), "/v1/state/wanted", None).await;
    assert_eq!(
        (status, &wanted["facts"]),
        (200, &json!(["crate_version:synapse"]))
    );
    let report =
        json!({ "reports": [{ "fact": "crate_version:synapse", "look": { "found": "6.0.1" } }] });
    assert_eq!(
        call(&d, Some(&a), "/v1/state/facts", Some(report.clone()))
            .await
            .0,
        403,
        "a lane cannot type a fact"
    );
    assert_eq!(
        call(&d, Some(&c), "/v1/state/facts", Some(report)).await.0,
        200
    );
    let rogue = json!({ "reports": [{ "fact": "rm_rf:/", "look": "absent" }] });
    assert_eq!(
        call(&d, Some(&c), "/v1/state/facts", Some(rogue)).await.0,
        400,
        "facts come from the registry"
    );

    let (_, got) = call(&d, Some(&b), "/v1/state/get?id=T-1", None).await;
    let derived = &got["record"]["derived"];
    assert_eq!(derived["verify"][0]["satisfied"], true);
    assert_eq!(derived["verify"][0]["observed"], "6.0.1");
    assert_eq!(derived["last_verified_by"], "checker");
    assert_eq!(derived["stale"], false);
    assert_eq!(
        got["record"]["revision"], 1,
        "a fact is not a write to the record"
    );

    // Beta hears that it changed: ids and field names, flagged derived.
    let mail = fetch_all(&d, &b).await;
    assert_eq!(mail.len(), 1);
    let body = body_of(&mail[0]);
    assert_eq!(
        (body["id"].as_str(), body["derived"].as_bool()),
        (Some("T-1"), Some(true))
    );
    assert_eq!(body["fields"], json!(["facts", "stale"]));
    assert!(!body.to_string().contains("6.0.1"));

    // The listing carries the same derived view.
    let (_, listed) = call(&d, Some(&a), "/v1/state/list", None).await;
    assert_eq!(
        listed["records"][0]["derived"]["verify"][0]["satisfied"],
        true
    );
    d.stop().await;
}
