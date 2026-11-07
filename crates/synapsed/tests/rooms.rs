// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rooms, slice R1 (docs/ROOMS_DESIGN.md): create, policy, invite and delete over real loopback
//! HTTP, the creator-only visibility of board 388, and the shared role and room namespace.

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

    /// Stop the daemon and hand back its home, for a restart on the same state.
    async fn stop(mut self) -> tempfile::TempDir {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.home
    }
}

fn new_home(grants: &[(&str, Permission)]) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let store = Keystore::open(home.path()).unwrap();
    for (role, permission) in grants {
        store.grant(role, permission).unwrap();
    }
    home
}

async fn start(home: tempfile::TempDir) -> Running {
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
        stop: Some(tx),
        task: Some(task),
    }
}

fn instance_id(d: &Running) -> String {
    let text = std::fs::read_to_string(d.home.path().join("synapsed.json")).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    v["instance_id"].as_str().unwrap().to_string()
}

async fn post_claim(d: &Running, req: &synapse::roles::ClaimRequest) -> String {
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
    let status = reply.status().as_u16();
    let reply: Value = reply.json().await.unwrap();
    assert_eq!(status, 200, "{reply}");
    reply["session"].as_str().unwrap().to_string()
}

/// Claim `role` the usual way: its certificate is one link, signed by the account key.
async fn claim(d: &Running, role: &str) -> String {
    let store = Keystore::open(d.home.path()).unwrap();
    let identity = store.role(role, Utc::now()).unwrap();
    let signed_at = Utc::now().max(d.started_at + chrono::Duration::seconds(1));
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let req = sign_claim_for(&identity, &instance_id(d), nonce, signed_at).unwrap();
    post_claim(d, &req).await
}

async fn call(d: &Running, token: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let client = reqwest::Client::new();
    let req = match &body {
        Some(b) => client.post(d.url(path)).json(b),
        None => client.get(d.url(path)),
    };
    let resp = req.bearer_auth(token).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn create(d: &Running, token: &str, room: &str) -> (u16, Value) {
    call(d, token, "/v1/rooms/create", Some(json!({"room": room}))).await
}

async fn rooms_seen(d: &Running, token: &str) -> Vec<String> {
    let (status, reply) = call(d, token, "/v1/rooms", None).await;
    assert_eq!(status, 200, "{reply}");
    let mut ids: Vec<String> = reply["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["room"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

fn homes() -> tempfile::TempDir {
    new_home(&[
        ("pm", Permission::RoomCreate),
        ("boss", Permission::RoleAdmin),
    ])
}

#[tokio::test]
async fn unauthorized_create_refused() {
    let d = start(homes()).await;
    let dev = claim(&d, "dev").await;
    let (status, reply) = create(&d, &dev, "lounge").await;
    assert_eq!(status, 403, "{reply}");
    assert!(rooms_seen(&d, &claim(&d, "boss").await).await.is_empty());
    // The control: a role holding room-create creates one.
    let pm = claim(&d, "pm").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    d.stop().await;
}

#[tokio::test]
async fn a_new_room_is_invisible_to_a_third_agent_and_visible_to_its_creator_and_the_account_holder()
 {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let boss = claim(&d, "boss").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    assert_eq!(rooms_seen(&d, &pm).await, ["lounge@acct"]);
    assert_eq!(rooms_seen(&d, &boss).await, ["lounge@acct"]);
    assert!(
        rooms_seen(&d, &dev).await.is_empty(),
        "a third agent sees the room"
    );
    d.stop().await;
}

#[tokio::test]
async fn room_name_taken_by_a_role_refused_and_a_role_cannot_take_a_rooms_name() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    claim(&d, "dev").await;
    let (status, reply) = create(&d, &pm, "dev").await;
    assert_eq!(status, 409, "{reply}");
    assert_eq!(reply["error"], "name_taken");
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    // A role that first claims under the room's name is refused: one namespace.
    let store = Keystore::open(d.home.path()).unwrap();
    let identity = store.role("lounge", Utc::now()).unwrap();
    let signed_at = Utc::now().max(d.started_at + chrono::Duration::seconds(1));
    let req = sign_claim_for(
        &identity,
        &instance_id(&d),
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
    let reply = reqwest::Client::new()
        .post(d.url("/v1/claim"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status().as_u16(), 403);
    d.stop().await;
}

#[tokio::test]
async fn a_stranger_cannot_manage_a_room_and_a_hidden_room_answers_as_unknown() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    let policy = |room: &str| json!({"room": room, "join_policy": "invite-only"});
    // An open room is joinable by anyone, so it is not hidden: the refusal names the reason.
    let (status, reply) = call(&d, &dev, "/v1/rooms/policy", Some(policy("lounge"))).await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (403, Some("not_moderator"))
    );
    // The creator closes it; now the stranger hears what it hears for a room that is not there.
    assert_eq!(
        call(&d, &pm, "/v1/rooms/policy", Some(policy("lounge")))
            .await
            .0,
        200
    );
    let hidden = call(&d, &dev, "/v1/rooms/policy", Some(policy("lounge"))).await;
    let absent = call(&d, &dev, "/v1/rooms/policy", Some(policy("nowhere"))).await;
    assert_eq!(hidden.0, 404);
    assert_eq!(
        hidden, absent,
        "a hidden room is told apart from an absent one"
    );
    d.stop().await;
}

#[tokio::test]
async fn the_creator_invites_deletes_and_the_name_is_free_again() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    let (status, reply) = call(
        &d,
        &pm,
        "/v1/rooms/invite",
        Some(json!({"room": "lounge", "invitee": "dev@acct"})),
    )
    .await;
    assert_eq!(status, 200, "{reply}");
    let (status, _) = call(
        &d,
        &pm,
        "/v1/rooms/invite",
        Some(json!({"room": "lounge", "invitee": "not a global id"})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, reply) = call(&d, &pm, "/v1/rooms/delete", Some(json!({"room": "lounge"}))).await;
    assert_eq!(status, 200, "{reply}");
    assert!(rooms_seen(&d, &pm).await.is_empty());
    assert_eq!(create(&d, &pm, "lounge").await.0, 200, "the name is free");
    d.stop().await;
}

#[tokio::test]
async fn a_restart_keeps_the_rooms_and_who_created_them() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    let home = d.stop().await;
    let d = start(home).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(rooms_seen(&d, &pm).await, ["lounge@acct"]);
    assert!(rooms_seen(&d, &dev).await.is_empty());
    d.stop().await;
}
