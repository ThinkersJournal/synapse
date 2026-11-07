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
    start_with_window(home, None).await
}

/// `window`: how recent a call makes a role online (the daemon's is 90 s; tests shorten it).
async fn start_with_window(home: tempfile::TempDir, window: Option<chrono::Duration>) -> Running {
    let cfg = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    };
    let mut daemon = Daemon::open(&cfg)
        .expect("open daemon")
        .with_redelivery_gaps(vec![chrono::Duration::milliseconds(300); 3])
        .with_redelivery_check(Duration::from_millis(50));
    if let Some(window) = window {
        daemon = daemon.with_online_window(window);
    }
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

async fn join(d: &Running, token: &str, room: &str) -> (u16, Value) {
    call(d, token, "/v1/rooms/join", Some(json!({"room": room}))).await
}

async fn members(d: &Running, token: &str, room: &str) -> (u16, Value) {
    call(d, token, &format!("/v1/rooms/members?room={room}"), None).await
}

fn member_ids(reply: &Value) -> Vec<String> {
    let mut ids: Vec<String> = reply["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["member"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

async fn invite_only(d: &Running, pm: &str) {
    let (status, reply) = call(
        d,
        pm,
        "/v1/rooms/policy",
        Some(json!({"room": "lounge", "join_policy": "invite-only"})),
    )
    .await;
    assert_eq!(status, 200, "{reply}");
}

#[tokio::test]
async fn nobody_can_be_joined_by_another() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    claim(&d, "ops").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    // A request that names another role is refused: the joiner is the session, never a field.
    let (status, _) = call(
        &d,
        &dev,
        "/v1/rooms/join",
        Some(json!({"room": "lounge", "member": "ops@acct"})),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    let (status, reply) = members(&d, &pm, "lounge").await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(member_ids(&reply), ["dev@acct"], "only the caller joined");
    d.stop().await;
}

#[tokio::test]
async fn invite_only_refuses_uninvited() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    let ops = claim(&d, "ops").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    invite_only(&d, &pm).await;
    let (status, _) = call(
        &d,
        &pm,
        "/v1/rooms/invite",
        Some(json!({"room": "lounge", "invitee": "dev@acct"})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, reply) = join(&d, &dev, "lounge").await;
    assert_eq!(status, 200, "the invited role joins: {reply}");
    assert_ne!(
        join(&d, &ops, "lounge").await.0,
        200,
        "an uninvited role is refused"
    );
    let (_, reply) = members(&d, &pm, "lounge").await;
    assert_eq!(member_ids(&reply), ["dev@acct"]);
    d.stop().await;
}

#[tokio::test]
async fn banned_cannot_rejoin() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    let (status, reply) = call(
        &d,
        &pm,
        "/v1/rooms/ban",
        Some(json!({"room": "lounge", "member": "dev@acct"})),
    )
    .await;
    assert_eq!(status, 200, "{reply}");
    let (status, reply) = join(&d, &dev, "lounge").await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (403, Some("join_refused"))
    );
    let (_, reply) = members(&d, &pm, "lounge").await;
    assert!(member_ids(&reply).is_empty(), "the ban removed the member");
    // A removed (not banned) member may come back when the policy allows.
    let ops = claim(&d, "ops").await;
    assert_eq!(join(&d, &ops, "lounge").await.0, 200);
    let (status, _) = call(
        &d,
        &pm,
        "/v1/rooms/remove",
        Some(json!({"room": "lounge", "member": "ops@acct"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(join(&d, &ops, "lounge").await.0, 200, "removed, not banned");
    d.stop().await;
}

#[tokio::test]
async fn hidden_room_answers_404_same_as_unknown() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    invite_only(&d, &pm).await;
    // Members, leave and an uninvited join: the stranger hears what it hears for an absent room.
    let hidden = members(&d, &dev, "lounge").await;
    let absent = members(&d, &dev, "nowhere").await;
    assert_eq!(hidden.0, 404);
    assert_eq!(
        hidden, absent,
        "a hidden room is told apart from an absent one"
    );
    let hidden = join(&d, &dev, "lounge").await;
    let absent = join(&d, &dev, "nowhere").await;
    assert_eq!(hidden.0, 404);
    assert_eq!(hidden, absent);
    let hidden = call(&d, &dev, "/v1/rooms/leave", Some(json!({"room": "lounge"}))).await;
    let absent = call(
        &d,
        &dev,
        "/v1/rooms/leave",
        Some(json!({"room": "nowhere"})),
    )
    .await;
    assert_eq!(hidden, absent);
    d.stop().await;
}

#[tokio::test]
async fn a_muted_room_says_so_to_the_joiner_and_leaving_removes_the_member() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    let (status, _) = call(
        &d,
        &pm,
        "/v1/rooms/policy",
        Some(json!({"room": "lounge", "join_policy": "open", "default_send": "muted"})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, reply) = join(&d, &dev, "lounge").await;
    assert_eq!((status, &reply["muted"]), (200, &json!(true)), "{reply}");
    // A member reads the member list; leaving takes it out.
    assert_eq!(members(&d, &dev, "lounge").await.0, 200);
    let (status, _) = call(&d, &dev, "/v1/rooms/leave", Some(json!({"room": "lounge"}))).await;
    assert_eq!(status, 200);
    let (_, reply) = members(&d, &pm, "lounge").await;
    assert!(member_ids(&reply).is_empty());
    d.stop().await;
}

#[tokio::test]
async fn retired_member_not_in_delivery_set() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let boss = claim(&d, "boss").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    let (_, reply) = members(&d, &pm, "lounge").await;
    let row = &reply["members"][0];
    assert_eq!(
        (row["online"].as_bool(), row["deliverable"].as_bool()),
        (Some(true), Some(true)),
        "the control: a live member is deliverable: {row}"
    );
    let (status, reply) = call(&d, &boss, "/v1/roles/retire", Some(json!({"role": "dev"}))).await;
    assert_eq!(status, 200, "{reply}");
    let (_, reply) = members(&d, &pm, "lounge").await;
    let row = &reply["members"][0];
    assert_eq!(
        (row["retired"].as_bool(), row["deliverable"].as_bool()),
        (Some(true), Some(false)),
        "{row}"
    );
    d.stop().await;
}

async fn post(d: &Running, token: &str, room: &str, text: &str, id: Option<&str>) -> (u16, Value) {
    let mut body = json!({"to": format!("{room}@acct"), "body_b64": B64.encode(text.as_bytes())});
    if let Some(id) = id {
        body["message_id"] = json!(id);
    }
    call(d, token, "/v1/send", Some(body)).await
}

async fn inbox(d: &Running, token: &str) -> Vec<Value> {
    let (status, reply) = call(d, token, "/v1/fetch", Some(json!({"lease_secs": 5}))).await;
    assert_eq!(status, 200, "{reply}");
    reply["messages"].as_array().cloned().unwrap_or_default()
}

/// A home where `ann` holds the `post` grant on `room:lounge@acct` and nothing else.
fn home_with_a_poster() -> tempfile::TempDir {
    let home = homes();
    let grants = json!({"grants": [
        {"principal": "ann@acct", "actions": ["post"], "objects": ["room:lounge@acct"]}
    ]});
    std::fs::write(home.path().join("access.json"), grants.to_string()).unwrap();
    home
}

#[tokio::test]
async fn a_non_member_post_is_refused_with_the_typed_reason() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    let ops = claim(&d, "ops").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    invite_only(&d, &pm).await;
    let (status, _) = call(
        &d,
        &pm,
        "/v1/rooms/invite",
        Some(json!({"room": "lounge", "invitee": "dev@acct"})),
    )
    .await;
    assert_eq!(status, 200);
    // dev can see the room (invited) but is not in it and holds no post grant: a typed refusal.
    let (status, reply) = post(&d, &dev, "lounge", "hello", None).await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (403, Some("not_a_member")),
        "{reply}"
    );
    // ops cannot see the room: it hears what it hears for an absent recipient.
    let (status, reply) = post(&d, &ops, "lounge", "hello", None).await;
    let (absent_status, absent) = post(&d, &ops, "nowhere", "hello", None).await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (absent_status, absent["error"].as_str())
    );
    assert_eq!(status, 404);
    // Nothing was delivered to anyone.
    assert!(inbox(&d, &pm).await.is_empty());
    d.stop().await;
}

#[tokio::test]
async fn a_non_member_holding_the_post_grant_posts_and_receives_nothing() {
    let d = start(home_with_a_poster()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    let ann = claim(&d, "ann").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    let (status, reply) = post(&d, &ann, "lounge", "[STATUS] lane=ann doing=x", None).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["room"]["joined"], 1);
    assert_eq!(reply["room"]["delivered"], 1);
    let got = inbox(&d, &dev).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["from"], "ann@acct");
    assert!(
        inbox(&d, &ann).await.is_empty(),
        "the poster receives nothing back"
    );
    let (_, reply) = members(&d, &pm, "lounge").await;
    assert_eq!(
        member_ids(&reply),
        ["dev@acct"],
        "posting did not make ann a member"
    );
    d.stop().await;
}

#[tokio::test]
async fn the_post_grant_does_not_imply_join() {
    let d = start(home_with_a_poster()).await;
    let pm = claim(&d, "pm").await;
    let ann = claim(&d, "ann").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    invite_only(&d, &pm).await;
    assert_ne!(
        join(&d, &ann, "lounge").await.0,
        200,
        "a post grant is not a join"
    );
    let (_, reply) = members(&d, &pm, "lounge").await;
    assert!(member_ids(&reply).is_empty());
    d.stop().await;
}

#[tokio::test]
async fn join_then_send_honours_an_invite_only_room() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let ops = claim(&d, "ops").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    invite_only(&d, &pm).await;
    // The two steps a "join then send" convenience would take: each is refused on its own terms.
    assert_ne!(join(&d, &ops, "lounge").await.0, 200);
    assert_ne!(post(&d, &ops, "lounge", "hello", None).await.0, 200);
    let (_, reply) = members(&d, &pm, "lounge").await;
    assert!(member_ids(&reply).is_empty(), "the send did not join ops");
    d.stop().await;
}

#[tokio::test]
async fn muted_post_refused_with_typed_error_and_a_muted_member_still_receives() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    let (status, _) = call(
        &d,
        &pm,
        "/v1/rooms/policy",
        Some(json!({"room": "lounge", "join_policy": "open", "default_send": "muted"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    let (status, reply) = post(&d, &dev, "lounge", "hello", None).await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (403, Some("muted")),
        "{reply}"
    );
    // The creator posts; the muted member still receives.
    let (status, reply) = post(&d, &pm, "lounge", "hello dev", None).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(
        inbox(&d, &dev).await.len(),
        1,
        "muted governs sending, not reading"
    );
    d.stop().await;
}

#[tokio::test]
async fn copy_keeps_original_sender_and_room_and_a_forged_sender_is_refused() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    let (status, reply) = post(&d, &pm, "lounge", "hello", Some("p1")).await;
    assert_eq!(status, 200, "{reply}");
    let got = inbox(&d, &dev).await;
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0]["from"], "pm@acct",
        "the copy names the original sender"
    );
    assert_eq!(
        got[0]["message_id"], "pm@acct/p1#lounge@acct",
        "and carries the room"
    );
    assert_eq!(got[0]["body_b64"], B64.encode(b"hello"));
    // A request cannot name its sender: the field does not exist, so it is refused.
    let (status, _) = call(
        &d,
        &dev,
        "/v1/send",
        Some(json!({"to": "lounge@acct", "from": "pm@acct", "body_b64": B64.encode(b"x")})),
    )
    .await;
    assert_eq!(status, 400);
    d.stop().await;
}

#[tokio::test]
async fn offline_member_receives_nothing_and_nothing_queued() {
    let d = start_with_window(homes(), Some(chrono::Duration::milliseconds(400))).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    tokio::time::sleep(Duration::from_millis(700)).await; // dev makes no call: it goes offline
    let (status, reply) = post(&d, &pm, "lounge", "hello", None).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["room"]["delivered"], 0);
    assert_eq!(reply["room"]["refused"]["offline"], 1);
    assert_eq!(
        inbox(&d, &dev).await.len(),
        0,
        "nothing was queued for the offline member"
    );
    d.stop().await;
}

#[tokio::test]
async fn resend_dedupes_per_member() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    let (_, first) = post(&d, &pm, "lounge", "hello", Some("same")).await;
    let (_, again) = post(&d, &pm, "lounge", "hello", Some("same")).await;
    assert_eq!(first["room"]["delivered"], 1);
    assert_eq!(
        again["room"]["delivered"], 0,
        "a retry writes no second copy"
    );
    assert_eq!(inbox(&d, &dev).await.len(), 1);
    d.stop().await;
}

/// Membership is the consent (the join/post ruling, PM option A): a post reaches a member
/// although the poster holds no `synapse:send` on it. The control: a direct send is refused.
#[tokio::test]
async fn membership_is_the_consent_no_per_pair_send_check() {
    let d = start(homes()).await;
    let pm = claim(&d, "pm").await;
    let dev = claim(&d, "dev").await;
    assert_eq!(create(&d, &pm, "lounge").await.0, 200);
    assert_eq!(join(&d, &dev, "lounge").await.0, 200);
    let (status, _) = call(
        &d,
        &pm,
        "/v1/send",
        Some(json!({"to": "dev@acct", "body_b64": B64.encode(b"direct")})),
    )
    .await;
    assert_ne!(status, 200, "the control: pm may not message dev directly");
    let (status, reply) = post(&d, &pm, "lounge", "to the room", None).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(
        inbox(&d, &dev).await.len(),
        1,
        "the room post reached the member"
    );
    d.stop().await;
}
