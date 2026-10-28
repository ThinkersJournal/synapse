// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lane launch on message over real loopback HTTP: `GET /v1/waiting`, `POST /v1/launch-result`,
//! `POST /v1/launch-clear` and the `launch` field of `/v1/list`. Design:
//! `docs/superpowers/specs/2026-10-15-cutover-and-lane-launch.md` section C. The state machine's
//! timing is unit-tested in `src/launch.rs`; these tests pin the wire and the authority.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use synapse::certificate::chain_to_pem;
use synapse::keystore::Keystore;
use synapse::roles::sign_claim_for;
use synapsed::{Daemon, DaemonConfig, LaunchSenders, LauncherConfig};

struct Running {
    addr: SocketAddr,
    home: tempfile::TempDir,
    started_at: DateTime<Utc>,
    senders: LaunchSenders,
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

/// A daemon whose online window is short, so a role that stays silent is offline within the test,
/// with `launcher_roles` as given, no grace, and `beta` the one allowed sender.
async fn start(launcher_roles: &[&str]) -> Running {
    start_with(launcher_roles, &["beta"]).await
}

async fn start_with(launcher_roles: &[&str], senders: &[&str]) -> Running {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let config = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    };
    let launcher = LauncherConfig {
        roles: launcher_roles.iter().map(|r| (*r).to_string()).collect(),
        grace: chrono::Duration::zero(),
        wait: chrono::Duration::seconds(60),
        backoff: vec![chrono::Duration::seconds(30)],
    };
    let daemon = Daemon::open(&config)
        .expect("open daemon")
        .with_launcher(launcher)
        .with_launch_senders(senders.iter().map(|r| (*r).to_string()).collect())
        .with_online_window(chrono::Duration::milliseconds(300));
    let started_at = daemon.started_at();
    let handle = daemon.launch_senders();
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
        senders: handle,
        stop: Some(tx),
        task: Some(task),
    }
}

async fn post(d: &Running, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
    let mut req = reqwest::Client::new().post(d.url(path)).json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn get(d: &Running, path: &str, token: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .get(d.url(path))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Claim `role` with a fresh random nonce and return its session token.
async fn claim(d: &Running, role: &str) -> String {
    let announce: Value = serde_json::from_str(
        &std::fs::read_to_string(d.home.path().join("synapsed.json")).expect("announce file"),
    )
    .unwrap();
    let instance = announce["instance_id"].as_str().unwrap();
    let identity = Keystore::open(d.home.path())
        .unwrap()
        .role(role, Utc::now())
        .unwrap();
    let signed_at = Utc::now().max(d.started_at + chrono::Duration::seconds(1));
    let req = sign_claim_for(
        &identity,
        instance,
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
    let (status, reply) = post(d, "/v1/claim", None, body).await;
    assert_eq!(status, 200, "claim refused: {reply}");
    reply["session"].as_str().unwrap().to_string()
}

/// `launcher` and `alpha` claimed, and one message queued for `alpha`, who then stays silent.
async fn mail_waits_for_a_silent_alpha(d: &Running) -> (String, String) {
    let launcher = claim(d, "overmind").await;
    let _alpha = claim(d, "alpha").await;
    let sender = claim(d, "beta").await;
    let (s, sent) = post(
        d,
        "/v1/send",
        Some(&sender),
        json!({"to": "alpha@acct", "body_b64": B64.encode(b"SECRET-BODY")}),
    )
    .await;
    assert_eq!(s, 200, "{sent}");
    // Past the 300 ms online window: no one has spoken for alpha since its claim.
    tokio::time::sleep(Duration::from_millis(500)).await;
    (launcher, sender)
}

#[tokio::test]
async fn with_no_launcher_roles_every_launch_route_is_403() {
    let d = start(&[]).await;
    let token = claim(&d, "overmind").await;
    assert_eq!(get(&d, "/v1/waiting", &token).await.0, 403);
    let (s, _) = post(
        &d,
        "/v1/launch-result",
        Some(&token),
        json!({"signal_id": "x", "epoch": "e", "attempt": 1, "role": "alpha", "outcome": "started"}),
    )
    .await;
    assert_eq!(s, 403);
    let (s, _) = post(
        &d,
        "/v1/launch-clear",
        Some(&token),
        json!({"role": "alpha"}),
    )
    .await;
    assert_eq!(s, 403);
    d.stop().await;
}

#[tokio::test]
async fn only_a_configured_launcher_role_may_read_the_signal() {
    let d = start(&["overmind"]).await;
    let (_launcher, sender) = mail_waits_for_a_silent_alpha(&d).await;
    assert_eq!(get(&d, "/v1/waiting", &sender).await.0, 403);
    // Not authenticated at all: 401, as for every route.
    let resp = reqwest::Client::new()
        .get(d.url("/v1/waiting"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    d.stop().await;
}

#[tokio::test]
async fn a_silent_role_with_mail_is_signalled_without_content_then_answered() {
    let d = start(&["overmind"]).await;
    let (launcher, sender) = mail_waits_for_a_silent_alpha(&d).await;

    let (s, w) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(s, 200, "{w}");
    let roles = w["roles"].as_array().unwrap();
    assert_eq!(roles.len(), 1, "{w}");
    let sig = &roles[0];
    assert_eq!(sig["role"], "alpha");
    assert_eq!(sig["attempt"], 1);
    assert_eq!(sig["count"], 1);
    let text = w.to_string();
    for leak in ["SECRET-BODY", "beta", &launcher, &sender] {
        assert!(
            !text.contains(leak),
            "{leak} leaked into the signal: {text}"
        );
    }
    // Level-triggered: reading again shows the same signal, and does not consume anything.
    let (_, again) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(again["roles"][0]["signal_id"], sig["signal_id"]);

    let answer = |outcome: &str, attempt: u64| {
        json!({
            "signal_id": sig["signal_id"], "epoch": sig["epoch"],
            "attempt": attempt, "role": "alpha", "outcome": outcome, "reason": "spawned",
        })
    };
    // A wrong attempt is not an open signal.
    let (s, e) = post(
        &d,
        "/v1/launch-result",
        Some(&launcher),
        answer("started", 2),
    )
    .await;
    assert_eq!((s, &e["error"]), (409, &json!("stale_signal")), "{e}");
    let (s, e) = post(
        &d,
        "/v1/launch-result",
        Some(&launcher),
        answer("started", 1),
    )
    .await;
    assert_eq!(s, 200, "{e}");
    // Answered: launching, so nothing more is signalled, and a repeat answer is stale.
    let (_, w) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(w["roles"].as_array().unwrap().len(), 0, "{w}");
    let (s, _) = post(
        &d,
        "/v1/launch-result",
        Some(&launcher),
        answer("started", 1),
    )
    .await;
    assert_eq!(s, 409);
    // The sender can see why the mail is not being read.
    let (_, list) = get(&d, "/v1/list", &sender).await;
    let alpha = list["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == "alpha@acct")
        .unwrap()
        .clone();
    assert_eq!(alpha["launch"]["state"], "launching", "{alpha}");
    assert_eq!(alpha["launch"]["reason"], "spawned");
    assert_eq!(alpha["pending"]["queued"], 1, "the mail is untouched");
    d.stop().await;
}

#[tokio::test]
async fn clearing_resignals_the_same_id_as_attempt_one_of_a_new_epoch() {
    let d = start(&["overmind"]).await;
    let (launcher, _sender) = mail_waits_for_a_silent_alpha(&d).await;
    let (_, w) = get(&d, "/v1/waiting", &launcher).await;
    let sig = w["roles"][0].clone();
    let (s, r) = post(
        &d,
        "/v1/launch-result",
        Some(&launcher),
        json!({
            "signal_id": sig["signal_id"], "epoch": sig["epoch"], "attempt": 1,
            "role": "alpha", "outcome": "refused", "reason": "policy",
        }),
    )
    .await;
    assert_eq!(s, 200, "{r}");
    let (_, w) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(
        w["roles"].as_array().unwrap().len(),
        0,
        "refused is terminal"
    );

    let (s, cleared) = post(
        &d,
        "/v1/launch-clear",
        Some(&launcher),
        json!({"role": "alpha"}),
    )
    .await;
    assert_eq!(s, 200, "{cleared}");
    assert_ne!(cleared["epoch"], sig["epoch"]);
    let (_, w) = get(&d, "/v1/waiting", &launcher).await;
    let again = &w["roles"][0];
    assert_eq!(again["signal_id"], sig["signal_id"]);
    assert_eq!(again["attempt"], 1);
    assert_eq!(again["epoch"], cleared["epoch"]);
    d.stop().await;
}

#[tokio::test]
async fn a_role_that_speaks_is_online_and_not_signalled() {
    let d = start(&["overmind"]).await;
    let (launcher, _sender) = mail_waits_for_a_silent_alpha(&d).await;
    // Alpha claims again and makes an authenticated call: it is heard from, so it is online.
    let alpha = claim(&d, "alpha").await;
    let (s, _) = post(&d, "/v1/heartbeat", Some(&alpha), json!({})).await;
    assert_eq!(s, 200);
    let (_, w) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(w["roles"].as_array().unwrap().len(), 0, "{w}");
    d.stop().await;
}

#[tokio::test]
async fn malformed_launch_requests_are_400() {
    let d = start(&["overmind"]).await;
    let launcher = claim(&d, "overmind").await;
    assert_eq!(get(&d, "/v1/waiting?wait=abc", &launcher).await.0, 400);
    assert_eq!(get(&d, "/v1/waiting?other=1", &launcher).await.0, 400);
    for bad in [
        json!({"signal_id": "x", "epoch": "e", "attempt": 1, "role": "alpha", "outcome": "nope"}),
        json!({"signal_id": "x", "epoch": "e", "attempt": 1, "role": "a b", "outcome": "started"}),
        json!({"signal_id": "x", "epoch": "e", "attempt": 1, "role": "alpha",
               "outcome": "failed", "reason": "has a space and: free text"}),
    ] {
        let (s, e) = post(&d, "/v1/launch-result", Some(&launcher), bad).await;
        assert_eq!(s, 400, "{e}");
    }
    // A bounded wait with nothing waiting returns an empty list after about the wait.
    let started = std::time::Instant::now();
    let (s, w) = get(&d, "/v1/waiting?wait=1", &launcher).await;
    assert_eq!(s, 200);
    assert_eq!(w["roles"].as_array().unwrap().len(), 0);
    assert!(started.elapsed() >= Duration::from_millis(900));
    d.stop().await;
}

/// `overmind` (launcher), a silent `alpha`, and `beta` and `gamma` as possible senders.
async fn two_senders(d: &Running) -> (String, String, String) {
    let launcher = claim(d, "overmind").await;
    let _alpha = claim(d, "alpha").await;
    let beta = claim(d, "beta").await;
    let gamma = claim(d, "gamma").await;
    (launcher, beta, gamma)
}

async fn send_to_alpha(d: &Running, token: &str, id: &str) {
    let (s, sent) = post(
        d,
        "/v1/send",
        Some(token),
        json!({"to": "alpha@acct", "message_id": id, "body_b64": B64.encode(b"x")}),
    )
    .await;
    assert_eq!(s, 200, "{sent}");
}

async fn silence(d: &Running) {
    let _ = d;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn mail_from_an_allowed_sender_signals() {
    let d = start_with(&["overmind"], &["beta"]).await;
    let (launcher, beta, _gamma) = two_senders(&d).await;
    send_to_alpha(&d, &beta, "m1").await;
    silence(&d).await;
    let (s, w) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(s, 200, "{w}");
    assert_eq!(w["roles"].as_array().unwrap().len(), 1, "{w}");
    assert_eq!(w["roles"][0]["count"], 1);
    d.stop().await;
}

#[tokio::test]
async fn mail_from_a_sender_not_listed_does_not_signal() {
    let d = start_with(&["overmind"], &["beta"]).await;
    let (launcher, _beta, gamma) = two_senders(&d).await;
    send_to_alpha(&d, &gamma, "m1").await;
    silence(&d).await;
    let (s, w) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(s, 200, "{w}");
    assert_eq!(w["roles"], json!([]), "{w}");
    d.stop().await;
}

#[tokio::test]
async fn mixed_mail_signals_on_the_allowed_messages_count_and_time() {
    let d = start_with(&["overmind"], &["beta"]).await;
    let (launcher, beta, gamma) = two_senders(&d).await;
    send_to_alpha(&d, &gamma, "early").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let before_beta = Utc::now();
    send_to_alpha(&d, &beta, "late").await;
    silence(&d).await;
    let (_, w) = get(&d, "/v1/waiting", &launcher).await;
    let sig = &w["roles"][0];
    assert_eq!(sig["count"], 1, "the unlisted message is not counted: {w}");
    let id = sig["signal_id"].as_str().unwrap();
    let stamp = id.strip_prefix("alpha:").expect("signal id shape");
    let at: DateTime<Utc> = stamp.parse().unwrap();
    assert!(
        at >= before_beta,
        "signal id {id} is dated by the unlisted message, not the allowed one"
    );
    d.stop().await;
}

#[tokio::test]
async fn an_empty_sender_list_signals_nothing_even_with_launcher_roles() {
    let d = start_with(&["overmind"], &[]).await;
    let (launcher, beta, _gamma) = two_senders(&d).await;
    send_to_alpha(&d, &beta, "m1").await;
    silence(&d).await;
    let (s, w) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(s, 200, "{w}");
    assert_eq!(w["roles"], json!([]), "empty must never mean anyone: {w}");
    d.stop().await;
}

#[tokio::test]
async fn a_changed_allowlist_applies_on_the_next_poll_and_a_role_at_account_matches() {
    let d = start_with(&["overmind"], &["gamma"]).await;
    let (launcher, beta, _gamma) = two_senders(&d).await;
    send_to_alpha(&d, &beta, "m1").await;
    silence(&d).await;
    assert_eq!(
        get(&d, "/v1/waiting", &launcher).await.1["roles"],
        json!([])
    );
    d.senders.set(vec!["beta@acct".to_string()]);
    let (_, w) = get(&d, "/v1/waiting", &launcher).await;
    assert_eq!(w["roles"].as_array().unwrap().len(), 1, "{w}");
    // Another account's beta is not this account's beta.
    d.senders.set(vec!["beta@other".to_string()]);
    assert_eq!(
        get(&d, "/v1/waiting", &launcher).await.1["roles"],
        json!([])
    );
    d.stop().await;
}

#[tokio::test]
async fn stats_says_whether_launch_senders_is_set() {
    let set = start_with(&["overmind"], &["beta"]).await;
    let token = claim(&set, "overmind").await;
    assert_eq!(
        get(&set, "/v1/stats", &token).await.1["launch_senders_set"],
        true
    );
    set.stop().await;
    let unset = start_with(&["overmind"], &[]).await;
    let token = claim(&unset, "overmind").await;
    assert_eq!(
        get(&unset, "/v1/stats", &token).await.1["launch_senders_set"],
        false
    );
    unset.stop().await;
}

// A sender cannot borrow a listed role's name: `a_forged_from_is_refused` and
// `a_claim_without_key_proof_issues_no_token` in tests/api.rs pin that the sender is the claimed,
// key-proven role and never a client-supplied value.
