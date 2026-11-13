// SPDX-License-Identifier: MIT OR Apache-2.0
//! `[STALLED]` notices (ROADMAP row 31, liveness part 2, S2): mail waiting for an offline role is
//! announced once to each sender and once, as a digest, to the alert roles. Real loopback HTTP, a short
//! online window and stall delay, and real sleeps, as `launch.rs` does.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use synapse::certificate::Permission;
use synapse::certificate::chain_to_pem;
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

/// Online window and stall delay 300 ms, sweep every 100 ms; `realert` as given; `ops` is the one
/// alert role; `pm` holds `role-admin`.
async fn start(realert: Duration) -> Running {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    Keystore::open(home.path())
        .unwrap()
        .grant("pm", &Permission::RoleAdmin)
        .unwrap();
    let config = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_millis(100),
    };
    common::allow_all(&config.home);
    let daemon = Daemon::open(&config)
        .expect("open daemon")
        .with_online_window(chrono::Duration::milliseconds(300))
        .with_stall(Duration::from_millis(300), realert)
        .with_alert_roles(vec!["ops".to_string()]);
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

async fn send(d: &Running, from: &str, to: &str, text: &str) {
    let (s, sent) = post(
        d,
        "/v1/send",
        Some(from),
        json!({"to": to, "body_b64": B64.encode(text)}),
    )
    .await;
    assert_eq!(s, 200, "{sent}");
}

/// Every message waiting for the holder of `token`, as text, leased for a second and not acked.
async fn inbox(d: &Running, token: &str) -> Vec<String> {
    let (s, got) = post(d, "/v1/fetch", Some(token), json!({"max": 50})).await;
    assert_eq!(s, 200, "{got}");
    got["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| String::from_utf8(B64.decode(m["body_b64"].as_str().unwrap()).unwrap()).unwrap())
        .collect()
}

fn stalled(inbox: &[String]) -> Vec<&String> {
    inbox
        .iter()
        .filter(|m| m.starts_with("[STALLED]"))
        .collect()
}

async fn wait(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[tokio::test]
async fn an_offline_role_with_queued_mail_gets_one_stalled_notice_per_sender() {
    let d = start(Duration::from_secs(3600)).await;
    let _alpha = claim(&d, "alpha").await;
    let (beta, gamma) = (claim(&d, "beta").await, claim(&d, "gamma").await);
    send(&d, &beta, "alpha@acct", "one").await;
    send(&d, &beta, "alpha@acct", "two").await;
    send(&d, &gamma, "alpha@acct", "three").await;
    wait(1500).await; // several sweeps past the 300 ms stall delay
    let (b, g) = (inbox(&d, &beta).await, inbox(&d, &gamma).await);
    assert_eq!(stalled(&b).len(), 1, "{b:?}");
    assert!(
        stalled(&b)[0].starts_with("[STALLED] role=alpha waiting=2 oldest="),
        "{b:?}"
    );
    assert!(stalled(&b)[0].ends_with(" online=false"), "{b:?}");
    assert_eq!(stalled(&g).len(), 1, "{g:?}");
    assert!(
        stalled(&g)[0].starts_with("[STALLED] role=alpha waiting=1 "),
        "{g:?}"
    );
    d.stop().await;
}

#[tokio::test]
async fn an_online_role_is_never_stalled() {
    let d = start(Duration::from_secs(3600)).await;
    let alpha = claim(&d, "alpha").await;
    let beta = claim(&d, "beta").await;
    send(&d, &beta, "alpha@acct", "hello").await;
    for _ in 0..12 {
        let (s, _) = post(&d, "/v1/heartbeat", Some(&alpha), json!({})).await;
        assert_eq!(s, 200);
        wait(100).await;
    }
    assert!(stalled(&inbox(&d, &beta).await).is_empty());
    d.stop().await;
}

#[tokio::test]
async fn a_fetch_ends_the_episode_and_a_new_stall_waits_for_stall_realert() {
    let d = start(Duration::from_secs(3600)).await;
    let alpha = claim(&d, "alpha").await;
    let beta = claim(&d, "beta").await;
    send(&d, &beta, "alpha@acct", "first").await;
    wait(1200).await;
    let first = inbox(&d, &beta).await;
    assert_eq!(stalled(&first).len(), 1, "{first:?}");
    // Alpha comes back, reads and acks everything: the episode is over.
    let (s, got) = post(&d, "/v1/fetch", Some(&alpha), json!({"max": 50})).await;
    assert_eq!(s, 200);
    for m in got["messages"].as_array().unwrap() {
        post(
            &d,
            "/v1/ack",
            Some(&alpha),
            json!({"message_id": m["message_id"]}),
        )
        .await;
    }
    // It goes quiet again with new mail waiting: inside stall_realert, so no second notice.
    send(&d, &beta, "alpha@acct", "second").await;
    wait(1500).await;
    let again = inbox(&d, &beta).await;
    assert!(stalled(&again).is_empty(), "{again:?}");
    d.stop().await;
}

#[tokio::test]
async fn a_role_that_stays_stalled_is_announced_again_after_stall_realert() {
    let d = start(Duration::from_millis(700)).await;
    let _alpha = claim(&d, "alpha").await;
    let beta = claim(&d, "beta").await;
    send(&d, &beta, "alpha@acct", "waiting").await;
    wait(2500).await;
    // Notices are delivered once (single delivery), so each fetch drains what is there.
    let got = inbox(&d, &beta).await;
    assert!(stalled(&got).len() >= 2, "{got:?}");
    d.stop().await;
}

#[tokio::test]
async fn a_retired_role_is_not_stalled() {
    let d = start(Duration::from_secs(3600)).await;
    let _alpha = claim(&d, "alpha").await;
    let (beta, pm) = (claim(&d, "beta").await, claim(&d, "pm").await);
    send(&d, &beta, "alpha@acct", "hello").await;
    let (s, r) = post(&d, "/v1/roles/retire", Some(&pm), json!({"role": "alpha"})).await;
    assert_eq!(s, 200, "{r}");
    wait(1200).await;
    assert!(stalled(&inbox(&d, &beta).await).is_empty());
    d.stop().await;
}

#[tokio::test]
async fn a_stalled_notice_is_not_itself_stalled_mail() {
    let d = start(Duration::from_millis(200)).await;
    let _alpha = claim(&d, "alpha").await;
    let beta = claim(&d, "beta").await;
    send(&d, &beta, "alpha@acct", "waiting").await;
    wait(1500).await;
    // Beta never fetched, so the notices to it sit in its queue; it is offline with only the
    // daemon's own mail waiting. Nothing may announce beta as stalled to anyone.
    let ops = claim(&d, "ops").await;
    let seen = inbox(&d, &ops).await;
    assert!(
        seen.iter()
            .all(|m| !m.contains("role=beta") && !m.contains("beta:")),
        "{seen:?}"
    );
    d.stop().await;
}

#[tokio::test]
async fn the_alert_roles_get_one_digest_not_one_per_message() {
    let d = start(Duration::from_secs(3600)).await;
    let _alpha = claim(&d, "alpha").await;
    let beta = claim(&d, "beta").await;
    for i in 0..5 {
        send(&d, &beta, "alpha@acct", &format!("m{i}")).await;
    }
    wait(1500).await;
    let ops = claim(&d, "ops").await;
    let got = inbox(&d, &ops).await;
    let digests: Vec<_> = got
        .iter()
        .filter(|m| m.starts_with("[STALLED] digest"))
        .collect();
    assert_eq!(digests.len(), 1, "{got:?}");
    assert!(digests[0].contains("roles=1 list=alpha:5:"), "{got:?}");
    d.stop().await;
}
