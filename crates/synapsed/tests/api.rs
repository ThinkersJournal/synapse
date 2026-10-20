// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapsed` over real loopback HTTP (M5a), including the PM's security conditions:
//! claims prove the role key, Host-header check, no CORS, Bearer on every authenticated route,
//! constant-time token handling, and no token or key material in responses.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use synapse::certificate::chain_to_pem;
use synapse::keystore::Keystore;
use synapse::roles::{sign_claim, sign_claim_for};
use synapse::security_events::LimiterConfig;
use synapsed::{Daemon, DaemonConfig, DaemonError, Pause, SECURITY_EVENTS_FILE, SecurityConfig};

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

fn config(home: &std::path::Path) -> DaemonConfig {
    DaemonConfig {
        home: home.to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    }
}

/// `SYNAPSE_TEST_STORE=sqlite` (with `--features sqlite-store`) runs this whole suite against the
/// PersistAnt SQLite store; unset, against redb.
fn open_daemon(cfg: &DaemonConfig) -> Result<Daemon, DaemonError> {
    #[cfg(feature = "sqlite-store")]
    if std::env::var("SYNAPSE_TEST_STORE").as_deref() == Ok("sqlite") {
        return Daemon::open_with(cfg, synapsed::StoreKind::Sqlite);
    }
    Daemon::open(cfg)
}

async fn start() -> Running {
    start_with(None).await
}

async fn start_with(security: Option<SecurityConfig>) -> Running {
    start_daemon(security, None).await
}

async fn start_daemon(security: Option<SecurityConfig>, pause: Option<Pause>) -> Running {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let mut daemon = open_daemon(&config(home.path())).expect("open daemon");
    if let Some(security) = security {
        daemon = daemon.with_security(security);
    }
    if let Some(pause) = pause {
        daemon = daemon.with_pause(pause);
    }
    let started_at = daemon.started_at();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.serve(listener, async move {
        let _ = rx.await;
    }));
    // The daemon announces its address and instance id before serving; claims need the id.
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

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

async fn get_json(d: &Running, path: &str, token: &str) -> Value {
    let reply = client()
        .get(d.url(path))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status().as_u16(), 200, "GET {path}");
    reply.json().await.unwrap()
}

/// A wire-format claim for `role`, signed after the daemon started (M3 refuses claims signed at or
/// before the table's start).
fn claim_body(d: &Running, role: &str) -> Value {
    // A fresh random nonce per claim: no test carries a literal nonce, and a test that needs a
    // replay reuses the returned body.
    claim_body_with(d, role, *uuid::Uuid::new_v4().as_bytes())
}

fn claim_body_with(d: &Running, role: &str, nonce: [u8; 16]) -> Value {
    let store = Keystore::open(d.home.path()).unwrap();
    // The certificate is issued at the real time; only the claim is signed after the daemon's
    // start (a certificate issued in the daemon's future would be "not yet valid").
    let identity = store.role(role, Utc::now()).unwrap();
    let signed_at = Utc::now().max(d.started_at + chrono::Duration::seconds(1));
    let req = sign_claim_for(&identity, &instance_id(d), nonce, signed_at).unwrap();
    json!({
        "audience": req.audience,
        "chain_pem": chain_to_pem(&req.chain),
        "nonce_hex": req.nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "signed_at": req.signed_at.to_rfc3339(),
        "signature_b64": B64.encode(&req.signature),
    })
}

/// The daemon's instance id, as a same-user client learns it: from the owner-only announce file.
fn instance_id(d: &Running) -> String {
    let text = std::fs::read_to_string(d.home.path().join("synapsed.json")).expect("announce file");
    let v: Value = serde_json::from_str(&text).unwrap();
    v["instance_id"].as_str().unwrap().to_string()
}

async fn claim(d: &Running, role: &str) -> (String, u64) {
    claim_with(d, claim_body(d, role)).await
}

/// A claim with a fresh random nonce, for tests that claim a role many times.
async fn claim_fresh(d: &Running, role: &str) -> (String, u64) {
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    claim_with(d, claim_body_with(d, role, nonce)).await
}

async fn claim_with(d: &Running, body: Value) -> (String, u64) {
    let (status, reply, text) = post(d, "/v1/claim", None, body).await;
    assert_eq!(status, 200, "claim refused: {text}");
    (
        reply["session"]
            .as_str()
            .expect("a session token")
            .to_string(),
        reply["epoch"].as_u64().expect("an epoch"),
    )
}

async fn post(d: &Running, path: &str, token: Option<&str>, body: Value) -> (u16, Value, String) {
    let mut req = client().post(d.url(path)).json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, value, text)
}

#[tokio::test]
async fn health_answers_without_a_token() {
    let d = start().await;
    let reply: Value = client()
        .get(d.url("/v1/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reply["ok"], true);
    assert!(reply["started_at"].is_string());
    assert!(reply.get("proof").is_none(), "no challenge, no proof");
    d.stop().await;
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Whether `proof` is HMAC-SHA256(instance id, message for `addr` and `challenge`).
fn proof_holds(instance_id: &str, addr: SocketAddr, challenge: &[u8; 16], proof: &str) -> bool {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &unhex(instance_id));
    let msg = synapsed::health_proof_message(addr, challenge);
    ring::hmac::verify(&key, &msg, &unhex(proof)).is_ok()
}

/// #74: a challenged health proves the daemon holds the announced instance id, bound to the
/// challenge and to the address it serves on.
#[tokio::test]
async fn health_proves_the_instance_id() {
    let d = start().await;
    let id = instance_id(&d);
    let challenge = [0x5a; 16];
    let hexed: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
    let reply: Value = client()
        .get(d.url(&format!("/v1/health?challenge={hexed}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proof = reply["proof"].as_str().expect("a proof");
    assert!(proof_holds(&id, d.addr, &challenge, proof), "{reply}");
    // The same proof is worthless for another challenge, another address, or another instance.
    assert!(!proof_holds(&id, d.addr, &[0xa5; 16], proof));
    let elsewhere: SocketAddr = format!("127.0.0.1:{}", d.addr.port() ^ 1).parse().unwrap();
    assert!(!proof_holds(&id, elsewhere, &challenge, proof));
    assert!(!proof_holds(&"00".repeat(16), d.addr, &challenge, proof));

    for bad in [
        "challenge=",
        "challenge=zz",
        "challenge=+aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "challenge=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "other=1",
    ] {
        let resp = client()
            .get(d.url(&format!("/v1/health?{bad}")))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{bad}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "malformed", "{bad}");
    }
    d.stop().await;
}

/// #74: the daemon removes its announce file when it stops, but only while the file still names it.
#[tokio::test]
async fn stopping_removes_only_its_own_announce_file() {
    // Stop by hand rather than with `Running::stop`, which would drop the home with the file.
    async fn stop_keeping_home(d: Running) -> tempfile::TempDir {
        let Running {
            home, stop, task, ..
        } = d;
        stop.unwrap().send(()).unwrap();
        task.unwrap().await.unwrap().unwrap();
        home
    }

    let d = start().await;
    let path = d.home.path().join("synapsed.json");
    assert!(path.exists(), "announced while serving");
    let home = stop_keeping_home(d).await;
    assert!(!path.exists(), "removed on graceful stop");
    drop(home);

    // A file that names another instance is not ours to remove.
    let d = start().await;
    let path = d.home.path().join("synapsed.json");
    let other =
        json!({"addr": "127.0.0.1:1", "instance_id": "00".repeat(16), "pid": 1}).to_string();
    std::fs::write(&path, &other).unwrap();
    let home = stop_keeping_home(d).await;
    assert_eq!(std::fs::read_to_string(&path).unwrap(), other);
    drop(home);
}

#[tokio::test]
async fn a_round_trip_between_two_roles() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;
    let body = B64.encode(b"hello beta");
    let (s, sent, _) = post(
        &d,
        "/v1/send",
        Some(&alpha),
        json!({"to": "beta@acct", "body_b64": body}),
    )
    .await;
    assert_eq!(s, 200, "{sent}");
    assert_eq!(sent["outcome"], "queued");
    let id = sent["message_id"].as_str().unwrap().to_string();

    let (s, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
    assert_eq!(s, 200, "{got}");
    let msg = &got["messages"][0];
    assert_eq!(msg["message_id"], id.as_str());
    assert_eq!(
        msg["from"], "alpha@acct",
        "from is the sender's verified role"
    );
    assert_eq!(
        B64.decode(msg["body_b64"].as_str().unwrap()).unwrap(),
        b"hello beta"
    );

    let (s, acked, _) = post(&d, "/v1/ack", Some(&beta), json!({"message_id": id})).await;
    assert_eq!(s, 200, "{acked}");
    assert_eq!(acked["outcome"], "removed");
    d.stop().await;
}

/// A message fetched `max_deliveries` times (each time by a fresh holder, which voids the prior
/// lease) moves to the role's dead set: `/v1/dead` shows it with its body, `/v1/requeue` puts it
/// back with the count reset.
#[tokio::test]
async fn a_message_never_acked_goes_dead_and_can_be_requeued() {
    let d = start().await;
    let (alpha, _) = claim_fresh(&d, "alpha").await;
    claim_fresh(&d, "beta").await;
    let (s, sent, _) = post(
        &d,
        "/v1/send",
        Some(&alpha),
        json!({"to": "beta@acct", "message_id": "m1", "body_b64": B64.encode(b"poison")}),
    )
    .await;
    assert_eq!(s, 200, "{sent}");
    let id = sent["message_id"].as_str().unwrap().to_string();
    for round in 0..10 {
        let beta = claim_fresh(&d, "beta").await.0;
        let (s, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
        assert_eq!(s, 200, "{got}");
        assert_eq!(
            got["messages"].as_array().unwrap().len(),
            1,
            "round {round}"
        );
    }
    let beta = claim_fresh(&d, "beta").await.0;
    let (_, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
    assert!(
        got["messages"].as_array().unwrap().is_empty(),
        "the tenth lease was the last: {got}"
    );
    let dead = get_json(&d, "/v1/dead", &beta).await;
    let dead = dead["messages"].as_array().unwrap();
    assert_eq!(dead.len(), 1, "{dead:?}");
    assert_eq!(dead[0]["message_id"], id.as_str());
    assert_eq!(dead[0]["from"], "alpha@acct");
    assert_eq!(dead[0]["attempts"], 10);
    assert_eq!(
        B64.decode(dead[0]["body_b64"].as_str().unwrap()).unwrap(),
        b"poison"
    );
    let listed = get_json(&d, "/v1/list", &beta).await;
    let beta_entry = listed["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == "beta@acct")
        .expect("beta listed");
    assert_eq!(beta_entry["pending"]["dead"], 1);

    let (s, requeued, _) = post(&d, "/v1/requeue", Some(&beta), json!({"message_id": id})).await;
    assert_eq!(s, 200, "{requeued}");
    assert_eq!(requeued["outcome"], "requeued");
    let (_, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
    assert_eq!(
        got["messages"][0]["attempts"], 1,
        "the count was reset: {got}"
    );
    let (s, _, _) = post(&d, "/v1/requeue", Some(&beta), json!({"message_id": id})).await;
    assert_eq!(s, 404, "a message that is not dead cannot be requeued");
    d.stop().await;
}

#[tokio::test]
async fn a_forged_from_is_refused() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (s, _, _) = post(
        &d,
        "/v1/send",
        Some(&alpha),
        json!({"to": "beta@acct", "from": "beta@acct", "body_b64": B64.encode(b"x")}),
    )
    .await;
    assert_eq!(s, 400, "a client-supplied from must be refused");
    d.stop().await;
}

#[tokio::test]
async fn a_bad_or_missing_token_is_401() {
    // 17 bad requests: a roomy budget, so this test measures status codes and not the limiter.
    let d = start_with(Some(tuned(1000, 200, 2000, std::time::Duration::ZERO))).await;
    let bad = "00".repeat(32);
    for path in [
        "/v1/send",
        "/v1/fetch",
        "/v1/ack",
        "/v1/heartbeat",
        "/v1/requeue",
    ] {
        let plus = format!("+a{}", "0".repeat(62)); // u8::from_str_radix accepts "+a"
        for token in [
            None,
            Some(bad.as_str()),
            Some("not-hex"),
            Some(plus.as_str()),
        ] {
            let (s, _, _) = post(&d, path, token, json!({})).await;
            assert_eq!(s, 401, "{path} with token {token:?}");
        }
    }
    let s = client()
        .get(d.url("/v1/list"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(s, 401, "/v1/list without a token");
    d.stop().await;
}

#[tokio::test]
async fn an_old_epoch_token_is_409_after_takeover() {
    let d = start().await;
    let (old, first) = claim(&d, "alpha").await;
    let (_new, second) = claim(&d, "alpha").await;
    assert_eq!(second, first + 1);
    let (s, reply, _) = post(
        &d,
        "/v1/send",
        Some(&old),
        json!({"to": "beta@acct", "body_b64": ""}),
    )
    .await;
    assert_eq!(s, 409, "{reply}");
    assert_eq!(reply["error"], "superseded");
    assert_eq!(reply["current"], second);
    d.stop().await;
}

#[tokio::test]
async fn a_claim_without_key_proof_issues_no_token() {
    let d = start().await;
    let mut body = claim_body(&d, "alpha");
    let mut sig = B64.decode(body["signature_b64"].as_str().unwrap()).unwrap();
    sig[0] ^= 1;
    body["signature_b64"] = json!(B64.encode(&sig));
    let (s, reply, _) = post(&d, "/v1/claim", None, body).await;
    assert_eq!(s, 403, "{reply}");
    assert_eq!(reply["error"], "claim_refused");
    assert!(
        reply.get("session").is_none(),
        "no token for an unproven claim"
    );
    d.stop().await;
}

/// Raw HTTP, so the Host header is exactly what the test says.
fn raw(addr: SocketAddr, request: &str) -> String {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[tokio::test]
async fn a_wrong_host_header_is_421() {
    let d = start().await;
    let addr = d.addr;
    let port = addr.port();
    let cases = [
        format!("evil.example:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        "127.0.0.1".to_string(),
    ];
    for host in cases {
        let req = format!("GET /v1/health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let reply = tokio::task::spawn_blocking(move || raw(addr, &req))
            .await
            .unwrap();
        assert!(reply.starts_with("HTTP/1.1 421"), "Host {host}: {reply}");
    }
    let good =
        format!("GET /v1/health HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
    let reply = tokio::task::spawn_blocking(move || raw(addr, &good))
        .await
        .unwrap();
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "control, localhost:port: {reply}"
    );
    d.stop().await;
}

#[tokio::test]
async fn no_response_carries_cors_headers() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let responses = vec![
        client()
            .get(d.url("/v1/health"))
            .header("Origin", "https://evil.example")
            .send()
            .await
            .unwrap(),
        client()
            .request(reqwest::Method::OPTIONS, d.url("/v1/send"))
            .header("Origin", "https://evil.example")
            .header("Access-Control-Request-Method", "POST")
            .send()
            .await
            .unwrap(),
        client()
            .post(d.url("/v1/fetch"))
            .bearer_auth(&alpha)
            .header("Origin", "https://evil.example")
            .json(&json!({}))
            .send()
            .await
            .unwrap(),
    ];
    for r in responses {
        let cors: Vec<_> = r
            .headers()
            .keys()
            .filter(|k| k.as_str().starts_with("access-control-"))
            .collect();
        assert!(cors.is_empty(), "CORS headers on {}: {cors:?}", r.url());
    }
    d.stop().await;
}

#[tokio::test]
async fn a_post_without_json_content_type_is_415() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let s = client()
        .post(d.url("/v1/fetch"))
        .bearer_auth(&alpha)
        .header("Content-Type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(s, 415);
    d.stop().await;
}

#[test]
fn a_non_loopback_bind_is_refused() {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").unwrap();
    let mut cfg = config(home.path());
    cfg.addr = "0.0.0.0:7920".parse().unwrap();
    assert!(matches!(Daemon::open(&cfg), Err(DaemonError::NotLoopback)));
}

#[tokio::test]
async fn a_second_daemon_on_the_same_home_fails() {
    let d = start().await;
    assert!(
        open_daemon(&config(d.home.path())).is_err(),
        "the store lock keeps one daemon"
    );
    d.stop().await;
}

#[tokio::test]
async fn no_token_or_key_material_leaks() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (_beta, _) = claim(&d, "beta").await;
    let mut bodies = Vec::new();
    for (path, body) in [
        (
            "/v1/send",
            json!({"to": "beta@acct", "body_b64": B64.encode(b"x")}),
        ),
        ("/v1/fetch", json!({})),
        ("/v1/heartbeat", json!({"summary": "working"})),
        ("/v1/ack", json!({"message_id": "nope"})),
        ("/v1/send", json!({"to": "not a role", "body_b64": ""})),
    ] {
        bodies.push(post(&d, path, Some(&alpha), body).await.2);
    }
    bodies.push(
        client()
            .get(d.url("/v1/list"))
            .bearer_auth(&alpha)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    );
    for text in bodies {
        assert!(
            !text.contains(&alpha),
            "a response carried the session token: {text}"
        );
        assert!(
            !text.contains("PRIVATE KEY"),
            "a response carried key material: {text}"
        );
    }
    d.stop().await;
}

#[tokio::test]
async fn list_shows_claimed_roles_with_presence() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (s, _, _) = post(
        &d,
        "/v1/heartbeat",
        Some(&alpha),
        json!({"summary": "writing M5"}),
    )
    .await;
    assert_eq!(s, 200);
    let reply: Value = client()
        .get(d.url("/v1/list"))
        .bearer_auth(&alpha)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let roles = reply["roles"].as_array().unwrap();
    let me = roles
        .iter()
        .find(|r| r["global_id"] == "alpha@acct")
        .expect("alpha listed");
    assert_eq!(me["online"], true);
    assert_eq!(me["summary"], "writing M5");
    d.stop().await;
}

// ---- Final-review fixes (Opus review of M5a) ----

/// Review I3: a claim is bound to this daemon's instance id. A claim for another audience, or an
/// unbound v1 claim, gets no token, so a claim captured by a port-squatter can't be relayed here.
#[tokio::test]
async fn a_claim_for_another_daemon_or_no_daemon_is_refused() {
    let d = start().await;
    let store = Keystore::open(d.home.path()).unwrap();
    let identity = store.role("alpha", Utc::now()).unwrap();
    let signed_at = Utc::now().max(d.started_at + chrono::Duration::seconds(1));
    for req in [
        sign_claim_for(
            &identity,
            "another-daemon",
            *uuid::Uuid::new_v4().as_bytes(),
            signed_at,
        )
        .unwrap(),
        sign_claim(&identity, *uuid::Uuid::new_v4().as_bytes(), signed_at).unwrap(),
    ] {
        let body = json!({
            "audience": req.audience,
            "chain_pem": chain_to_pem(&req.chain),
            "nonce_hex": req.nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "signed_at": req.signed_at.to_rfc3339(),
            "signature_b64": B64.encode(&req.signature),
        });
        let (s, reply, _) = post(&d, "/v1/claim", None, body).await;
        assert_eq!(s, 403, "audience {:?}: {reply}", req.audience);
        assert!(reply.get("session").is_none());
    }
    d.stop().await;
}

/// Review I3: the instance id is announced only through an owner-only file, never over HTTP.
#[tokio::test]
async fn the_instance_id_is_announced_only_in_an_owner_only_file() {
    let d = start().await;
    let id = instance_id(&d);
    assert_eq!(id.len(), 32);
    let health = client()
        .get(d.url("/v1/health"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !health.contains(&id),
        "health must not reveal the instance id"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.home.path().join("synapsed.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    d.stop().await;
}

/// Review I1: message ids are scoped by sender, so one role can't take another's id first.
#[tokio::test]
async fn a_squatted_message_id_does_not_suppress_another_senders_message() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;
    let (gamma, _) = claim(&d, "gamma").await;
    let send = |token: String, body: &'static [u8]| {
        let d = &d;
        async move {
            post(
                d,
                "/v1/send",
                Some(&token),
                json!({"to": "beta@acct", "message_id": "m1", "body_b64": B64.encode(body)}),
            )
            .await
        }
    };
    let (_, g, _) = send(gamma.clone(), b"forged").await;
    let (_, a, _) = send(alpha.clone(), b"real").await;
    assert_eq!(g["outcome"], "queued");
    assert_eq!(
        a["outcome"], "queued",
        "alpha's m1 must not be a duplicate of gamma's: {a}"
    );
    assert_ne!(a["message_id"], g["message_id"]);
    let (_, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
    let froms: Vec<&str> = got["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["from"].as_str().unwrap())
        .collect();
    assert_eq!(froms.len(), 2, "{got}");
    assert!(froms.contains(&"alpha@acct") && froms.contains(&"gamma@acct"));
    // A resend by the same sender with the same id is still a duplicate.
    let (_, again, _) = send(alpha, b"real").await;
    assert_eq!(again["outcome"], "duplicate");
    d.stop().await;
}

/// Review I2: the daemon serves its own account's claimed roles only; anything else would let one
/// role fill the disk with queues nobody can ever read.
#[tokio::test]
async fn mail_for_a_foreign_account_or_an_unclaimed_role_is_refused() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    for to in ["x@other", "never-claimed@acct"] {
        let (s, reply, _) = post(
            &d,
            "/v1/send",
            Some(&alpha),
            json!({"to": to, "body_b64": B64.encode(b"x")}),
        )
        .await;
        assert_eq!(s, 404, "{to}: {reply}");
        assert_eq!(reply["error"], "unknown_recipient");
    }
    d.stop().await;
}

/// Review M1: an absurd lease is a 400, not a panic in the handler.
#[tokio::test]
async fn an_oversized_lease_is_400_not_a_panic() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (s, reply, _) = post(
        &d,
        "/v1/fetch",
        Some(&alpha),
        json!({"lease_secs": i64::MAX}),
    )
    .await;
    assert_eq!(s, 400, "{reply}");
    d.stop().await;
}

/// Review M2: serve() itself refuses a non-loopback listener, whatever the config said.
#[tokio::test]
async fn serve_refuses_a_non_loopback_listener() {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").unwrap();
    let daemon = Daemon::open(&config(home.path())).unwrap();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let result = daemon.serve(listener, async {}).await;
    assert!(result.is_err(), "serving on 0.0.0.0 must fail");
}

/// Review M3: more than one Host header is refused, whichever comes first.
#[tokio::test]
async fn duplicate_host_headers_are_421() {
    let d = start().await;
    let addr = d.addr;
    let port = addr.port();
    let req = format!(
        "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nHost: evil.example:{port}\r\nConnection: close\r\n\r\n"
    );
    let reply = tokio::task::spawn_blocking(move || raw(addr, &req))
        .await
        .unwrap();
    assert!(reply.starts_with("HTTP/1.1 421"), "{reply}");
    d.stop().await;
}

/// Queue one message to `to` with the session `token`'s role as sender; returns its full id.
async fn send_to(d: &Running, token: &str, to: &str, body: &[u8]) -> String {
    let (s, sent, text) = post(
        d,
        "/v1/send",
        Some(token),
        json!({"to": to, "body_b64": B64.encode(body)}),
    )
    .await;
    assert_eq!(s, 200, "{text}");
    assert_eq!(sent["outcome"], "queued");
    sent["message_id"].as_str().unwrap().to_string()
}

/// #77 D1: acking a message the caller's epoch does not hold the lease on is 403 `not_your_lease`.
/// Negative: a queued-but-never-fetched message, and a message leased by a superseded epoch of the
/// same role. Positive: the epoch that holds the lease acks it.
#[tokio::test]
async fn acking_a_message_you_do_not_hold_the_lease_on_is_403_not_your_lease() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;

    // Never fetched, so no lease at all.
    let unleased = send_to(&d, &alpha, "beta@acct", b"one").await;
    let (s, reply, _) = post(&d, "/v1/ack", Some(&beta), json!({"message_id": unleased})).await;
    assert_eq!(s, 403, "{reply}");
    assert_eq!(reply["error"], "not_your_lease");

    // Positive control: once beta fetches it (taking the lease), the same ack succeeds.
    let (s, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
    assert_eq!(s, 200, "{got}");
    assert_eq!(got["messages"][0]["message_id"], unleased.as_str());
    let (s, acked, _) = post(&d, "/v1/ack", Some(&beta), json!({"message_id": unleased})).await;
    assert_eq!(s, 200, "{acked}");
    assert_eq!(acked["outcome"], "removed");

    // Leased by beta's first epoch; after a takeover the new epoch does not hold that lease.
    let leased = send_to(&d, &alpha, "beta@acct", b"two").await;
    let (_, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
    assert_eq!(got["messages"][0]["message_id"], leased.as_str());
    let (beta2, _) = claim(&d, "beta").await;
    let (s, reply, _) = post(&d, "/v1/ack", Some(&beta2), json!({"message_id": leased})).await;
    assert_eq!(s, 403, "{reply}");
    assert_eq!(reply["error"], "not_your_lease");
    d.stop().await;
}

/// #77 D3: a client `message_id` containing `/` or a control character is 400 `malformed` (ids are
/// scoped as `<sender>/<id>`, so a `/` would forge another namespace). `ab` is queued.
#[tokio::test]
async fn a_message_id_with_a_slash_or_control_char_is_400_malformed() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (_beta, _) = claim(&d, "beta").await;
    for bad in ["a/b", "a\u{7}"] {
        let (s, reply, _) = post(
            &d,
            "/v1/send",
            Some(&alpha),
            json!({"to": "beta@acct", "message_id": bad, "body_b64": B64.encode(b"x")}),
        )
        .await;
        assert_eq!(s, 400, "{bad:?}: {reply}");
        assert_eq!(reply["error"], "malformed", "{bad:?}");
    }
    let (s, reply, _) = post(
        &d,
        "/v1/send",
        Some(&alpha),
        json!({"to": "beta@acct", "message_id": "ab", "body_b64": B64.encode(b"x")}),
    )
    .await;
    assert_eq!(s, 200, "{reply}");
    assert_eq!(reply["outcome"], "queued");
    d.stop().await;
}

/// The presence summary `list` reports for `role`.
async fn summary_of(d: &Running, token: &str, role: &str) -> Value {
    let (s, listed, _) = post_get_list(d, token).await;
    assert_eq!(s, 200, "{listed}");
    listed["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == role)
        .expect("role listed")["summary"]
        .clone()
}

async fn post_get_list(d: &Running, token: &str) -> (u16, Value, String) {
    let resp = client()
        .get(d.url("/v1/list"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

/// #77 D4: a heartbeat summary over 500 bytes, or containing a control character, is 400
/// `malformed` and leaves the stored summary unchanged. Exactly 500 characters is accepted.
#[tokio::test]
async fn a_heartbeat_summary_too_long_or_with_a_control_char_is_400_malformed() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    for bad in ["x".repeat(501), "line one\nline two".to_string()] {
        let (s, reply, _) = post(&d, "/v1/heartbeat", Some(&alpha), json!({"summary": bad})).await;
        assert_eq!(s, 400, "{reply}");
        assert_eq!(reply["error"], "malformed");
    }
    assert_eq!(summary_of(&d, &alpha, "alpha@acct").await, Value::Null);

    let ok = "x".repeat(500);
    let (s, reply, _) = post(&d, "/v1/heartbeat", Some(&alpha), json!({"summary": ok})).await;
    assert_eq!(s, 200, "{reply}");
    assert_eq!(summary_of(&d, &alpha, "alpha@acct").await, json!(ok));
    d.stop().await;
}

/// #77 D5: once a recipient's mailbox holds `max_bytes` (64 MiB) of bodies, the next send is 413
/// `mailbox_full` (the daemon's own limit, not axum's 2 MB request cap: each request body here is
/// about 2 MB of base64 and every one before the full mailbox is accepted). Every send before
/// that is queued, and a small message that still fits is queued afterwards.
#[tokio::test]
async fn a_full_mailbox_is_413_mailbox_full() {
    const BODY: usize = 1_500_000; // base64 inflates to 2_000_000 < axum's 2 MiB request limit
    const CAP: usize = 64 * 1024 * 1024;
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (_beta, _) = claim(&d, "beta").await;
    let body = vec![7u8; BODY];

    let fits = CAP / BODY;
    for _ in 0..fits {
        send_to(&d, &alpha, "beta@acct", &body).await;
    }
    let (s, reply, text) = post(
        &d,
        "/v1/send",
        Some(&alpha),
        json!({"to": "beta@acct", "body_b64": B64.encode(&body)}),
    )
    .await;
    assert_eq!(s, 413, "{text}");
    assert_eq!(reply["error"], "mailbox_full");

    // The cap is on bytes: a small message that still fits is accepted.
    send_to(&d, &alpha, "beta@acct", b"small").await;
    d.stop().await;
}

// ---- P5: brute-force hardening (countermeasures and events) ----

fn limiter(free: u32, base_ms: i64, max_ms: i64) -> LimiterConfig {
    LimiterConfig {
        free_failures: free,
        window: chrono::Duration::minutes(5),
        base_delay: chrono::Duration::milliseconds(base_ms),
        max_delay: chrono::Duration::milliseconds(max_ms),
        lockout_after: u32::MAX,
        lockout: chrono::Duration::zero(),
        max_keys: 100,
    }
}

fn tuned(free: u32, base_ms: i64, max_ms: i64, interval: Duration) -> SecurityConfig {
    SecurityConfig {
        bearer: limiter(free, base_ms, max_ms),
        claim: limiter(free, base_ms, max_ms),
        health: limiter(free, base_ms, max_ms),
        misuse: limiter(free, base_ms, max_ms),
        event_interval: interval,
    }
}

/// One free failure, then 200 ms, 400 ms, ...; every event written.
fn small() -> SecurityConfig {
    tuned(1, 200, 2000, Duration::ZERO)
}

const SLOW: Duration = Duration::from_millis(200);

fn events_text(d: &Running) -> String {
    std::fs::read_to_string(d.home.path().join(SECURITY_EVENTS_FILE)).expect("event file")
}

fn events(d: &Running) -> Vec<Value> {
    events_text(d)
        .lines()
        .map(|l| serde_json::from_str(l).expect("a JSON line"))
        .collect()
}

fn on(events: &[Value], kind: &str, surface: &str) -> Vec<Value> {
    events
        .iter()
        .filter(|e| e["kind"] == kind && e["surface"] == surface)
        .cloned()
        .collect()
}

/// The delays the daemon owed, in order. Recorded instead of slept, so the tests below assert which
/// answers were held back without timing them: a slow shared runner once took 260 ms over a valid
/// claim and failed a `< 200 ms` bound that measured the runner, not the daemon.
#[derive(Clone, Default)]
struct Pauses(Arc<Mutex<Vec<Duration>>>);

impl Pauses {
    fn pause(&self) -> Pause {
        let owed = self.0.clone();
        Arc::new(move |delay| {
            owed.lock().unwrap().push(delay);
            Box::pin(std::future::ready(()))
        })
    }

    /// The delays owed since the last call.
    fn take(&self) -> Vec<Duration> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }

    /// The one delay owed since the last call, if any.
    fn owed(&self) -> Option<Duration> {
        let owed = self.take();
        assert!(owed.len() <= 1, "one request owed {owed:?}");
        owed.first().copied()
    }
}

/// [`small`] limits, with every owed delay recorded rather than slept.
async fn start_recorded() -> (Running, Pauses) {
    let pauses = Pauses::default();
    let d = start_daemon(Some(small()), Some(pauses.pause())).await;
    (d, pauses)
}

#[tokio::test]
async fn an_owed_delay_is_really_waited_out() {
    // The real clock, and only a lower bound: an answer cannot arrive before its sleep ends,
    // however slow the machine is.
    let d = start_with(Some(small())).await;
    let mut last = Duration::ZERO;
    for token in ["a1", "b2", "c3"].map(|b| b.repeat(32)) {
        let started = std::time::Instant::now();
        let (s, _, _) = post(&d, "/v1/heartbeat", Some(&token), json!({})).await;
        last = started.elapsed();
        assert_eq!(s, 401);
    }
    assert!(last >= SLOW, "the 3rd failure was answered in {last:?}");
    d.stop().await;
}

#[tokio::test]
async fn bad_bearers_are_delayed_and_recorded() {
    let (d, pauses) = start_recorded().await;
    let (good, _) = claim(&d, "alpha").await;
    pauses.take();
    let bad = ["a1", "b2", "c3"].map(|b| b.repeat(32));
    let mut last = None;
    for token in &bad {
        let (s, _, _) = post(&d, "/v1/heartbeat", Some(token), json!({})).await;
        assert_eq!(s, 401);
        last = pauses.owed();
    }
    assert!(last >= Some(SLOW), "the 3rd failure owed {last:?}");
    let text = events_text(&d);
    let lines = on(&events(&d), "auth_failure", "synapsed/bearer");
    assert!(lines.len() >= 3, "{text}");
    assert!(lines.iter().all(|e| e["subject"] == "bearer"));
    for token in &bad {
        assert!(
            !text.contains(token.as_str()),
            "a token is in the event file"
        );
    }
    // Positive control: the failures do not slow a valid caller.
    let (s, _, _) = post(&d, "/v1/heartbeat", Some(&good), json!({})).await;
    assert_eq!(s, 200);
    assert_eq!(pauses.owed(), None, "a valid token was held back");
    d.stop().await;
}

#[tokio::test]
async fn refused_claims_are_delayed_and_recorded() {
    let (d, pauses) = start_recorded().await;
    let mut secrets = Vec::new();
    let mut last = None;
    for _ in 0..3 {
        let mut body = claim_body(&d, "alpha");
        let mut sig = B64.decode(body["signature_b64"].as_str().unwrap()).unwrap();
        sig[0] ^= 1;
        body["signature_b64"] = json!(B64.encode(&sig));
        secrets.push(body["nonce_hex"].as_str().unwrap().to_string());
        secrets.push(body["signature_b64"].as_str().unwrap().to_string());
        let (s, reply, _) = post(&d, "/v1/claim", None, body).await;
        assert_eq!(s, 403, "{reply}");
        assert_eq!(reply["error"], "claim_refused");
        last = pauses.owed();
    }
    assert!(last >= Some(SLOW), "the 3rd refusal owed {last:?}");
    let mut malformed = claim_body(&d, "alpha");
    malformed["nonce_hex"] = json!("zz");
    let (s, reply, _) = post(&d, "/v1/claim", None, malformed).await;
    assert_eq!(s, 400, "{reply}");
    assert!(
        pauses.owed().is_some(),
        "a malformed claim was not held back"
    );
    let text = events_text(&d);
    let lines = on(&events(&d), "auth_failure", "synapsed/claim");
    assert!(lines.len() >= 4, "{text}");
    assert!(lines.iter().all(|e| e["subject"] == "alpha@acct"), "{text}");
    for secret in &secrets {
        assert!(
            !text.contains(secret.as_str()),
            "a secret is in the event file"
        );
    }
    // Positive control: a valid claim is not slowed by the failures before it.
    let (s, reply, _) = post(&d, "/v1/claim", None, claim_body(&d, "alpha")).await;
    assert_eq!(s, 200, "{reply}");
    assert_eq!(pauses.owed(), None, "a valid claim was held back");
    d.stop().await;
}

#[tokio::test]
async fn challenged_health_over_budget_is_slowed_not_refused() {
    let (d, pauses) = start_recorded().await;
    let id = instance_id(&d);
    let challenge = [0x5a; 16];
    let hexed: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
    let url = d.url(&format!("/v1/health?challenge={hexed}"));
    let mut last = None;
    for n in 1..=3 {
        let resp = client().get(&url).send().await.unwrap();
        last = pauses.owed();
        assert_eq!(resp.status(), 200, "request {n}");
        let reply: Value = resp.json().await.unwrap();
        let proof = reply["proof"].as_str().expect("a proof");
        assert!(proof_holds(&id, d.addr, &challenge, proof), "request {n}");
        if n == 1 {
            assert_eq!(last, None, "the first challenge was held back");
            assert!(on(&events(&d), "rate_limited", "synapsed/health").is_empty());
        }
    }
    assert!(last >= Some(SLOW), "the 3rd challenge owed {last:?}");
    // Requests 2 and 3 each owed a delay, so each left an event.
    let lines = on(&events(&d), "rate_limited", "synapsed/health");
    assert_eq!(lines.len(), 2, "{}", events_text(&d));
    assert!(lines.iter().all(|e| e["subject"] == "health"));
    // Positive control: an unchallenged health is not counted or slowed.
    let resp = client().get(d.url("/v1/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(pauses.owed(), None, "an unchallenged health was held back");
    d.stop().await;
}

#[tokio::test]
async fn repeated_unknown_recipients_are_delayed_per_role() {
    let (d, pauses) = start_recorded().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;
    pauses.take();
    let body = json!({"to": "ghost@acct", "body_b64": B64.encode(b"x")});
    let mut last = None;
    for _ in 0..3 {
        let (s, reply, _) = post(&d, "/v1/send", Some(&alpha), body.clone()).await;
        assert_eq!(s, 404, "{reply}");
        assert_eq!(reply["error"], "unknown_recipient");
        last = pauses.owed();
    }
    assert!(
        last >= Some(SLOW),
        "the 3rd unknown recipient owed {last:?}"
    );
    let lines = on(&events(&d), "rate_limited", "synapsed/recipient");
    assert!(!lines.is_empty(), "{}", events_text(&d));
    assert!(lines.iter().all(|e| e["subject"] == "alpha@acct"));
    // Positive control: another role has its own key.
    let (s, _, _) = post(&d, "/v1/send", Some(&beta), body).await;
    assert_eq!(s, 404);
    assert_eq!(pauses.owed(), None, "beta's first 404 was held back");
    d.stop().await;
}

#[tokio::test]
async fn repeated_bad_acks_are_delayed_per_role() {
    let (d, pauses) = start_recorded().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;
    pauses.take();
    let body = json!({"message_id": "alpha@acct/nothing"});
    let mut last = None;
    for _ in 0..3 {
        let (s, reply, _) = post(&d, "/v1/ack", Some(&alpha), body.clone()).await;
        assert_eq!(s, 404, "{reply}");
        last = pauses.owed();
    }
    assert!(last >= Some(SLOW), "the 3rd bad ack owed {last:?}");
    let lines = on(&events(&d), "rate_limited", "synapsed/ack");
    assert!(!lines.is_empty(), "{}", events_text(&d));
    assert!(lines.iter().all(|e| e["subject"] == "alpha@acct"));
    // Positive control: another role's ack is unaffected.
    let (s, _, _) = post(&d, "/v1/ack", Some(&beta), body).await;
    assert_eq!(s, 404);
    assert_eq!(pauses.owed(), None, "beta's first bad ack was held back");
    d.stop().await;
}

#[tokio::test]
async fn the_event_gate_coalesces_a_flood() {
    // Nothing is delayed (100 free failures), so only the gate limits what is written.
    let d = start_with(Some(tuned(100, 200, 2000, Duration::from_secs(60)))).await;
    for n in 0..5u8 {
        let token = format!("{:02x}", 0xd0 + n).repeat(32);
        let (s, _, _) = post(&d, "/v1/heartbeat", Some(&token), json!({})).await;
        assert_eq!(s, 401);
    }
    let lines = on(&events(&d), "auth_failure", "synapsed/bearer");
    assert_eq!(lines.len(), 1, "{}", events_text(&d));
    d.stop().await;
}

#[cfg(unix)]
#[test]
fn a_too_open_security_event_file_refuses_to_start() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let path = home.path().join(SECURITY_EVENTS_FILE);
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Daemon::open(&config(home.path())),
        Err(DaemonError::Security(_))
    ));
    // Positive control: the same file at 0600 opens.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Daemon::open(&config(home.path())).is_ok());
}

/// S-1 (agentlife): `list` carries each role's mailbox depth, so a watcher can see mail waiting for
/// a role and whether a running one still holds unacked mail.
#[tokio::test]
async fn list_shows_mailbox_depth_per_role() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;
    let pending = |listed: &Value, role: &str| {
        listed["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["global_id"] == role)
            .expect("role listed")["pending"]
            .clone()
    };
    let first = send_to(&d, &alpha, "beta@acct", b"one").await;
    send_to(&d, &alpha, "beta@acct", b"two").await;
    let (s, listed, text) = post_get_list(&d, &alpha).await;
    assert_eq!(s, 200, "{text}");
    let beta_pending = pending(&listed, "beta@acct");
    assert_eq!(beta_pending["queued"], 2, "{text}");
    assert_eq!(beta_pending["leased"], 0, "{text}");
    assert!(beta_pending["oldest_enqueued_at"].is_string(), "{text}");
    assert_eq!(
        pending(&listed, "alpha@acct"),
        json!({"queued": 0, "leased": 0, "dead": 0, "oldest_enqueued_at": null}),
        "no mail for alpha"
    );

    let (s, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({"max": 1})).await;
    assert_eq!(s, 200, "{got}");
    assert_eq!(got["messages"][0]["message_id"], first.as_str());
    let (_, listed, text) = post_get_list(&d, &alpha).await;
    let beta_pending = pending(&listed, "beta@acct");
    assert_eq!(
        (&beta_pending["queued"], &beta_pending["leased"]),
        (&json!(1), &json!(1)),
        "{text}"
    );

    let (s, acked, _) = post(&d, "/v1/ack", Some(&beta), json!({"message_id": first})).await;
    assert_eq!(s, 200, "{acked}");
    let (_, listed, text) = post_get_list(&d, &alpha).await;
    let beta_pending = pending(&listed, "beta@acct");
    assert_eq!(
        (&beta_pending["queued"], &beta_pending["leased"]),
        (&json!(1), &json!(0)),
        "{text}"
    );
    d.stop().await;
}

async fn get_stats(d: &Running, token: Option<&str>) -> (u16, Value, String) {
    let mut req = client().get(d.url("/v1/stats"));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

fn counters(stats: &Value, role: &str) -> [u64; 4] {
    let entry = stats["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["global_id"] == role)
        .unwrap_or_else(|| panic!("{role} not in {stats}"));
    ["sent", "acked", "redelivered", "expired"].map(|k| entry[k].as_u64().expect(k))
}

/// `/v1/stats`: cumulative per-role counters for the soak. `sent` counts new enqueues to the role
/// (a duplicate is not one), `acked` counts removals, `redelivered` counts every delivery after the
/// first, `expired` those whose previous lease had run out (a takeover redelivers without expiry).
/// Authenticated; the answer carries no message content; counters are per-process and say so.
#[tokio::test]
async fn stats_count_sent_acked_redelivered_and_expired_per_role() {
    let d = start().await;
    assert_eq!(get_stats(&d, None).await.0, 401, "needs a token");
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;

    let (s, stats, _) = get_stats(&d, Some(&alpha)).await;
    assert_eq!(s, 200, "{stats}");
    assert_eq!(counters(&stats, "beta@acct"), [0, 0, 0, 0], "fresh daemon");
    assert_eq!(stats["scope"], "process");
    assert!(stats["since"].is_string(), "{stats}");

    let m1 = send_to(&d, &alpha, "beta@acct", b"SECRET-ONE").await;
    send_to(&d, &alpha, "beta@acct", b"SECRET-TWO").await;
    send_to(&d, &alpha, "beta@acct", b"SECRET-THREE").await;
    // A resend under the same client id is a duplicate, not a second message.
    let (_, dup, _) = post(
        &d,
        "/v1/send",
        Some(&alpha),
        json!({"to": "beta@acct", "message_id": "fixed", "body_b64": B64.encode(b"x")}),
    )
    .await;
    assert_eq!(dup["outcome"], "queued");
    let (_, dup, _) = post(
        &d,
        "/v1/send",
        Some(&alpha),
        json!({"to": "beta@acct", "message_id": "fixed", "body_b64": B64.encode(b"x")}),
    )
    .await;
    assert_eq!(dup["outcome"], "duplicate");

    let (_, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({"lease_secs": 5})).await;
    assert_eq!(got["messages"].as_array().unwrap().len(), 4);
    post(&d, "/v1/ack", Some(&beta), json!({"message_id": m1})).await;
    let (_, stats, _) = get_stats(&d, Some(&alpha)).await;
    assert_eq!(counters(&stats, "beta@acct"), [4, 1, 0, 0]);

    // Let the 5 s leases run out; the three left come back, each after an expiry.
    tokio::time::sleep(Duration::from_millis(5500)).await;
    let (_, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({"lease_secs": 60})).await;
    assert_eq!(got["messages"].as_array().unwrap().len(), 3);
    let (_, stats, _) = get_stats(&d, Some(&alpha)).await;
    assert_eq!(counters(&stats, "beta@acct"), [4, 1, 3, 3]);

    // A takeover voids beta's live leases: redelivered, but nothing expired.
    let (beta2, _) = claim(&d, "beta").await;
    let (_, got, _) = post(&d, "/v1/fetch", Some(&beta2), json!({})).await;
    assert_eq!(got["messages"].as_array().unwrap().len(), 3);
    let (s, stats, text) = get_stats(&d, Some(&beta2)).await;
    assert_eq!(s, 200);
    assert_eq!(counters(&stats, "beta@acct"), [4, 1, 6, 3]);
    assert_eq!(counters(&stats, "alpha@acct"), [0, 0, 0, 0]);
    for leak in ["SECRET", "body", "message_id", &m1, &beta, &beta2] {
        assert!(!text.contains(leak), "stats leaked {leak:?}: {text}");
    }
    d.stop().await;
}

#[tokio::test]
async fn fetch_can_exclude_messages_it_would_otherwise_lease() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;
    let mut ids = Vec::new();
    for text in ["one", "two"] {
        let (s, sent, _) = post(
            &d,
            "/v1/send",
            Some(&alpha),
            json!({"to": "beta@acct", "body_b64": B64.encode(text)}),
        )
        .await;
        assert_eq!(s, 200, "{sent}");
        ids.push(sent["message_id"].as_str().unwrap().to_string());
    }

    let (s, got, _) = post(&d, "/v1/fetch", Some(&beta), json!({"exclude": [ids[0]]})).await;
    assert_eq!(s, 200, "{got}");
    let leased: Vec<&str> = got["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(leased, [ids[1].as_str()]);

    // The excluded one was not leased: the next plain fetch hands it out as attempt 1.
    let (s, rest, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
    assert_eq!(s, 200, "{rest}");
    assert_eq!(rest["messages"][0]["message_id"], ids[0].as_str());
    assert_eq!(rest["messages"][0]["attempts"], 1);

    // Bounded and typed: too many, a non-string, an over-long id are 400 `malformed`.
    let too_many: Vec<String> = (0..101).map(|i| format!("x{i}")).collect();
    for bad in [
        json!({"exclude": too_many}),
        json!({"exclude": [1]}),
        json!({"exclude": ["x".repeat(257)]}),
    ] {
        let (s, body, _) = post(&d, "/v1/fetch", Some(&beta), bad).await;
        assert_eq!(s, 400, "{body}");
    }
    d.stop().await;
}

/// G1/G2: a heartbeat may carry `cwd` and `repo` (bounded, no control characters); `list` shows
/// them and filters on them exactly; a fetched message carries the sender's summary and cwd.
#[tokio::test]
async fn presence_cwd_repo_filter_list_and_ride_on_fetched_mail() {
    let d = start().await;
    let (alpha, _) = claim(&d, "alpha").await;
    let (beta, _) = claim(&d, "beta").await;
    let (s, reply, _) = post(
        &d,
        "/v1/heartbeat",
        Some(&alpha),
        json!({"summary": "busy", "cwd": r"C:/Projects/synapse", "repo": "synapse"}),
    )
    .await;
    assert_eq!(s, 200, "{reply}");
    // Refused, and nothing stored from the refused beat.
    for bad in [json!({"cwd": "a\nb"}), json!({"repo": "x".repeat(501)})] {
        let (s, reply, _) = post(&d, "/v1/heartbeat", Some(&beta), bad).await;
        assert_eq!(s, 400, "{reply}");
    }
    let listed = |query: &'static str| {
        let d = &d;
        let beta = beta.clone();
        async move {
            let reply: Value = client()
                .get(d.url(&format!("/v1/list{query}")))
                .bearer_auth(&beta)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            reply["roles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["global_id"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(listed("").await.len(), 2);
    assert_eq!(listed("?repo=synapse").await, ["alpha@acct"]);
    assert_eq!(
        listed("?cwd=C%3A%2FProjects%2Fsynapse").await,
        ["alpha@acct"]
    );
    assert!(listed("?repo=other").await.is_empty());
    assert!(listed("?repo=synapse&cwd=nowhere").await.is_empty());

    let (s, sent, _) = post(
        &d,
        "/v1/send",
        Some(&alpha),
        json!({"to": "beta@acct", "body_b64": B64.encode(b"hi")}),
    )
    .await;
    assert_eq!(s, 200, "{sent}");
    let (s, fetched, _) = post(&d, "/v1/fetch", Some(&beta), json!({})).await;
    assert_eq!(s, 200, "{fetched}");
    let m = &fetched["messages"][0];
    assert_eq!(m["from_summary"], "busy");
    assert_eq!(m["from_cwd"], r"C:/Projects/synapse");
    d.stop().await;
}
