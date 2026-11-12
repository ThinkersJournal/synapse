// SPDX-License-Identifier: MIT OR Apache-2.0
//! ROADMAP row 37(d): is the `std::sync::Mutex` around the mailbox (held across blocking store I/O on a
//! tokio worker) a latency problem? This starts an in-process daemon on loopback, drives `send`,
//! `fetch` and `ack` from `C` concurrent roles, and meanwhile probes two cheap calls every 25 ms: a
//! `heartbeat` (presence only) and a `list` (reads the mailbox under its lock). Numbers only.
//!
//!     cargo run --release -p synapsed --example latency_probe -- [--secs 4] [--levels 0,1,8,32]
//!     cargo run --release -p synapsed --features sqlite-store --example latency_probe -- --sqlite
//!
//! The question it answers: does the probe's latency rise with the load? If the p99 of a cheap call
//! stays near its idle value while writers hammer the store, the mutex is not the bottleneck; if it
//! climbs with `C`, calls are queueing behind the lock.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use synapse::certificate::chain_to_pem;
use synapse::keystore::Keystore;
use synapse::roles::sign_claim_for;
use synapsed::{Daemon, DaemonConfig, StoreKind};

struct Running {
    addr: SocketAddr,
    home: tempfile::TempDir,
    started_at: DateTime<Utc>,
}

impl Running {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

async fn start(kind: StoreKind) -> Running {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let cfg = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    };
    let daemon = Daemon::open_with(&cfg, kind).expect("open daemon");
    let started_at = daemon.started_at();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(daemon.serve(listener, std::future::pending::<()>()));
    for _ in 0..200 {
        if home.path().join("synapsed.json").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Running {
        addr,
        home,
        started_at,
    }
}

fn instance_id(d: &Running) -> String {
    let text = std::fs::read_to_string(d.home.path().join("synapsed.json")).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    v["instance_id"].as_str().unwrap().to_string()
}

async fn claim(d: &Running, http: &reqwest::Client, role: &str) -> String {
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
    let reply: Value = http
        .post(d.url("/v1/claim"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    reply["session"].as_str().expect("a session").to_string()
}

#[derive(Default, Clone)]
struct Samples(Vec<f64>);

impl Samples {
    fn push(&mut self, since: Instant) {
        self.0.push(since.elapsed().as_secs_f64() * 1000.0);
    }

    fn row(&self, name: &str) -> String {
        let mut v = self.0.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let at = |p: f64| {
            v.get(((v.len().saturating_sub(1)) as f64 * p).round() as usize)
                .copied()
                .unwrap_or(0.0)
        };
        format!(
            "| {name} | {} | {:.2} | {:.2} | {:.2} | {:.2} |",
            v.len(),
            at(0.5),
            at(0.95),
            at(0.99),
            v.last().copied().unwrap_or(0.0)
        )
    }
}

async fn call(
    http: &reqwest::Client,
    d: &Running,
    token: &str,
    path: &str,
    body: Option<Value>,
) -> Value {
    let req = match body {
        Some(b) => http.post(d.url(path)).json(&b),
        None => http.get(d.url(path)),
    };
    req.bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_or(Value::Null)
}

/// One load level: `workers` roles send to a neighbour, fetch and ack for `secs`, while a probe role
/// times a heartbeat and a list every 25 ms.
async fn level(
    d: Arc<Running>,
    tokens: Arc<Vec<(String, String)>>,
    probe: String,
    workers: usize,
    secs: u64,
) {
    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut tasks = Vec::new();
    for i in 0..workers {
        let (d, tokens, http) = (Arc::clone(&d), Arc::clone(&tokens), http.clone());
        tasks.push(tokio::spawn(async move {
            let (mut send, mut fetch, mut ack) = (Samples::default(), Samples::default(), Samples::default());
            let (_, token) = &tokens[i];
            let (neighbour, _) = &tokens[(i + 1) % tokens.len().min(workers.max(2))];
            let mut n = 0u64;
            while Instant::now() < deadline {
                n += 1;
                let t = Instant::now();
                call(
                    &http,
                    &d,
                    token,
                    "/v1/send",
                    Some(json!({"to": format!("{neighbour}@acct"), "message_id": format!("m{n}"), "body_b64": B64.encode([b'x'; 256])})),
                )
                .await;
                send.push(t);
                let t = Instant::now();
                let got = call(&http, &d, token, "/v1/fetch", Some(json!({"max": 8}))).await;
                fetch.push(t);
                for m in got["messages"].as_array().cloned().unwrap_or_default() {
                    let t = Instant::now();
                    call(&http, &d, token, "/v1/ack", Some(json!({"message_id": m["message_id"]}))).await;
                    ack.push(t);
                }
            }
            (send, fetch, ack)
        }));
    }
    let probe_task = {
        let (d, http) = (Arc::clone(&d), http.clone());
        tokio::spawn(async move {
            let (mut beat, mut list) = (Samples::default(), Samples::default());
            while Instant::now() < deadline {
                let t = Instant::now();
                call(&http, &d, &probe, "/v1/heartbeat", Some(json!({}))).await;
                beat.push(t);
                let t = Instant::now();
                call(&http, &d, &probe, "/v1/list", None).await;
                list.push(t);
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            (beat, list)
        })
    };
    let (mut send, mut fetch, mut ack) =
        (Samples::default(), Samples::default(), Samples::default());
    for t in tasks {
        let (s, f, a) = t.await.unwrap();
        send.0.extend(s.0);
        fetch.0.extend(f.0);
        ack.0.extend(a.0);
    }
    let (beat, list) = probe_task.await.unwrap();
    println!("\n**{workers} concurrent roles** ({secs} s)\n");
    println!("| call | n | p50 ms | p95 ms | p99 ms | max ms |\n|---|---|---|---|---|---|");
    for (name, s) in [
        ("probe heartbeat", &beat),
        ("probe list", &list),
        ("send", &send),
        ("fetch", &fetch),
        ("ack", &ack),
    ] {
        if !s.0.is_empty() {
            println!("{}", s.row(name));
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let secs: u64 = flag("--secs").and_then(|v| v.parse().ok()).unwrap_or(4);
    let levels: Vec<usize> = flag("--levels")
        .map(|v| v.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![0, 1, 8, 32]);
    let sqlite = args.iter().any(|a| a == "--sqlite");
    #[cfg(feature = "sqlite-store")]
    let kind = if sqlite {
        StoreKind::Sqlite
    } else {
        StoreKind::Redb
    };
    #[cfg(not(feature = "sqlite-store"))]
    let kind = {
        assert!(!sqlite, "--sqlite needs --features sqlite-store");
        StoreKind::Redb
    };
    let d = Arc::new(start(kind).await);
    let http = reqwest::Client::new();
    let max = levels.iter().copied().max().unwrap_or(0).max(2);
    let mut tokens = Vec::new();
    for i in 0..max {
        let role = format!("w{i}");
        let token = claim(&d, &http, &role).await;
        tokens.push((role, token));
    }
    let probe = claim(&d, &http, "probe").await;
    let tokens = Arc::new(tokens);
    println!(
        "store: {kind:?}; release build recommended; loopback; one process (daemon and clients share the machine)"
    );
    for workers in levels {
        level(
            Arc::clone(&d),
            Arc::clone(&tokens),
            probe.clone(),
            workers,
            secs,
        )
        .await;
    }
}
