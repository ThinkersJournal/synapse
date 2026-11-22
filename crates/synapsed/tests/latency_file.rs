// SPDX-License-Identifier: MIT OR Apache-2.0
//! The daemon publishes how long its requests take (`docs/CLIENT_TIMEOUTS_DESIGN.md` R4), so a short-lived
//! client can start its timeout from the load the daemon is under.

mod common;

use std::time::Duration;

use serde_json::Value;
use synapse::keystore::Keystore;
use synapsed::{Daemon, DaemonConfig};

#[tokio::test]
async fn a_running_daemon_publishes_its_request_latency_for_clients() {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let cfg = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    };
    common::allow_all(&cfg.home);
    let daemon = Daemon::open(&cfg).expect("open daemon");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.serve(listener, async move {
        let _ = rx.await;
    }));
    let file = home.path().join(synapsed_client::LATENCY_FILE);
    assert!(
        !file.exists(),
        "nothing is published before a request was timed"
    );
    let client = reqwest::Client::new();
    let mut published: Option<Value> = None;
    for _ in 0..200 {
        let _ = client
            .get(format!("http://{addr}/v1/health"))
            .send()
            .await
            .unwrap();
        if let Ok(text) = std::fs::read_to_string(&file) {
            published = serde_json::from_str(&text).ok();
            if published.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let seen = published.expect("the latency file appears within the publish interval");
    assert!(
        seen["smoothed_ms"].is_u64() && seen["deviation_ms"].is_u64(),
        "{seen}"
    );
    assert!(
        seen["at"]
            .as_str()
            .is_some_and(|t| t.parse::<chrono::DateTime<chrono::Utc>>().is_ok()),
        "{seen}"
    );
    let _ = stop.send(());
    let _ = task.await;
}
