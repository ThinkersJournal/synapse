// SPDX-License-Identifier: MIT OR Apache-2.0
//! A session that aged out (ROADMAP row 37b) is claimed again by the client, once, without the
//! caller noticing, and a session in use is not. (That a TAKEN role is reported and not claimed back
//! is the daemon's ordering, tested in `tests/api.rs`: superseded is answered before expired.) The
//! daemon is in-process with a short session ttl; the client is the real blocking one, on its own
//! thread (its HTTP client owns a runtime).

use std::time::Duration;

use serde_json::json;
use synapse::keystore::Keystore;
use synapsed::{Daemon, DaemonConfig};
use synapsed_client::Daemon as Client;

async fn serve(ttl: chrono::Duration) -> (tempfile::TempDir, tokio::sync::oneshot::Sender<()>) {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let cfg = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    };
    let daemon = Daemon::open(&cfg).expect("open").with_session_ttl(ttl);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(daemon.serve(listener, async move {
        let _ = rx.await;
    }));
    for _ in 0..200 {
        if home.path().join("synapsed.json").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (home, tx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_session_is_claimed_again_and_a_used_one_is_not() {
    let (home, stop) = serve(chrono::Duration::milliseconds(600)).await;
    let path = home.path().to_path_buf();
    let outcome = std::thread::spawn(move || {
        let client = Client::connect(&path).expect("connect");
        let first = client.claim("alpha").expect("claim");
        client
            .call("alpha", "/v1/heartbeat", Some(&json!({})))
            .expect("a fresh session works");

        // Idle past the ttl: the next call is an expiry. It must succeed on its own, with a new epoch.
        std::thread::sleep(Duration::from_millis(900));
        client
            .call("alpha", "/v1/heartbeat", Some(&json!({})))
            .expect("an expired session is claimed again by the client");
        let second = client.session_info("alpha").expect("session");
        assert!(second.epoch > first.epoch, "the re-claim took a new epoch");

        // A used session never expires: calls inside the window keep it alive without a re-claim.
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(300));
            client
                .call("alpha", "/v1/heartbeat", Some(&json!({})))
                .expect("a used session slides");
        }
        assert_eq!(
            client.session_info("alpha").expect("session").epoch,
            second.epoch,
            "and it did not claim again"
        );
    })
    .join();
    assert!(outcome.is_ok(), "the client thread panicked");
    let _ = stop.send(());
}
