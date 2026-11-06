// SPDX-License-Identifier: MIT OR Apache-2.0
//! An expired role certificate, through the real client and a real in-process daemon.
//!
//! Two homes behave differently, on purpose, and both ways were only ever read in the code
//! (`load_role`, `src/keystore.rs`), never run:
//!
//! - A home that holds the account key renews the role's certificate when the client claims, so a
//!   session whose `cert.pem` lapsed (the four account-home roles show `EXPIRED` in the spec audit
//!   while online) claims again without anyone doing anything.
//! - A role-only home (from `synapse id provision`) has no account key and cannot renew: the claim
//!   fails with `CertificateExpired` before anything reaches the daemon, and the cert file is left
//!   alone.
//!
//! The client is the real blocking one, on its own thread (its HTTP client owns a runtime).

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use synapse::keystore::{Keystore, KeystoreError};
use synapsed::{Daemon, DaemonConfig};
use synapsed_client::{Daemon as Client, MailError};

async fn serve() -> (tempfile::TempDir, tokio::sync::oneshot::Sender<()>) {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let cfg = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    };
    let daemon = Daemon::open(&cfg).expect("open");
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

fn cert_path(home: &Path, role: &str) -> PathBuf {
    home.join("roles").join(role).join("cert.pem")
}

/// Full home: a certificate that lapsed two days ago is renewed by the claim, and the claim works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_home_renews_an_expired_certificate_when_the_client_claims() {
    let (home, stop) = serve().await;
    let path = home.path().to_path_buf();

    // Make the role three days ago, so its 24 h certificate ended two days ago.
    let long_ago = Utc::now() - chrono::Duration::days(3);
    let store = Keystore::open(&path).unwrap();
    let old = store.role("alpha", long_ago).unwrap();
    assert!(
        old.not_after < Utc::now() - chrono::Duration::days(1),
        "the setup certificate must already be expired"
    );
    let before = std::fs::read(cert_path(&path, "alpha")).unwrap();

    let p = path.clone();
    let outcome = std::thread::spawn(move || {
        let client = Client::connect(&p).expect("connect");
        client
            .claim("alpha")
            .expect("an expired certificate in a full home is renewed by the claim")
    })
    .join();
    let claimed = outcome.expect("the client thread panicked");
    assert_eq!(claimed.global_id, "alpha@acct");

    let after = std::fs::read(cert_path(&path, "alpha")).unwrap();
    assert_ne!(before, after, "cert.pem was rewritten");
    let renewed = Keystore::open(&path)
        .unwrap()
        .role("alpha", Utc::now())
        .unwrap();
    assert!(
        renewed.not_after > Utc::now() + chrono::Duration::hours(12),
        "the renewed certificate is current: {}",
        renewed.not_after
    );
    let _ = stop.send(());
}

/// Role-only home: the same lapse is `CertificateExpired`, and the file is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_role_only_home_cannot_renew_and_the_claim_says_certificate_expired() {
    let (daemon_home, stop) = serve().await;
    let lane = tempfile::tempdir().unwrap();
    let pubs = Keystore::init_role(lane.path(), "acct", "alpha").unwrap();
    // Issued ten days ago for eight days: ended two days ago.
    let pem = Keystore::open(daemon_home.path())
        .unwrap()
        .issue_role_certificate(
            "alpha",
            pubs,
            Utc::now() - chrono::Duration::days(10),
            chrono::Duration::days(8),
        )
        .unwrap();
    Keystore::install_role_certificate(lane.path(), "alpha", &pem).unwrap();
    // A role-only home holds no announce file; copy the daemon's, as the announce-sync stopgap does.
    std::fs::copy(
        daemon_home.path().join("synapsed.json"),
        lane.path().join("synapsed.json"),
    )
    .unwrap();
    let before = std::fs::read(cert_path(lane.path(), "alpha")).unwrap();

    let lane_path = lane.path().to_path_buf();
    let outcome = std::thread::spawn(move || {
        let client = Client::connect(&lane_path).expect("connect");
        client.claim("alpha")
    })
    .join()
    .expect("the client thread panicked");
    assert!(
        matches!(
            outcome,
            Err(MailError::Keystore(KeystoreError::CertificateExpired))
        ),
        "expected CertificateExpired, got {:?}",
        outcome.as_ref().err()
    );
    assert_eq!(
        std::fs::read(cert_path(lane.path(), "alpha")).unwrap(),
        before,
        "a role-only home leaves cert.pem alone"
    );
    let _ = stop.send(());
}

/// Control: the same role-only setup with a current certificate claims fine, so the test above
/// fails on the lapse and not on the setup (copied announce file, role-only connect).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_a_role_only_home_with_a_current_certificate_claims() {
    let (daemon_home, stop) = serve().await;
    let lane = tempfile::tempdir().unwrap();
    let pubs = Keystore::init_role(lane.path(), "acct", "alpha").unwrap();
    let pem = Keystore::open(daemon_home.path())
        .unwrap()
        .issue_role_certificate("alpha", pubs, Utc::now(), chrono::Duration::days(8))
        .unwrap();
    Keystore::install_role_certificate(lane.path(), "alpha", &pem).unwrap();
    std::fs::copy(
        daemon_home.path().join("synapsed.json"),
        lane.path().join("synapsed.json"),
    )
    .unwrap();
    let lane_path = lane.path().to_path_buf();
    let claimed = std::thread::spawn(move || {
        Client::connect(&lane_path)
            .expect("connect")
            .claim("alpha")
            .expect("a current certificate claims")
    })
    .join()
    .expect("the client thread panicked");
    assert_eq!(claimed.global_id, "alpha@acct");
    let _ = stop.send(());
}
